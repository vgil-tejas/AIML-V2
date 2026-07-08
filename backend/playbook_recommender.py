"""
CyberSentinel — Playbook Recommender (feedback-trained)
=======================================================
Mines the logs to answer: "which NEW playbooks should the SOC build?"

Design (per product decision):
  * PURE feedback-driven — the true-positive gate is a classifier trained ONLY on
    analyst dispositions (alert_feedback). No heuristic fallback: below a minimum
    labelled set the recommender honestly refuses and reports "collecting labels".
  * Recurrence over the log types you actually train on (threat_type), not a fixed
    taxonomy.
  * Gap-check against the existing playbook catalogue — only UNCOVERED patterns.
  * Output = ranked recommendations + a draft response template for each.

This module is pure/deterministic (no DB, no async): main.py pulls the rows from
ClickHouse and passes them in, so the logic is trivially testable. The model is a
small numpy logistic regression — no heavy ML dependency, fully in-house.
"""
from __future__ import annotations
import math
import numpy as np

try:
    import threat_intel as ti
except Exception:
    ti = None
try:
    import playbooks as pb
except Exception:
    pb = None

# ── Gates (a recommender that fires on 1 label is theatre) ──────────────────
MIN_LABELS = 24          # total dispositions needed before we train at all
MIN_PER_CLASS = 6        # need both TP and not-TP examples
MIN_RECURRENCE = 30      # a pattern must recur this many times to deserve a playbook
TP_THRESHOLD = 0.5       # model P(true-positive) needed to call a pattern "real"

# Dispositions that mean "this was a real threat" (label = 1).
_TP_LABELS = {"true_positive", "tp", "escalate", "malicious", "suspicious", "confirmed"}
# Never recommend a playbook for these (benign / noise buckets).
_SKIP_THREATS = {"", "unknown", "login_success", "successful_login", "other"}

FEATURE_NAMES = [
    "log_events", "max_level", "avg_level", "frac_critical", "frac_high",
    "log_uniq_dst", "log_uniq_ports", "log_uniq_users", "is_anomaly",
]


def label_to_y(disposition: str) -> int:
    return 1 if str(disposition).strip().lower() in _TP_LABELS else 0


def featurize(row: dict, anomaly_set: set) -> list:
    """Behavioural feature vector for one entity row (from get_entity_features)."""
    ev = max(1, int(row.get("events", 0)))
    return [
        math.log1p(ev),
        float(row.get("max_lvl", 0)) / 15.0,
        float(row.get("avg_lvl", 0)) / 15.0,
        int(row.get("crit", 0)) / ev,
        int(row.get("high", 0)) / ev,
        math.log1p(int(row.get("uniq_dst", 0))),
        math.log1p(int(row.get("uniq_ports", 0))),
        math.log1p(int(row.get("uniq_users", 0))),
        1.0 if row.get("entity") in anomaly_set else 0.0,
    ]


# ── Logistic regression (numpy, L2, batch gradient descent) ─────────────────
class LogReg:
    def __init__(self, n_features: int):
        self.w = np.zeros(n_features)
        self.b = 0.0
        self.mu = np.zeros(n_features)
        self.sd = np.ones(n_features)

    @staticmethod
    def _sig(z):
        return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))

    def fit(self, X, y, iters=800, lr=0.2, l2=1e-3):
        X = np.asarray(X, dtype=float)
        y = np.asarray(y, dtype=float)
        self.mu = X.mean(axis=0)
        self.sd = X.std(axis=0)
        self.sd[self.sd == 0] = 1.0
        Xs = (X - self.mu) / self.sd
        n = len(y)
        for _ in range(iters):
            p = self._sig(Xs @ self.w + self.b)
            err = p - y
            self.w -= lr * (Xs.T @ err / n + l2 * self.w)
            self.b -= lr * float(err.mean())
        return self

    def predict_proba(self, X):
        X = np.asarray(X, dtype=float)
        Xs = (X - self.mu) / self.sd
        return self._sig(Xs @ self.w + self.b)


def train(training_rows: list, anomaly_set: set) -> dict:
    """training_rows: [{...entity features..., 'disposition': str}].
    Returns a model bundle + honest status/metrics, or a 'collecting' status."""
    rows = [r for r in training_rows if r.get("disposition")]
    n = len(rows)
    y = [label_to_y(r["disposition"]) for r in rows]
    pos, neg = sum(y), n - sum(y)
    if n < MIN_LABELS or pos < MIN_PER_CLASS or neg < MIN_PER_CLASS:
        return {"trained": False, "status": "collecting", "labels": n,
                "pos": pos, "neg": neg, "needed": MIN_LABELS,
                "need_per_class": MIN_PER_CLASS}
    X = [featurize(r, anomaly_set) for r in rows]
    model = LogReg(len(FEATURE_NAMES)).fit(X, y)
    # Honest in-sample accuracy (small data — we report it as such, not as a promise).
    p = model.predict_proba(X)
    acc = float(((p >= 0.5).astype(int) == np.asarray(y)).mean())
    weights = {FEATURE_NAMES[i]: round(float(model.w[i]), 3) for i in range(len(FEATURE_NAMES))}
    return {"trained": True, "status": "ready", "labels": n, "pos": pos, "neg": neg,
            "train_accuracy": round(acc, 3), "weights": weights, "_model": model}


# ── Recommendation ──────────────────────────────────────────────────────────
def covered_threat_types(all_threats: list) -> set:
    """Which log types an existing playbook already handles — so we only
    recommend the gaps. Uses the real matcher against a synth incident."""
    covered = set()
    if not pb:
        return covered
    for t in all_threats:
        inc = {"id": f"t:{t}", "severity": "high",
               "entities": {"ips": ["0.0.0.0"], "users": []},
               "narrative": t.replace("_", " "), "techniques": [],
               "tactics": [], "reached_lateral": ("lateral" in t or "rdp" in t or "smb" in t),
               "ueba_findings": ([{"type": t}] if t in ("account_takeover", "impossible_travel") else [])}
        # technique hint from the KB so technique-prefix triggers can fire
        if ti:
            tid = ti.THREAT_TO_TECHNIQUE.get(t)
            if tid:
                inc["techniques"] = [{"id": tid, "name": t}]
        if pb.match_playbooks(inc):
            covered.add(t)
    return covered


def _is_network_threat(t: str) -> bool:
    return any(k in t for k in ("scan", "recon", "brute", "ddos", "malicious", "c2",
                                "exfil", "lateral", "rdp", "smb", "vpn", "web", "sql"))


def _is_identity_threat(t: str) -> bool:
    return any(k in t for k in ("takeover", "identity", "credential", "account",
                                "privilege", "escalation", "impossible"))


def draft_response(threat_type: str) -> dict:
    """A suggested ordered response template for a recommended playbook — built
    from the action catalogue + ATT&CK-grounded mitigations. Mutating steps are
    flagged for approval, exactly like a real playbook."""
    acts = (pb.ACTIONS if pb else {})

    def step(a, approval=False, params=None):
        meta = acts.get(a, {})
        return {"action": a, "label": meta.get("label", a),
                "mutates": bool(meta.get("mutates")), "requires_approval": approval,
                "params": params or {}}

    steps = [step("enrich_reputation"), step("enrich_abuseipdb"),
             step("tag_entity", params={"tag": threat_type})]
    if _is_identity_threat(threat_type):
        steps.append(step("disable_user", approval=True))
    if _is_network_threat(threat_type):
        steps.append(step("block_ip", approval=True))
    steps += [step("open_case", params={"title": f"{threat_type.replace('_',' ').title()} from {{ip}}"}),
              step("notify", params={"channel": "soc"})]

    mitigations, technique, tactic = [], "", ""
    if ti:
        kb = ti.retrieve_for_alert(threat_type=threat_type, keywords=threat_type, limit=1)
        if kb:
            e = kb[0]
            technique, tactic = e.get("technique_id", ""), e.get("tactic", "")
            mitigations = e.get("mitigations", [])
    return {"steps": steps, "mitigations": mitigations,
            "technique": technique, "tactic": tactic}


def recommend(model_bundle: dict, score_rows: list, recurrence: list,
              covered: set, anomaly_set: set) -> dict:
    """Rank uncovered, recurring, model-confirmed-TP log types as candidate
    playbooks. score_rows = get_entity_features(None); recurrence =
    get_threat_type_recurrence()."""
    if not model_bundle.get("trained"):
        return {"status": model_bundle.get("status", "collecting"),
                "labels": model_bundle.get("labels", 0),
                "needed": model_bundle.get("needed", MIN_LABELS),
                "need_per_class": model_bundle.get("need_per_class", MIN_PER_CLASS),
                "pos": model_bundle.get("pos", 0), "neg": model_bundle.get("neg", 0),
                "recommendations": []}
    model = model_bundle["_model"]
    # Predict TP for every scored entity, then bucket the predictions by the
    # entity's dominant log type -> per-threat-type TP confidence.
    by_threat_conf: dict = {}
    if score_rows:
        X = [featurize(r, anomaly_set) for r in score_rows]
        probs = model.predict_proba(X)
        for r, p in zip(score_rows, probs):
            by_threat_conf.setdefault(r.get("top_threat", "unknown"), []).append(float(p))

    rec_by_type = {r["threat_type"]: r for r in recurrence}
    cands = []
    for t, rstat in rec_by_type.items():
        if t in _SKIP_THREATS or t in covered:
            continue
        if rstat["events"] < MIN_RECURRENCE:
            continue
        confs = by_threat_conf.get(t, [])
        tp_conf = float(np.mean(confs)) if confs else 0.0
        if tp_conf < TP_THRESHOLD:
            continue
        # Rank: recurrence (log) × TP confidence × severity weight × spread.
        sev_w = 1.0 + (rstat["crit"] / max(1, rstat["events"])) * 1.5
        rank = math.log1p(rstat["events"]) * tp_conf * sev_w * (1 + math.log1p(rstat["ips"]))
        draft = draft_response(t)
        cands.append({
            "threat_type": t, "title": t.replace("_", " ").title(),
            "tp_confidence": round(tp_conf, 3),
            "events": rstat["events"], "distinct_ips": rstat["ips"],
            "critical": rstat["crit"], "high_or_crit": rstat["hi"],
            "span_days": rstat["span_days"], "max_level": rstat["max_lvl"],
            "first_seen": rstat["first_seen"], "last_seen": rstat["last_seen"],
            "technique": draft["technique"], "tactic": draft["tactic"],
            "draft_steps": draft["steps"], "mitigations": draft["mitigations"],
            "rank_score": round(rank, 2),
            "why": (f"{rstat['events']:,} confirmed-pattern events across "
                    f"{rstat['ips']} source IPs over {rstat['span_days']} day(s); "
                    f"model TP-confidence {round(tp_conf*100)}%; no existing playbook covers it."),
        })
    cands.sort(key=lambda c: c["rank_score"], reverse=True)
    return {"status": "ready", "labels": model_bundle["labels"],
            "train_accuracy": model_bundle.get("train_accuracy"),
            "weights": model_bundle.get("weights"),
            "recommendations": cands}


def label_queue(recurrence: list, covered: set, examples_by_type: dict,
                labelled_entities: set, limit: int = 12) -> list:
    """The fast-labelling queue: recurring patterns that are NOT yet covered,
    each with a fresh UNLABELLED example entity (queried directly per
    threat_type — see get_label_queue_examples — so the queue never starves
    down to one item just because the busiest IPs overall got labelled first).
    Returns one representative entity per pattern to disposition."""
    out = []
    for rstat in recurrence:
        t = rstat["threat_type"]
        if t in _SKIP_THREATS:
            continue
        ex = examples_by_type.get(t)
        if not ex or ex["entity"] in labelled_entities:
            continue
        out.append({
            "threat_type": t, "title": t.replace("_", " ").title(),
            "covered": t in covered, "events": rstat["events"], "ips": rstat["ips"],
            "max_level": rstat["max_lvl"], "critical": rstat["crit"],
            "example_entity": ex["entity"],
            "example_detail": (f"{ex['events']} events, max level {ex['max_lvl']}, "
                               f"{ex['crit']} critical, {ex['uniq_dst']} destinations"),
        })
        if len(out) >= limit:
            break
    return out
