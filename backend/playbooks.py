"""
CyberSentinel — Response Playbooks
==================================
Deterministic, dependency-light playbook *definitions* and *matching*. This is
the "what should we do about this incident" layer — the SOAR brain — kept pure
so it is trivial to test and reason about. Execution of the actions lives in
main.py (it needs ClickHouse / httpx); this module only decides which playbook
applies and in what order.

Design (the standout): every playbook is AI-suggested + blast-radius-previewed +
human-approved + fully logged to the ledger. Actions that change the world
(block_ip, disable_user) carry requires_approval=True and never auto-run.

A playbook trigger is a set of predicates over a correlated incident dict (see
incidents.py). All present predicates must match (AND); a missing predicate is
ignored. Matching is explainable: match_playbooks returns WHY each one fired.
"""
from __future__ import annotations


# ── Action catalogue (labels + whether they mutate the world) ───────────────
# The executor in main.py implements each by name. requires_approval actions are
# only run when the analyst explicitly approves the run.
ACTIONS = {
    "enrich_reputation": {"label": "Enrich with in-house IP reputation", "mutates": False},
    # Action KEY stays enrich_abuseipdb (runs, history, feedback all key off it).
    # Only the label is white-labelled — the buyer never learns the vendor.
    "enrich_abuseipdb":  {"label": "Enrich with ReputationNet", "mutates": False},
    "tag_entity":        {"label": "Tag the entity for tracking", "mutates": False},
    "open_case":         {"label": "Open an investigation case", "mutates": False},
    "notify":            {"label": "Notify the SOC channel", "mutates": False},
    "block_ip":          {"label": "Block the source IP at the firewall", "mutates": True},
    "disable_user":      {"label": "Disable the affected user account", "mutates": True},
}


PLAYBOOKS: list[dict] = [
    {
        "id": "pb-brute-force",
        "name": "Brute-force / credential attack response",
        "description": "Source is hammering authentication. Enrich, contain the IP, "
                       "open a case, and notify the SOC.",
        "trigger": {"technique_prefixes": ["T1110"],
                    "threat_keywords": ["brute", "auth", "login_fail", "password"]},
        "severity": "high",
        "steps": [
            {"action": "enrich_reputation", "requires_approval": False},
            {"action": "enrich_abuseipdb",  "requires_approval": False},
            {"action": "tag_entity", "params": {"tag": "brute-force"}, "requires_approval": False},
            {"action": "block_ip",   "requires_approval": True},
            {"action": "open_case",  "params": {"title": "Brute-force from {ip}"}, "requires_approval": False},
            {"action": "notify",     "params": {"channel": "soc"}, "requires_approval": False},
        ],
    },
    {
        "id": "pb-lateral",
        "name": "Lateral movement / sensitive-service containment",
        "description": "Source reached lateral movement or hit sensitive services. "
                       "Enrich, tag, open a case, and notify — contain the IP on approval.",
        "trigger": {"reached_lateral": True,
                    "tactics_any": ["lateral-movement", "lateral_movement", "Lateral Movement"],
                    "technique_prefixes": ["T1021", "T1210", "T1570"],
                    "threat_keywords": ["lateral", "sensitive_port", "rdp", "smb", "ssh"]},
        "severity": "critical",
        "steps": [
            {"action": "enrich_reputation", "requires_approval": False},
            {"action": "tag_entity", "params": {"tag": "lateral-movement"}, "requires_approval": False},
            {"action": "open_case",  "params": {"title": "Lateral movement from {ip}"}, "requires_approval": False},
            {"action": "block_ip",   "requires_approval": True},
            {"action": "notify",     "params": {"channel": "soc"}, "requires_approval": False},
        ],
    },
    {
        "id": "pb-identity",
        "name": "Identity compromise / impossible-travel response",
        "description": "UEBA flagged account takeover or impossible travel. Enrich, "
                       "open a case, notify — disable the account on approval.",
        "trigger": {"ueba_types": ["account_takeover", "impossible_travel"]},
        "severity": "critical",
        "steps": [
            {"action": "enrich_reputation", "requires_approval": False},
            {"action": "tag_entity", "params": {"tag": "identity-risk"}, "requires_approval": False},
            {"action": "open_case",  "params": {"title": "Identity compromise: {user}"}, "requires_approval": False},
            {"action": "disable_user", "requires_approval": True},
            {"action": "notify",     "params": {"channel": "soc"}, "requires_approval": False},
        ],
    },
]

PLAYBOOK_BY_ID = {p["id"]: p for p in PLAYBOOKS}


def _incident_threat_text(incident: dict) -> str:
    """Flatten an incident's matchable text (techniques, tactics, narrative)."""
    parts = [incident.get("narrative", "")]
    parts += [t.get("name", "") for t in incident.get("techniques", [])]
    parts += list(incident.get("tactics", []))
    return " ".join(parts).lower()


def _matches(trigger: dict, incident: dict) -> list[str]:
    """Return the list of reasons this trigger fires for the incident, or [] if
    it does not. A trigger fires if ANY of its predicate groups match (OR across
    predicate kinds — playbooks are broad nets, refined later by approval)."""
    reasons: list[str] = []
    tech_ids = [t.get("id", "") for t in incident.get("techniques", [])]
    tactics = [t.lower() for t in incident.get("tactics", [])]
    ueba = [f.get("type", "") for f in incident.get("ueba_findings", [])]
    text = _incident_threat_text(incident)

    for pref in trigger.get("technique_prefixes", []):
        hit = [tid for tid in tech_ids if tid.startswith(pref)]
        if hit:
            reasons.append(f"ATT&CK technique {', '.join(hit)}")
    if trigger.get("reached_lateral") and incident.get("reached_lateral"):
        reasons.append("activity reached lateral movement")
    for tac in trigger.get("tactics_any", []):
        if tac.lower() in tactics:
            reasons.append(f"tactic {tac}")
    for ut in trigger.get("ueba_types", []):
        if ut in ueba:
            reasons.append(f"UEBA finding: {ut.replace('_', ' ')}")
    for kw in trigger.get("threat_keywords", []):
        if kw in text:
            reasons.append(f"signal mentions '{kw}'")
            break  # one keyword reason is enough, avoid noise
    return reasons


def match_playbooks(incident: dict) -> list[dict]:
    """Rank playbooks that apply to an incident, each with WHY it matched.
    Returns [{playbook, reasons}], most severe first."""
    out = []
    sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for pb in PLAYBOOKS:
        reasons = _matches(pb["trigger"], incident)
        if reasons:
            out.append({"playbook": pb, "reasons": reasons})
    out.sort(key=lambda m: sev_rank.get(m["playbook"]["severity"], 0), reverse=True)
    return out


# ── Customer-editable YAML playbooks ────────────────────────────────────────
# The bank drops .yaml files into playbooks.d/ (a live volume mount — no image
# rebuild) and they merge into the catalogue at startup. Same schema as the
# built-ins above; an id collision means "override the built-in".
def _load_yaml_playbooks() -> None:
    import os, glob, logging
    logger = logging.getLogger("cybersentinel.playbooks")
    try:
        import yaml
    except ImportError:
        return
    for path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "playbooks.d", "*.yaml"))):
        try:
            with open(path, encoding="utf-8") as fh:
                docs = yaml.safe_load(fh)
            for p in (docs if isinstance(docs, list) else [docs]):
                if not (isinstance(p, dict) and p.get("id") and p.get("steps")):
                    logger.warning(f"skipping malformed playbook in {path}")
                    continue
                p.setdefault("severity", "medium")
                p.setdefault("trigger", {})
                p["source"] = "yaml:" + os.path.basename(path)
                if p["id"] in PLAYBOOK_BY_ID:            # override built-in
                    PLAYBOOKS[:] = [x for x in PLAYBOOKS if x["id"] != p["id"]]
                PLAYBOOKS.append(p)
                PLAYBOOK_BY_ID[p["id"]] = p
        except Exception as e:
            logger.warning(f"could not load playbook file {path}: {e}")


_load_yaml_playbooks()
