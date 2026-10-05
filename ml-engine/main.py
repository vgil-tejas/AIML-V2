"""
CyberSentinel Risk Engine v3.1
==============================
A single, unified per-IP **risk score (0-100)** that fuses three signals:

  1. Anomaly      — Isolation Forest over behavioural feature vectors.
  2. Deviation    — baseline-deviation alerts already detected by the backend.
  3. Threat-intel — known-bad subnets.

Retraining runs automatically every 24 h (and after every 10 k new logs) via an
in-process APScheduler job — no separate ml-intern container needed.

v3.1 performance changes:
  - Thread pool + semaphore: ClickHouse calls never block the async event loop
  - In-memory model cache: model loaded once at startup, not per request
  - TTL caches: health (30s), anomalies (60s), baseline_alerts (60s), clusters (120s)
  - Background pre-computation: health + anomalies refreshed proactively
"""
import asyncio
import os, sys, joblib, json, logging, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import networkx as nx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

sys.path.insert(0, "/app")
try:
    import clickhouse_client as osc
    STORE_ENABLED = osc.CLICKHOUSE_ENABLED
except ImportError:
    osc = None
    STORE_ENABLED = False

app = FastAPI(title="CyberSentinel Risk Engine", version="3.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

MODEL_DIR = Path(os.getenv("MODEL_DIR", "./models"))
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH  = MODEL_DIR / "isolation_forest.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"

KNOWN_BAD_SUBNETS = [s.strip() for s in os.getenv(
    "KNOWN_BAD_SUBNETS", "45.227.,193.169.,141.98.,185.220.").split(",") if s.strip()]

FEATURE_COLS = [
    "n_events", "event_rate_pm", "avg_interval_s", "min_interval_s",
    "std_interval_s", "unique_dst_ips", "unique_dst_ports", "unique_countries",
    "pct_critical", "pct_high", "brute_force_cnt", "ssh_bf_cnt",
    "rdp_cnt", "db_scan_cnt", "known_bad_cnt", "priv_esc_cnt",
    "vpn_bf_cnt", "baseline_alerts", "critical_alerts",
]

# ── Thread pool — ClickHouse calls run in worker threads, never block the loop ──
_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="ml-worker")
_ch_sem   = asyncio.Semaphore(6)

async def _to_thread(fn, *args):
    async with _ch_sem:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, fn, *args)

# ── In-memory model cache — loaded once, reloaded only after retraining ──────
_model  = None
_scaler = None

def _load_model():
    global _model, _scaler
    if MODEL_PATH.exists() and SCALER_PATH.exists():
        try:
            _model  = joblib.load(MODEL_PATH)
            _scaler = joblib.load(SCALER_PATH)
        except Exception as e:
            logging.getLogger("risk-engine").warning(f"model load failed: {e}")

# ── TTL caches ────────────────────────────────────────────────────────────────
_health_cache: dict = {}
_health_cache_ts: float = 0.0
_HEALTH_TTL = 30

_anomalies_cache: list = []
_anomalies_cache_ts: float = 0.0
_ANOMALIES_TTL = 60

_baseline_alerts_cache: dict = {}
_baseline_alerts_cache_ts: float = 0.0
_BASELINE_ALERTS_TTL = 60

_clusters_cache: dict = {}
_clusters_cache_ts: float = 0.0
_CLUSTERS_TTL = 120


# ── feature extraction ────────────────────────────────────────────────────────

def extract_ip_features(ip: str) -> dict:
    if not (STORE_ENABLED and osc):
        return {}
    events = osc.get_ip_events(ip, limit=2000)
    if not events:
        return {}
    f = osc.extract_features_from_events(ip, events)
    if not f:
        return {}
    total_alerts, crit_alerts = osc.get_alert_counts(ip)
    f["baseline_alerts"] = total_alerts
    f["critical_alerts"] = crit_alerts
    return f


def get_all_ip_features() -> list[dict]:
    if not (STORE_ENABLED and osc):
        return []
    if hasattr(osc, "get_all_ip_features_batch"):
        alert_counts = osc.get_all_alert_counts_batch() if hasattr(osc, "get_all_alert_counts_batch") else {}
        batch = osc.get_all_ip_features_batch(alert_counts)
        if batch:
            return batch
    features = []
    for ip in osc.get_all_unique_ips(size=5000):
        f = extract_ip_features(ip)
        if f:
            features.append(f)
    return features


# ── risk fusion ───────────────────────────────────────────────────────────────

def _intel_points(ip: str) -> tuple[int, dict]:
    known_bad = any(ip.startswith(s) for s in KNOWN_BAD_SUBNETS)
    pts = 25 if known_bad else 0
    return pts, {"known_bad_subnet": known_bad}


def _deviation_points(f: dict) -> tuple[int, dict]:
    base = int(f.get("baseline_alerts", 0))
    crit = int(f.get("critical_alerts", 0))
    pts = min(40, base * 3 + crit * 8)
    return pts, {"baseline_alerts": base, "critical_alerts": crit}


def fuse_risk(f: dict, anomaly_score: float, is_anomaly: bool) -> dict:
    ip = f["ip"]
    anomaly_pts = max(0, min(55, int((0.5 - anomaly_score) * 55)))
    dev_pts, dev_detail = _deviation_points(f)
    intel_pts, intel_detail = _intel_points(ip)

    risk = max(0, min(100, anomaly_pts + dev_pts + intel_pts))
    if is_anomaly:
        risk = max(risk, 50)

    band = ("critical" if risk >= 80 else "high" if risk >= 60
            else "medium" if risk >= 35 else "low")
    components = {
        "anomaly":   {"points": anomaly_pts, "score": round(anomaly_score, 4), "is_anomaly": is_anomaly},
        "deviation": {"points": dev_pts, **dev_detail},
        "intel":     {"points": intel_pts, **intel_detail},
    }
    return {"ip": ip, "risk_score": risk, "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly, "band": band, "components": components}


def _persist(score: dict):
    if STORE_ENABLED and osc:
        osc.save_ml_score(score["ip"], score["risk_score"], score["anomaly_score"],
                          score["is_anomaly"], score["components"])


# ── training + bulk scoring ───────────────────────────────────────────────────

def train_isolation_forest(features: list) -> tuple:
    if len(features) < 5:
        return None, None
    X = np.array([[f.get(c, 0) for c in FEATURE_COLS] for f in features])
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=150)
    model.fit(Xs)
    return model, scaler


def score_features(model, scaler, features: list[dict]) -> list[dict]:
    if not features:
        return []
    X = np.array([[f.get(c, 0) for c in FEATURE_COLS] for f in features])
    Xs = scaler.transform(X)
    raw_scores = model.decision_function(Xs)
    preds = model.predict(Xs)

    scored = []
    for i, f in enumerate(features):
        s = fuse_risk(f, float(raw_scores[i]), bool(preds[i] == -1))
        _persist(s)
        scored.append(s)
    return scored


_train_lock = None

@app.post("/api/ml/train")
async def train_model():
    global _train_lock, _model, _scaler
    if _train_lock is None:
        _train_lock = asyncio.Lock()
    if _train_lock.locked():
        return {"status": "already_training", "note": "Training already in progress — try again shortly"}
    async with _train_lock:
        features = await _to_thread(get_all_ip_features)
        if len(features) < 5:
            return {"status": "not_enough_data", "ip_count": len(features)}

        model, scaler = await _to_thread(train_isolation_forest, features)
        if model is None:
            return {"status": "training_failed"}

        await _to_thread(joblib.dump, model, MODEL_PATH)
        await _to_thread(joblib.dump, scaler, SCALER_PATH)
        _model = model
        _scaler = scaler  # update in-memory cache

        scored = await _to_thread(score_features, model, scaler, features)
        anomalies = [s for s in scored if s["is_anomaly"]]
        return {
            "status": "trained",
            "ip_count": len(features),
            "scored": len(scored),
            "anomalies": len(anomalies),
            "top_risk": sorted(scored, key=lambda x: x["risk_score"], reverse=True)[:10],
        }


@app.post("/api/ml/rescore")
async def rescore_all():
    if not MODEL_PATH.exists():
        return {"status": "no_model", "note": "POST /api/ml/train first"}
    features = await _to_thread(get_all_ip_features)
    if not features:
        return {"status": "no_data"}
    model = _model or joblib.load(MODEL_PATH)
    scaler = _scaler or joblib.load(SCALER_PATH)
    def _do():
        return score_features(model, scaler, features)
    scored = await _to_thread(_do)
    return {"status": "rescored", "scored": len(scored)}


@app.get("/api/ml/score/{ip}")
async def score_ip(ip: str, live: bool = False):
    """Score for one IP.

    Default (live=false): return the STORED score - the exact number the
    anomalies list shows - so every view of this IP agrees. Features are
    still extracted for display, but the score numbers are the stored ones.
    live=true: recompute on current features, persist, and bust the
    anomalies-list cache so the list updates to match immediately.
    """
    global _anomalies_cache_ts
    features = await _to_thread(extract_ip_features, ip)

    if not live:
        stored = await _to_thread(osc.get_ml_score, ip) if (STORE_ENABLED and osc) else None
        if stored:
            return {**stored, "features": features or None, "source": "stored"}
        # nothing stored yet -> fall through and compute a first score

    if not features:
        intel_pts, intel_detail = _intel_points(ip)
        if intel_pts:
            s = {"ip": ip, "risk_score": intel_pts, "anomaly_score": 0.0,
                 "is_anomaly": False, "band": "medium" if intel_pts >= 35 else "low",
                 "components": {"intel": {"points": intel_pts, **intel_detail}}}
            await _to_thread(_persist, s)
            _anomalies_cache_ts = 0.0
            return {**s, "source": "intel_only"}
        return {"ip": ip, "found": False}

    if _model is None:
        return {"ip": ip, "features": features, "anomaly_score": None,
                "note": "Model not trained yet. POST /api/ml/train first."}

    x = np.array([[features.get(c, 0) for c in FEATURE_COLS]])
    xs = _scaler.transform(x)
    anomaly_score = float(_model.decision_function(xs)[0])
    is_anom = bool(_model.predict(xs)[0] == -1)

    s = fuse_risk(features, anomaly_score, is_anom)
    await _to_thread(_persist, s)
    _anomalies_cache_ts = 0.0   # the list must reflect this new score at once
    return {**s, "features": features, "source": "live"}


_anomalies_total = 0  # real count of is_anomaly=1 (the list is capped at 500)


@app.get("/api/ml/anomalies")
async def list_anomalies():
    global _anomalies_cache, _anomalies_cache_ts, _anomalies_total
    if _anomalies_cache and time.time() - _anomalies_cache_ts < _ANOMALIES_TTL:
        return {"anomalies": _anomalies_cache, "total": _anomalies_total, "shown": len(_anomalies_cache)}
    if not (STORE_ENABLED and osc):
        return {"anomalies": [], "total": 0, "shown": 0}
    result = await _to_thread(osc.get_ml_anomalies, 500)
    total = await _to_thread(osc.count_ml_anomalies)
    if result is not None:
        _anomalies_cache = result
        _anomalies_cache_ts = time.time()
        _anomalies_total = int(total or 0)
    return {"anomalies": _anomalies_cache, "total": _anomalies_total, "shown": len(_anomalies_cache)}


@app.get("/api/ml/scores")
async def list_scores(limit: int = 100):
    if not (STORE_ENABLED and osc):
        return {"scores": []}
    scores = await _to_thread(osc.get_all_ml_scores, limit)
    return {"scores": scores}


# ── baseline deviation ────────────────────────────────────────────────────────

def _deviation_summary(ip: str) -> dict:
    alerts = osc.get_deviations(ip=ip, limit=50) if (STORE_ENABLED and osc) else []
    alerts.sort(key=lambda x: x.get("ts", ""), reverse=True)
    deviation_score = sum({"critical": 10, "high": 5, "medium": 2, "low": 1}.get(a.get("severity", "low"), 1)
                          for a in alerts)
    return {
        "ip": ip,
        "has_baseline": bool(STORE_ENABLED and osc and osc.get_baseline(ip)),
        "alert_count": len(alerts),
        "deviation_score": deviation_score,
        "alerts": alerts[:10],
        "alert_types": list({a.get("type") for a in alerts}),
    }


@app.get("/api/ml/baseline/{ip}")
async def ml_baseline_report(ip: str):
    return await _to_thread(_deviation_summary, ip)


@app.get("/api/ml/baseline-alerts")
async def all_baseline_alerts():
    global _baseline_alerts_cache, _baseline_alerts_cache_ts
    if _baseline_alerts_cache and time.time() - _baseline_alerts_cache_ts < _BASELINE_ALERTS_TTL:
        return _baseline_alerts_cache

    if not (STORE_ENABLED and osc):
        return {"total": 0, "ips": []}

    def _compute():
        ips = {a.get("ip") for a in osc.get_deviations(limit=2000) if a.get("ip")}
        results = [_deviation_summary(ip) for ip in ips]
        results.sort(key=lambda x: x.get("deviation_score", 0), reverse=True)
        return {"total": len(results), "ips": results[:50]}

    result = await _to_thread(_compute)
    _baseline_alerts_cache = result
    _baseline_alerts_cache_ts = time.time()
    return result


# ── subnet clustering ─────────────────────────────────────────────────────────

@app.get("/api/ml/clusters")
async def get_clusters():
    global _clusters_cache, _clusters_cache_ts
    if _clusters_cache and time.time() - _clusters_cache_ts < _CLUSTERS_TTL:
        return _clusters_cache

    def _compute():
        ips = osc.get_all_unique_ips(size=10000) if (STORE_ENABLED and osc) else []
        G = nx.Graph()
        subnets: dict[str, list] = {}
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4:
                subnets.setdefault(".".join(parts[:3]), []).append(ip)

        for sn, sn_ips in subnets.items():
            if len(sn_ips) > 1:
                for ip in sn_ips:
                    G.add_node(ip, subnet=sn)
                for i in range(len(sn_ips)):
                    for j in range(i + 1, len(sn_ips)):
                        G.add_edge(sn_ips[i], sn_ips[j])

        # Batch event + alert counts instead of per-IP queries
        all_ips_in_clusters = []
        components_list = [c for c in nx.connected_components(G) if len(c) > 1]
        for component in components_list:
            all_ips_in_clusters.extend(component)

        clusters = []
        for component in components_list:
            ips_list = list(component)
            subnet_key = ".".join(ips_list[0].split(".")[:3]) + ".x/24"
            total_events = 0
            total_alerts = 0
            if STORE_ENABLED and osc:
                for ip in ips_list:
                    total_events += osc.get_ip_total_count(ip) or 0
                    t, _ = osc.get_alert_counts(ip)
                    total_alerts += t
            clusters.append({
                "subnet": subnet_key,
                "ip_count": len(ips_list),
                "ips": ips_list[:20],
                "total_events": total_events,
                "total_alerts": total_alerts,
                "threat_level": ("critical" if total_events > 500 else
                                 "high" if total_events > 100 else "medium"),
            })

        clusters.sort(key=lambda x: x["total_events"], reverse=True)
        return {"clusters": clusters, "total_subnets": len(subnets)}

    result = await _to_thread(_compute)
    _clusters_cache = result
    _clusters_cache_ts = time.time()
    return result


# ── health ────────────────────────────────────────────────────────────────────

def _compute_health() -> dict:
    reg = _load_registry()
    return {
        "status": "ok",
        "version": "3.1.0",
        "model_ready": MODEL_PATH.exists(),
        "store_enabled": STORE_ENABLED,
        "scored_ips": osc.count_ml_scores() if (STORE_ENABLED and osc) else 0,
        "scheduler_running": _scheduler.running,
        "last_trained_at": reg.get("last_trained_at"),
        "log_count_at_last_train": reg.get("log_count_at_last_train", 0),
        "time": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/ml/health")
async def ml_health():
    global _health_cache, _health_cache_ts
    if _health_cache and time.time() - _health_cache_ts < _HEALTH_TTL:
        return _health_cache
    result = await _to_thread(_compute_health)
    _health_cache = result
    _health_cache_ts = time.time()
    return result


# ── Model registry ────────────────────────────────────────────────────────────
REGISTRY_PATH = MODEL_DIR / "registry.json"

def _load_registry() -> dict:
    try:
        return json.loads(REGISTRY_PATH.read_text()) if REGISTRY_PATH.exists() else {}
    except Exception:
        return {}

def _save_registry(data: dict):
    try:
        REGISTRY_PATH.write_text(json.dumps(data, default=str))
    except Exception as e:
        logging.getLogger("risk-engine").warning(f"registry write failed: {e}")


# ── Auto-retrain scheduler ────────────────────────────────────────────────────
RETRAIN_HOURS      = int(os.getenv("MODEL_RETRAIN_HOURS", "24"))
NEW_LOG_THRESHOLD  = int(os.getenv("ML_NEW_LOG_THRESHOLD", "10000"))
_log = logging.getLogger("risk-engine")

def _auto_retrain():
    global _model, _scaler
    if not (STORE_ENABLED and osc):
        return
    reg = _load_registry()
    now = datetime.now(timezone.utc)

    last_str = reg.get("last_trained_at")
    hours_elapsed = 999
    if last_str:
        try:
            from datetime import datetime as _dt
            last_dt = _dt.fromisoformat(last_str)
            hours_elapsed = (now - last_dt).total_seconds() / 3600
        except Exception:
            pass

    current_count = osc.get_total_doc_count() or 0
    count_at_last  = reg.get("log_count_at_last_train", 0)
    new_logs = max(0, current_count - count_at_last)

    if hours_elapsed < RETRAIN_HOURS and new_logs < NEW_LOG_THRESHOLD:
        return

    reason = f"time ({hours_elapsed:.1f}h)" if hours_elapsed >= RETRAIN_HOURS else f"log volume ({new_logs:,} new)"
    _log.info(f"[auto-retrain] triggered by {reason}")

    features = get_all_ip_features()
    if len(features) < 5:
        _log.info("[auto-retrain] not enough IPs — skipping")
        return

    model, scaler = train_isolation_forest(features)
    if model is None:
        _log.warning("[auto-retrain] training failed")
        return

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    _model  = model
    _scaler = scaler
    scored = score_features(model, scaler, features)
    anomalies = [s for s in scored if s["is_anomaly"]]
    _save_registry({
        "last_trained_at": now.isoformat(),
        "log_count_at_last_train": current_count,
        "ip_count": len(features),
        "anomaly_count": len(anomalies),
    })
    _log.info(f"[auto-retrain] done — {len(features)} IPs, {len(anomalies)} anomalies")


_scheduler = BackgroundScheduler(timezone="UTC")
_scheduler.add_job(_auto_retrain, "interval", hours=1, id="auto_retrain",
                   max_instances=1, coalesce=True)


@app.on_event("startup")
def _start_scheduler():
    _load_model()  # load model into memory once at boot
    _scheduler.start()
    _log.info(f"[scheduler] started — retrain every {RETRAIN_HOURS}h or {NEW_LOG_THRESHOLD:,} new logs")


@app.on_event("startup")
async def _start_background_refresh():
    async def _loop():
        await asyncio.sleep(3)
        while True:
            try:
                await asyncio.gather(ml_health(), list_anomalies(), return_exceptions=True)
            except Exception:
                pass
            await asyncio.sleep(30)
    asyncio.create_task(_loop())


@app.on_event("shutdown")
def _stop_scheduler():
    _scheduler.shutdown(wait=False)
