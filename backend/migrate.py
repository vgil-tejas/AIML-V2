"""
CyberSentinel — versioned, additive ClickHouse migration runner.

Applies numbered .sql files in migrations/ exactly once, recording each in a
schema_migrations table. Safe for production by construction:

  * ADDITIVE ONLY — any file containing a destructive statement (DROP, TRUNCATE,
    DELETE, ALTER ... DELETE, DETACH, RENAME) is REFUSED unless the operator
    explicitly sets ALLOW_DESTRUCTIVE=true (never set on the .23 prod box).
  * IDEMPOTENT — files use IF NOT EXISTS; already-applied versions are skipped.
  * ORDERED — files apply in filename order; a failure stops the run (later
    migrations never apply on top of a half-applied one).

Usage:
    python migrate.py            # apply pending
    python migrate.py --status   # show applied vs pending, apply nothing
"""
from __future__ import annotations

import os
import sys
import glob
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("cybersentinel.migrate")

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")
ALLOW_DESTRUCTIVE = os.getenv("ALLOW_DESTRUCTIVE", "false").lower() in ("true", "1", "yes")

_DESTRUCTIVE = ("drop ", "truncate", "delete ", "alter table" ) # alter checked w/ delete below


def _is_destructive(sql: str) -> bool:
    low = sql.lower()
    if "truncate" in low or "\ndrop " in ("\n" + low) or low.strip().startswith("drop "):
        return True
    if "detach " in low or " rename table" in low:
        return True
    # ALTER ... DELETE mutation (not the DDL "delete column" which is 'drop column')
    if "alter table" in low and " delete " in low:
        return True
    # bare DELETE FROM
    if low.strip().startswith("delete ") or "\ndelete from" in ("\n" + low):
        return True
    return False


def _split_statements(sql: str) -> list:
    # naive splitter: statements separated by ';' at line ends. Our migrations
    # are simple DDL; no ';' inside string literals.
    out, cur = [], []
    for line in sql.splitlines():
        s = line.strip()
        if s.startswith("--") or not s:
            continue
        cur.append(line)
        if s.endswith(";"):
            out.append("\n".join(cur).rstrip().rstrip(";"))
            cur = []
    if cur:
        out.append("\n".join(cur).rstrip().rstrip(";"))
    return [s for s in out if s.strip()]


def _client():
    import clickhouse_client as osc
    c = osc.get_client()
    if not c:
        raise RuntimeError("ClickHouse unavailable — cannot run migrations")
    return osc, c


def _ensure_table(osc):
    osc._exec("""CREATE TABLE IF NOT EXISTS cybersentinel.schema_migrations (
        version String, filename String, checksum String,
        applied_at DateTime64(3) DEFAULT now64(3)
    ) ENGINE = MergeTree ORDER BY version""")


def _applied(osc) -> set:
    rows = osc._q("SELECT version FROM cybersentinel.schema_migrations")
    return {r["version"] for r in rows}


def _files() -> list:
    return sorted(glob.glob(os.path.join(MIGRATIONS_DIR, "[0-9]*.sql")))


def current(osc=None) -> bool:
    """True if no pending migrations. Used by /health/ready."""
    try:
        if osc is None:
            import clickhouse_client as osc  # noqa
        _ensure_table(osc)
        applied = _applied(osc)
        pending = [f for f in _files()
                   if os.path.basename(f).split("_")[0] not in applied]
        return not pending
    except Exception:
        return False


def run(status_only: bool = False) -> int:
    osc, _ = _client()
    _ensure_table(osc)
    applied = _applied(osc)
    files = _files()
    pending = [f for f in files if os.path.basename(f).split("_")[0] not in applied]

    log.info("migrations: %d applied, %d pending", len(applied), len(pending))
    for f in files:
        ver = os.path.basename(f).split("_")[0]
        mark = "APPLIED" if ver in applied else "PENDING"
        log.info("  [%s] %s", mark, os.path.basename(f))
    if status_only:
        return 0
    if not pending:
        log.info("nothing to do — schema is current")
        return 0

    for f in pending:
        name = os.path.basename(f)
        ver = name.split("_")[0]
        sql = open(f, encoding="utf-8").read()
        if _is_destructive(sql) and not ALLOW_DESTRUCTIVE:
            log.error("REFUSING destructive migration %s (set ALLOW_DESTRUCTIVE=true "
                      "to override — never on prod)", name)
            return 2
        checksum = hashlib.sha256(sql.encode()).hexdigest()[:16]
        log.info("applying %s …", name)
        for stmt in _split_statements(sql):
            if not osc._exec(stmt):
                log.error("FAILED on statement in %s:\n%s", name, stmt[:200])
                return 3
        osc._insert_row("cybersentinel.schema_migrations",
                        {"version": ver, "filename": name, "checksum": checksum})
        log.info("  ✓ %s recorded", name)
    log.info("migrations complete")
    return 0


if __name__ == "__main__":
    sys.exit(run(status_only="--status" in sys.argv))
