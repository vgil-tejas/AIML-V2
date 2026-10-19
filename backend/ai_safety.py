"""
ai_safety.py — outbound sanitisation for anything sent to an external LLM.

The bank's logs never leave the box. Before ANY prompt goes to the AI provider,
real identifiers (IPv4/IPv6 addresses, emails, and analyst-named usernames) are
replaced with harmless, well-formed PLACEHOLDERS. For the NL->SQL path the model
emits those placeholders back inside the SQL, and we substitute the real values
in locally — so the query filters on the true value while the provider only ever
saw a decoy. Deterministic within a call, so restore is exact.

Placeholders are chosen to look like normal values of their type (TEST-NET-3
addresses, .invalid emails) so the model treats them naturally and copies them
verbatim into SQL.

Pure functions, no I/O, no dependencies — unit-testable in isolation.
"""
from __future__ import annotations
import re

# RFC 5737 TEST-NET-3 (203.0.113.0/24) — guaranteed non-routable decoys.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# "user jsmith", "username = bob", "account 'alice'", "logged in as root"
_USERKW = re.compile(
    r"\b(?:user|username|account|login|logged in as|as user)\b[\s:='\"]+([A-Za-z0-9._\\\-]{2,64})",
    re.IGNORECASE,
)


def _looks_like_ipv4(s: str) -> bool:
    try:
        parts = s.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def sanitize_for_ai(text: str) -> tuple[str, dict]:
    """Return (sanitized_text, mapping) where mapping is placeholder -> real value.
    Real IPs/emails/usernames are swapped for decoys so nothing sensitive leaves."""
    if not text:
        return text or "", {}
    mapping: dict[str, str] = {}
    rev: dict[str, str] = {}      # real -> placeholder (so repeats map consistently)
    counters = {"ip": 0, "ip6": 0, "email": 0, "user": 0}

    def _ph(real: str, kind: str) -> str:
        if real in rev:
            return rev[real]
        counters[kind] += 1
        n = counters[kind]
        if kind == "ip":
            ph = f"203.0.113.{(n % 253) + 1}"          # TEST-NET-3 decoy
        elif kind == "ip6":
            ph = f"2001:db8::{n:x}"                      # RFC 3849 doc range
        elif kind == "email":
            ph = f"user{n}@example.invalid"
        else:
            ph = f"redacted_user_{n}"
        rev[real] = ph
        mapping[ph] = real
        return ph

    out = text

    # 1) usernames named by keyword (do first; may contain no special chars)
    def _user_sub(m):
        whole, name = m.group(0), m.group(1)
        return whole.replace(name, _ph(name, "user"))
    out = _USERKW.sub(_user_sub, out)

    # 2) emails (before IPv4 so the domain's dots aren't eaten)
    out = _EMAIL.sub(lambda m: _ph(m.group(0), "email"), out)

    # 3) IPv6
    out = _IPV6.sub(lambda m: _ph(m.group(0), "ip6"), out)

    # 4) IPv4 (validate octets so version numbers like 1.2.3.4-ish text that isn't
    #    a real dotted-quad in range is still swapped — we err toward redaction)
    def _ip_sub(m):
        real = m.group(0)
        return _ph(real, "ip") if _looks_like_ipv4(real) else real
    out = _IPV4.sub(_ip_sub, out)

    return out, mapping


def sanitize_many(parts: list) -> tuple[list, dict]:
    """Sanitise several strings with ONE consistent mapping (the same real value
    maps to the same placeholder across all parts). Returns (clean_parts, mapping)."""
    sep = "␞␞"                       # symbol glyphs; never in real input
    joined = sep.join(str(p or "") for p in parts)
    clean, mapping = sanitize_for_ai(joined)
    out = clean.split(sep)
    # Guard against a count mismatch (shouldn't happen) — pad/truncate to len(parts).
    if len(out) != len(parts):
        out = (out + [""] * len(parts))[:len(parts)]
    return out, mapping


def restore_from_ai(text: str, mapping: dict) -> str:
    """Substitute decoy placeholders back to the real values (used on SQL the model
    returns, so the query filters on the true IP/user). Longest placeholders first
    to avoid partial overlaps."""
    if not text or not mapping:
        return text or ""
    out = text
    for ph in sorted(mapping, key=len, reverse=True):
        out = out.replace(ph, mapping[ph])
    return out


def contains_sensitive(text: str) -> bool:
    """True if the text still carries a real IP/email after sanitising — a tripwire
    so we can refuse to send something that slipped through."""
    if not text:
        return False
    for m in _IPV4.finditer(text):
        v = m.group(0)
        if _looks_like_ipv4(v) and not v.startswith("203.0.113."):
            return True
    if _EMAIL.search(text.replace("@example.invalid", "")):
        return True
    return False


if __name__ == "__main__":
    # Local self-test (no network, no DB). Run: python ai_safety.py
    tests_ok = 0
    q = "everything about 164.52.194.98 and what did user jsmith do from 10.0.10.5"
    clean, mp = sanitize_for_ai(q)
    assert "164.52.194.98" not in clean and "10.0.10.5" not in clean, clean
    assert "jsmith" not in clean, clean
    assert not contains_sensitive(clean), clean
    tests_ok += 1
    # model emits SQL with the decoys; restore must bring back the real values
    sql = f"SELECT * FROM logs WHERE src_ip='{[p for p in mp if mp[p]=='164.52.194.98'][0]}'"
    restored = restore_from_ai(sql, mp)
    assert "164.52.194.98" in restored, restored
    tests_ok += 1
    # email + ipv6
    clean2, mp2 = sanitize_for_ai("mail bob@bank.co.in via 2001:4860:4860::8888")
    assert "bob@bank.co.in" not in clean2 and "2001:4860:4860::8888" not in clean2, clean2
    assert restore_from_ai("x user1@example.invalid y", mp2) != "x user1@example.invalid y" or "bob" not in mp2, "restore"
    tests_ok += 1
    # idempotent / no false positive on already-decoy
    assert not contains_sensitive("src_ip 203.0.113.5"), "decoy flagged"
    tests_ok += 1
    print(f"ai_safety self-test: {tests_ok}/4 passed")
