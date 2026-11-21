"""
ai_safety.py - outbound sanitisation for anything sent to an external LLM.

The bank's logs never leave the box. Before ANY prompt goes to the AI provider,
real identifiers are replaced with harmless, well-formed PLACEHOLDERS. For the
NL->SQL path the model emits those placeholders back inside the SQL, and we
substitute the real values in locally - so the query filters on the true value
while the provider only ever saw a decoy. Deterministic within a call, so
restore is exact.

Coverage (in order of masking):
  1. keyword-named usernames    ("user jsmith", "account 'alice'")
  2. caller gazetteer           (known usernames / hostnames / terms from the DB)
  3. emails
  4. IPv6
  5. MAC addresses
  6. account / card / Aadhaar / PAN / phone-style IDs
  7. Windows-style host / machine names (DESKTOP-xxxx, WIN-xxxx, SRV-xxxx ...)
  8. IPv4

Layers 1, 3-8 are pattern-based and need no model or data. Layer 2 is the
"NER-lite" gazetteer: the caller passes the real usernames / hostnames it already
knows (pulled from ClickHouse) via `extra_terms`, and they are masked by meaning
wherever they appear - catching the identifiers that have no fixed shape and so
cannot be found by regex alone. No external NER model is used, so nothing has to
leave the box to detect what must not leave the box.

Placeholders look like normal values of their type (TEST-NET-3 addresses,
.invalid emails, documentation MACs) so the model treats them naturally and
copies them verbatim into SQL.

Pure functions, no I/O, no third-party dependencies - unit-testable in isolation.
"""
from __future__ import annotations
import re

# RFC 5737 TEST-NET-3 (203.0.113.0/24) - guaranteed non-routable decoys.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# "user jsmith", "username = bob", "account 'alice'", "logged in as root"
_USERKW = re.compile(
    r"\b(?:user|username|account|login|logged in as|as user)\b[\s:='\"]+([A-Za-z0-9._\\\-]{2,64})",
    re.IGNORECASE,
)
# MAC (colon or dash separated).
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")
# Indian PAN: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F).
_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
# Long numeric IDs: account / card (13-19) / Aadhaar (12). 12+ digits avoids
# 10-digit epoch timestamps and short ports. Restore puts the real value back,
# so over-masking only ever hides more, never breaks the query.
_LONGID = re.compile(r"\b\d{12,19}\b")
# Indian mobile: optional +91 / 0, then a 10-digit number starting 6-9. The 6-9
# start avoids matching a 10-digit epoch (which starts with 1).
_PHONE = re.compile(r"\b(?:\+?91[\-\s]?|0)?[6-9]\d{9}\b")
# Windows / common host & server names: DESKTOP-5A2F, WIN-ABC123, SRV-DB01 ...
_HOSTNAME = re.compile(
    r"\b(?:DESKTOP|LAPTOP|WIN|PC|SRV|SERVER|HOST|NODE|VM|DC|WKS|WS)-[A-Za-z0-9]{2,}\b",
    re.IGNORECASE,
)


def _looks_like_ipv4(s: str) -> bool:
    try:
        parts = s.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _norm_terms(extra_terms) -> dict:
    """Normalise the caller gazetteer into {real_value: kind}. Accepts a dict
    {value: kind} or a plain iterable of strings (kind defaults to 'term')."""
    out: dict[str, str] = {}
    if not extra_terms:
        return out
    if isinstance(extra_terms, dict):
        items = extra_terms.items()
    else:
        items = ((t, "term") for t in extra_terms)
    for val, kind in items:
        v = (str(val) if val is not None else "").strip()
        if len(v) < 2:                      # 1-char terms are too noisy to mask
            continue
        k = kind if kind in ("user", "host", "term") else "term"
        out[v] = k
    return out


def sanitize_for_ai(text: str, extra_terms=None) -> tuple[str, dict]:
    """Return (sanitized_text, mapping) where mapping is placeholder -> real value.
    Real identifiers are swapped for decoys so nothing sensitive leaves.

    extra_terms: optional caller gazetteer of known sensitive strings
    (usernames / hostnames pulled from the DB). Dict {value: 'user'|'host'|'term'}
    or a plain iterable of strings. Masked by meaning wherever they appear."""
    if not text:
        return text or "", {}
    mapping: dict[str, str] = {}
    rev: dict[str, str] = {}      # real -> placeholder (so repeats map consistently)
    counters = {"ip": 0, "ip6": 0, "email": 0, "user": 0,
                "mac": 0, "id": 0, "pan": 0, "phone": 0, "host": 0, "term": 0}

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
        elif kind == "mac":
            ph = f"00:00:5e:00:53:{n % 256:02x}"        # RFC 7042 doc MAC range
        elif kind == "id":
            ph = f"{9000000000000 + n}"                  # 13-digit decoy id
        elif kind == "pan":
            ph = f"AAAAA{n % 10000:04d}A"                # PAN-shaped decoy
        elif kind == "phone":
            ph = f"90000{n % 100000:05d}"                # 10-digit decoy mobile
        elif kind == "host":
            ph = f"HOST-REDACTED-{n}"
        elif kind == "term":
            ph = f"redacted_entity_{n}"
        else:                                           # "user"
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

    # 2) caller gazetteer (NER-lite): exact known usernames / hostnames / terms.
    #    Longest first so a longer term is masked before a shorter one it contains;
    #    word-boundary guard so we never replace inside another token.
    terms = _norm_terms(extra_terms)
    for real in sorted(terms, key=len, reverse=True):
        kind = terms[real]
        pat = re.compile(r"(?<![A-Za-z0-9_.\-])" + re.escape(real) + r"(?![A-Za-z0-9_.\-])")
        out = pat.sub(lambda _m, r=real, k=kind: _ph(r, k), out)

    # 3) emails (before IPv4 so the domain's dots aren't eaten)
    out = _EMAIL.sub(lambda m: _ph(m.group(0), "email"), out)

    # 4) IPv6
    out = _IPV6.sub(lambda m: _ph(m.group(0), "ip6"), out)

    # 5) MAC addresses
    out = _MAC.sub(lambda m: _ph(m.group(0), "mac"), out)

    # 6) structured IDs: PAN, then long numeric IDs, then phone numbers
    out = _PAN.sub(lambda m: _ph(m.group(0), "pan"), out)
    out = _LONGID.sub(lambda m: _ph(m.group(0), "id"), out)
    out = _PHONE.sub(lambda m: _ph(m.group(0), "phone"), out)

    # 7) Windows-style host / machine names
    out = _HOSTNAME.sub(lambda m: _ph(m.group(0), "host"), out)

    # 8) IPv4 (validate octets; err toward redaction)
    def _ip_sub(m):
        real = m.group(0)
        return _ph(real, "ip") if _looks_like_ipv4(real) else real
    out = _IPV4.sub(_ip_sub, out)

    return out, mapping


def sanitize_many(parts: list, extra_terms=None) -> tuple[list, dict]:
    """Sanitise several strings with ONE consistent mapping (the same real value
    maps to the same placeholder across all parts). Returns (clean_parts, mapping)."""
    sep = "␞␞"             # symbol glyphs; never in real input
    joined = sep.join(str(p or "") for p in parts)
    clean, mapping = sanitize_for_ai(joined, extra_terms=extra_terms)
    out = clean.split(sep)
    # Guard against a count mismatch (shouldn't happen) - pad/truncate to len(parts).
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


def contains_sensitive(text: str, extra_terms=None) -> bool:
    """True if the text still carries a real identifier after sanitising - a
    tripwire so we can refuse to send something that slipped through. Checks real
    IPv4, emails, MACs, PANs, and (if supplied) any caller gazetteer term."""
    if not text:
        return False
    for m in _IPV4.finditer(text):
        v = m.group(0)
        if _looks_like_ipv4(v) and not v.startswith("203.0.113."):
            return True
    if _EMAIL.search(text.replace("@example.invalid", "")):
        return True
    for m in _MAC.finditer(text):                       # any non-decoy MAC
        if not m.group(0).lower().startswith("00:00:5e:00:53:"):
            return True
    if _PAN.search(text.replace("AAAAA", "")):          # any non-decoy PAN
        return True
    for real in _norm_terms(extra_terms):
        if re.search(r"(?<![A-Za-z0-9_.\-])" + re.escape(real) + r"(?![A-Za-z0-9_.\-])", text):
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
    tests_ok += 1
    # idempotent / no false positive on already-decoy
    assert not contains_sensitive("src_ip 203.0.113.5"), "decoy flagged"
    tests_ok += 1
    # NER-lite gazetteer: bare hostname + bare username (no keyword) are masked
    terms = {"DESKTOP-5A2F": "host", "rajesh": "user", "FILESRV01": "host"}
    q3 = "did rajesh log into DESKTOP-5A2F and reach FILESRV01"
    clean3, mp3 = sanitize_for_ai(q3, extra_terms=terms)
    assert "rajesh" not in clean3 and "DESKTOP-5A2F" not in clean3 and "FILESRV01" not in clean3, clean3
    assert contains_sensitive("user is rajesh", extra_terms=terms), "gazetteer tripwire"
    assert "rajesh" in restore_from_ai(clean3, mp3), "gazetteer restore"
    tests_ok += 1
    # heuristics: MAC, PAN, Aadhaar-length id, phone, host pattern - no gazetteer
    q4 = ("host WIN-DB01 nic 00:1a:2b:3c:4d:5e pan ABCDE1234F "
          "aadhaar 123456789012 phone +919812345678")
    clean4, mp4 = sanitize_for_ai(q4)
    for leak in ("00:1a:2b:3c:4d:5e", "ABCDE1234F", "123456789012", "9812345678", "WIN-DB01"):
        assert leak not in clean4, f"{leak} leaked: {clean4}"
    tests_ok += 1
    # consistency across parts (sanitize_many) with a gazetteer
    parts, mpm = sanitize_many(["who is rajesh", "trail for rajesh"], extra_terms={"rajesh": "user"})
    assert parts[0].split()[-1] == parts[1].split()[-1], parts   # same decoy both parts
    tests_ok += 1
    print(f"ai_safety self-test: {tests_ok}/7 passed")
