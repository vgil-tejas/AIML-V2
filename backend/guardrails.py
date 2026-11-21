"""
Input guardrails for SOC Query — a thin, fail-closed check on the analyst's message
BEFORE it reaches the LLM, the web connector or the SQL generator.

Defends against oversized input (token cost / DoS), control-character noise, and
prompt-injection / system-prompt-exfiltration attempts ("ignore previous
instructions", "reveal your prompt", "act as DAN", ...). Output-side safety — the
SELECT-only SQL validator, ai_safety privacy sanitisation, and the web-search IP
guard — is enforced separately downstream; this is the first line, not the only one.
"""
import os
import re


def max_chars() -> int:
    return int(os.getenv("SOC_INPUT_MAX_CHARS", "1500"))


# Strip non-printable control chars (keep tab/newline out; collapse to space).
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# High-signal prompt-injection / jailbreak / prompt-leak patterns. Deliberately
# conservative (these phrasings don't occur in normal SOC questions) to avoid
# false positives on real analyst queries.
_INJECT = re.compile(
    r"(ignore (?:all |the |any )?(?:previous|above|prior|earlier|preceding) (?:instructions?|prompts?|messages?|rules?)|"
    r"disregard (?:all |the |any |previous |above |prior )(?:instructions?|prompts?|rules?|context)|"
    r"forget (?:all|everything|previous|prior|your instructions|what)|"
    r"(?:reveal|show|print|repeat|expose|leak|output|tell me) (?:me )?(?:your|the) (?:system )?(?:prompt|instructions?|rules|guidelines)|"
    r"what (?:is|are) your (?:system )?(?:prompt|instructions|rules)|"
    r"you are now|from now on you (?:are|will|must)|act as (?:a |an )?(?:dan|jailbreak|unrestricted|unfiltered)|"
    r"\bjailbreak\b|developer mode|do anything now|override (?:your |the )?(?:rules|instructions|safety|guardrails)|"
    r"pretend (?:you are|to be)|bypass (?:your |the )?(?:rules|safety|restrictions))",
    re.I)


def check(question: str):
    """Return (ok: bool, reason: str, cleaned: str).

    reason is "" when ok, else one of: "empty", "too_long", "injection".
    cleaned is the control-char-stripped, whitespace-collapsed question to use
    downstream (truncated to the cap on "too_long")."""
    q = _CTRL.sub(" ", question or "")
    q = " ".join(q.split())
    if not q:
        return False, "empty", q
    if len(q) > max_chars():
        return False, "too_long", q[:max_chars()]
    if _INJECT.search(q):
        return False, "injection", q
    return True, "", q
