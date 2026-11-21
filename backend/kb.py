"""
Vectorless knowledge-base retriever for CyberSentinel SOC Query.

- Corpus: backend/knowledge/system.md (the single source of truth about our own
  product). Edit that file to teach the assistant something new.
- Retrieval: classic BM25, word-by-word, pure Python stdlib. No embeddings, no
  vector database, nothing leaves the box. Synchronous and fast (small corpus).
- Auto-update: the index rebuilds itself the moment system.md's mtime changes,
  so a knowledge edit takes effect on the next query with no code change and no
  rebuild when the knowledge dir is mounted.

Chunking: each `##` / `###` heading starts one retrievable chunk; its body runs
until the next heading of the same or a higher level. A `page_id:` line directly
under a heading is lifted into chunk metadata (and dropped from the body) so a
retrieved chunk can drive a console deep-link.
"""
from __future__ import annotations

import math
import os
import re
import threading
from pathlib import Path
from typing import Optional

# Resolve the corpus next to this module (works baked at /app or mounted), with
# an env override for odd deployments.
_DEFAULT_PATH = Path(__file__).resolve().parent / "knowledge" / "system.md"
KB_PATH = Path(os.getenv("KB_PATH", str(_DEFAULT_PATH)))

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_PAGEID_RE = re.compile(r"^\s*page_id:\s*([a-z0-9_\-]+)\s*$", re.I)

# Tiny stopword list — enough to stop "the/of/and" from dominating BM25 without
# needing a dependency. Kept short on purpose (BM25's idf already down-weights
# common terms).
_STOP = frozenset((
    "the a an and or of to in on for is are be it its this that these those with as at by "
    "from into our we you your their they them he she his her i me my how do does did what "
    "which who whom where when why can could should would will shall may might must not no "
    "yes if then than so such about over under up down out off above below again more most "
    "some any all each other one two per via using use used use").split())

# BM25 params (standard defaults).
_K1 = 1.5
_B = 0.75


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall((text or "").lower())
            if len(t) >= 2 and t not in _STOP]


class _Chunk:
    __slots__ = ("id", "title", "breadcrumb", "page_id", "text", "tf", "length")

    def __init__(self, cid: int, title: str, breadcrumb: str, page_id: Optional[str], text: str):
        self.id = cid
        self.title = title
        self.breadcrumb = breadcrumb
        self.page_id = page_id
        self.text = text
        toks = _tokenize(title + " " + title + " " + text)   # title weighted ×2
        self.length = len(toks)
        tf: dict[str, int] = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        self.tf = tf


class _Index:
    def __init__(self):
        self.chunks: list[_Chunk] = []
        self.df: dict[str, int] = {}          # term -> #chunks containing it
        self.avgdl: float = 0.0
        self.n: int = 0
        self.mtime: float = -1.0
        self.ok: bool = False

    def build(self, md: str) -> None:
        self.chunks = _parse_chunks(md)
        self.n = len(self.chunks)
        df: dict[str, int] = {}
        total_len = 0
        for c in self.chunks:
            total_len += c.length
            for term in c.tf:
                df[term] = df.get(term, 0) + 1
        self.df = df
        self.avgdl = (total_len / self.n) if self.n else 0.0
        self.ok = self.n > 0

    def _idf(self, term: str) -> float:
        n_t = self.df.get(term, 0)
        if n_t == 0:
            return 0.0
        return math.log(1.0 + (self.n - n_t + 0.5) / (n_t + 0.5))

    def search(self, query: str, k: int = 4):
        q_terms = _tokenize(query)
        if not q_terms or not self.ok:
            return []
        q_set = list(dict.fromkeys(q_terms))   # dedupe, keep order
        idf = {t: self._idf(t) for t in q_set}
        scored = []
        for c in self.chunks:
            s = 0.0
            for t in q_set:
                f = c.tf.get(t)
                if not f:
                    continue
                denom = f + _K1 * (1.0 - _B + _B * (c.length / self.avgdl if self.avgdl else 1.0))
                s += idf[t] * (f * (_K1 + 1.0)) / denom
            if s > 0:
                scored.append((s, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:max(1, k)]


def _parse_chunks(md: str) -> list[_Chunk]:
    """Split markdown into chunks at `##`/`###` headings. The leading `#` title and
    any `#` H1 become breadcrumb context, not their own chunk."""
    lines = md.splitlines()
    chunks: list[_Chunk] = []
    cid = 0
    h1 = ""
    cur_title = ""
    cur_breadcrumb = ""
    cur_page = None
    cur_body: list[str] = []
    last_h2 = ""

    def flush():
        nonlocal cid
        if cur_title and (cur_body or cur_page):
            body = "\n".join(cur_body).strip()
            chunks.append(_Chunk(cid, cur_title, cur_breadcrumb, cur_page, body))
            cid += 1

    for ln in lines:
        m = _HEADING_RE.match(ln)
        if m:
            level = len(m.group(1))
            text = m.group(2).strip()
            if level == 1:
                # document title / H1 — context only, not a chunk
                flush()
                h1 = text
                cur_title = ""
                cur_body = []
                cur_page = None
                cur_breadcrumb = ""
                last_h2 = ""
                continue
            # level 2 or 3 -> start a new chunk
            flush()
            cur_title = text
            cur_body = []
            cur_page = None
            if level == 2:
                last_h2 = text
                cur_breadcrumb = h1
            else:  # level 3 nests under the last H2
                cur_breadcrumb = (h1 + " › " + last_h2).strip(" ›") if (h1 or last_h2) else ""
            continue
        # non-heading line
        if not cur_title:
            continue   # preamble before the first chunk heading
        pm = _PAGEID_RE.match(ln)
        if pm and cur_page is None and not _tokenize("".join(cur_body)):
            cur_page = pm.group(1).lower()
            continue   # lift page_id out of the body
        cur_body.append(ln)
    flush()
    return chunks


# ── module singleton + public API ────────────────────────────────────────────
_IDX = _Index()
_LOCK = threading.Lock()


def _ensure_fresh() -> None:
    """Rebuild the index if the corpus file changed (or on first use). Cheap: a
    single stat() per call, a parse only when mtime moved."""
    try:
        st = KB_PATH.stat()
    except OSError:
        with _LOCK:
            if _IDX.mtime != -2.0:
                _IDX.chunks, _IDX.ok, _IDX.n, _IDX.mtime = [], False, 0, -2.0
        return
    if st.st_mtime == _IDX.mtime:
        return
    with _LOCK:
        if st.st_mtime == _IDX.mtime:
            return
        try:
            md = KB_PATH.read_text(encoding="utf-8")
        except Exception:
            _IDX.ok = False
            return
        _IDX.build(md)
        _IDX.mtime = st.st_mtime


def search(query: str, k: int = 4, min_score: float = 0.0) -> list[dict]:
    """Return up to k relevant chunks as dicts: {title, page_id, text, score,
    breadcrumb}. Empty list if nothing relevant or the corpus is missing."""
    _ensure_fresh()
    out = []
    for score, c in _IDX.search(query, k=k):
        if score < min_score:
            continue
        out.append({"title": c.title, "page_id": c.page_id, "text": c.text,
                    "breadcrumb": c.breadcrumb, "score": round(float(score), 4)})
    return out


def ready() -> bool:
    _ensure_fresh()
    return _IDX.ok


def stats() -> dict:
    _ensure_fresh()
    return {"ready": _IDX.ok, "chunks": _IDX.n, "terms": len(_IDX.df),
            "avg_len": round(_IDX.avgdl, 1), "path": str(KB_PATH),
            "exists": KB_PATH.exists()}
