"""Hash type detection — length + prefix + character-set heuristics."""

from __future__ import annotations

import re

from donhash._hash_db import (
    HASH_DB,
    LENGTH_MAP,
    PREFIX_MAP,
)

# Hash types that are commonly encountered and should be ranked first when
# multiple candidates match. The earlier in this list, the higher the priority.
PRIORITY_TYPES: list[str] = [
    "MD5",
    "SHA-256",
    "SHA-1",
    "SHA-512",
    "NTLM",
    "NT",
    "MD4",
    "LM",
    "CRC-32",
    "SHA-224",
    "SHA-384",
    "RIPEMD-160",
    "Whirlpool",
    "BLAKE2b",
    "BLAKE2s",
    "SHA3-256",
    "RIPEMD-256",
    "MySQL5.x",
    "MySQL4.1",
    "PostgreSQL-MD5",
    "Django(SHA-256)",
]

# Pre-compiled regexes (avoid recompiling per call).
_HEX_RE = re.compile(r"[a-fA-F0-9]+")
_MYSQL41_RE = re.compile(r"\*[a-fA-F0-9]{40}")


def _is_hex(s: str) -> bool:
    return bool(_HEX_RE.fullmatch(s))


def _is_base64(s: str) -> bool:
    """Kept for backwards compatibility / external callers; not used internally."""
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s))


def detect_hash_type(hash_str: str) -> list[tuple[str, str, int]]:
    """Detect possible hash types for the given string.

    Returns a list of ``(name, description, category_id)`` tuples, ordered by
    confidence (most likely first). The list may be empty if no candidate
    matches.
    """
    if not hash_str or not isinstance(hash_str, str):
        return []

    h = hash_str.strip()
    if not h:
        return []

    results: list[tuple[str, str, int]] = []
    seen: set = set()

    # 1) Prefix-based detection (highest confidence — crypt-style hashes).
    #    Skip single-character prefixes here to avoid false positives like
    #    '*' or '_' matching arbitrary strings. They're handled by strict
    #    regexes below.
    for pfx, names in PREFIX_MAP.items():
        if len(pfx) < 2:
            continue
        if h.startswith(pfx):
            for n in names:
                if n not in seen:
                    spec = HASH_DB[n]
                    results.append((n, spec.desc, spec.cat))
                    seen.add(n)

    # 2) MySQL 4.1+ special case: '*' + exactly 40 hex chars (strict regex)
    if _MYSQL41_RE.fullmatch(h):
        n = "MySQL4.1"
        if n not in seen:
            results.insert(0, (n, HASH_DB[n].desc, HASH_DB[n].cat))
            seen.add(n)

    # 3) Hex-only detection by length
    if _is_hex(h):
        length = len(h)
        if length in LENGTH_MAP:
            for n in LENGTH_MAP[length]:
                if n not in seen:
                    spec = HASH_DB[n]
                    results.append((n, spec.desc, spec.cat))
                    seen.add(n)

    # Sort by priority: known common types first, then registration order
    # (Python's sort is stable, so non-priority types keep their insertion
    # order, which is deterministic).
    priority_index = {n: i for i, n in enumerate(PRIORITY_TYPES)}
    results.sort(key=lambda x: priority_index.get(x[0], len(PRIORITY_TYPES)))

    return results


def best_guess(hash_str: str) -> tuple[str, str, int] | None:
    """Return the single most-likely hash type, or ``None`` if no candidate."""
    results = detect_hash_type(hash_str)
    return results[0] if results else None
