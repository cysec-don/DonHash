# DonHash — Advanced Hash Detector & Cracker
# Copyright (c) 2026 CySec Don (cysecdon@gmail.com)
#
# Licensed under the DonHash Attribution License v1.0 (DH-AL).
# See LICENSE file for full terms.
#
# Attribution requirement: All copies, forks, updates, modifications, or
# commercial applications of this software MUST retain the following
# attribution in a prominent location:
#
#     "This software is based on DonHash by CySec Don (cysecdon@gmail.com).
#      Original source: https://github.com/cysec-don/DonHash"
#
# For the full terms of the attribution requirement, see Sections 1-3 of
# the LICENSE file.

"""Hash cracking engine — dictionary attack with optional threading."""

from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from donhash._engine import compute_crypt_hash, compute_hash, extract_salt
from donhash._hash_db import CATEGORY_NAMES, CRYPT, DETECT, HASH_DB, SALTED


@dataclass
class CrackResult:
    """Result of a single hash-cracking attempt."""

    hash: str
    type: str
    category: str = ""
    password: str | None = None
    attempts: int = 0
    time: float = 0.0
    speed: float = 0.0
    status: str = "not_found"
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "hash": self.hash,
            "type": self.type,
            "category": self.category,
            "password": self.password,
            "attempts": self.attempts,
            "time": self.time,
            "speed": self.speed,
            "status": self.status,
            "error": self.error,
        }


# ─── Wordlist helpers ────────────────────────────────────────────────────────

def _iter_wordlist(path: str, batch_size: int = 4096) -> Iterator[str]:
    """Stream a wordlist file line by line (memory-bounded)."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n\r")


def _count_lines(path: str) -> int:
    """Count lines in a file efficiently (buffered binary read)."""
    count = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            count += chunk.count(b"\n")
    return count


# ─── Core check ──────────────────────────────────────────────────────────────

def _check_word(
    word: str,
    target_norm: str,
    hash_type: str,
    salt: str,
    is_salted: bool,
    is_crypt: bool,
    target_hash: str,
) -> bool:
    """Return True if ``word`` hashes to ``target_hash`` under ``hash_type``."""
    if is_crypt:
        cand = compute_crypt_hash(word, target_hash, hash_type, salt)
        if cand is None:
            return False
        # crypt-style hashes may differ in formatting; compare lowercase
        return cand.lower() == target_norm
    cand = compute_hash(word, hash_type, salt if is_salted else "")
    if cand is None:
        return False
    return cand.lower() == target_norm


# ─── Single-threaded ─────────────────────────────────────────────────────────

def _crack_single_thread(
    target_hash: str,
    target_norm: str,
    hash_type: str,
    wordlist_path: str,
    is_crypt: bool,
    is_salted: bool,
    salt: str,
    verbose: bool,
    total: int,
    start_time: float,
    progress_cb=None,
) -> tuple[bool, str, int]:
    found = False
    word = ""
    attempts = 0
    try:
        for line in _iter_wordlist(wordlist_path):
            word = line
            attempts += 1
            if _check_word(word, target_norm, hash_type, salt, is_salted, is_crypt, target_hash):
                found = True
                break
            if verbose and attempts % 50000 == 0:
                _print_progress(attempts, total, start_time)
            if progress_cb is not None:
                progress_cb(attempts)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    return found, word, attempts


# ─── Multi-threaded (chunked, streaming) ─────────────────────────────────────

def _read_batch(f, batch_size: int = 4096) -> list[str]:
    """Read up to ``batch_size`` lines from ``f``."""
    out = []
    for _ in range(batch_size):
        line = f.readline()
        if not line:
            break
        out.append(line.rstrip("\n\r"))
    return out


def _crack_multi_thread(
    target_hash: str,
    target_norm: str,
    hash_type: str,
    wordlist_path: str,
    is_salted: bool,
    salt: str,
    verbose: bool,
    total: int,
    num_threads: int,
    start_time: float,
    progress_cb=None,
) -> tuple[bool, str, int]:
    """Multi-threaded cracker.

    Design:
    - Reads the wordlist in fixed-size batches (default 4096 lines) to keep
      memory bounded regardless of wordlist size.
    - Submits up to ``num_threads`` batches in parallel and waits for ALL of
      them to complete (or for ``stop_event`` to fire) before reading more.
      This keeps all workers busy and gives a deterministic ``attempts``
      count (sum of all batch sizes that were started before ``stop_event``).
    - On a match: sets ``stop_event`` so workers short-circuit, but the main
      thread still drains in-flight futures to accumulate their counts.
    """
    found = False
    found_word = ""
    total_attempts = 0
    lock = threading.Lock()
    stop_event = threading.Event()

    def process_batch(batch: list[str]) -> int:
        nonlocal found, found_word
        local = 0
        for w in batch:
            if stop_event.is_set():
                return local
            local += 1
            if _check_word(w, target_norm, hash_type, salt, is_salted, False, target_hash):
                with lock:
                    if not found:
                        found = True
                        found_word = w
                        stop_event.set()
                return local
        return local

    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f, \
             ThreadPoolExecutor(max_workers=num_threads) as ex:
            # Carry-over batch from the previous iteration (None on first round)
            carry: list[str] | None = None
            while not stop_event.is_set():
                # Seed pending list with the carry (or read a fresh batch)
                if carry is not None:
                    pending = [ex.submit(process_batch, carry)]
                    carry = None
                else:
                    first = _read_batch(f, batch_size=4096)
                    if not first:
                        break
                    pending = [ex.submit(process_batch, first)]

                # Fill the pending list up to num_threads by pre-reading more
                # batches. The last pre-read becomes the carry for next iter.
                while len(pending) < num_threads and not stop_event.is_set():
                    nb = _read_batch(f, batch_size=4096)
                    if not nb:
                        break
                    if len(pending) + 1 < num_threads:
                        pending.append(ex.submit(process_batch, nb))
                    else:
                        # Save the last pre-read as the carry so it isn't
                        # processed inline on this iteration (which would
                        # serialize a single worker while others idle).
                        carry = nb
                        break

                # Wait for ALL pending futures (don't break early — accumulate
                # every batch's count for a deterministic total).
                for future in as_completed(pending):
                    total_attempts += future.result()
                if verbose:
                    _print_progress(total_attempts, total, start_time)
                if progress_cb is not None:
                    progress_cb(total_attempts)
                if stop_event.is_set():
                    break
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[!] Interrupted.")

    return found, found_word, total_attempts


def _print_progress(attempts: int, total: int, start_time: float) -> None:
    el = time.time() - start_time
    rate = attempts / el if el > 0 else 0
    pct = (attempts / total * 100) if total > 0 else 0
    sys.stderr.write(
        f"\r[Progress] {attempts:,}/{total:,} ({pct:.1f}%) | "
        f"{rate:,.0f} h/s | {el:.1f}s"
    )
    sys.stderr.flush()


# ─── Public API ──────────────────────────────────────────────────────────────

def crack_single_hash(
    target_hash: str,
    hash_type: str,
    wordlist_path: str,
    verbose: bool = False,
    ext_salt: str = "",
    num_threads: int = 5,
    progress_cb=None,
) -> CrackResult:
    """Attempt to crack a single hash using a wordlist.

    Returns a :class:`CrackResult` describing the outcome. If the hash type is
    detection-only, ``status`` will be ``"unsupported"`` and no cracking will
    be attempted.
    """
    result = CrackResult(hash=target_hash, type=hash_type)

    if not os.path.isfile(wordlist_path):
        result.error = f"Wordlist not found: {wordlist_path}"
        result.status = "error"
        return result

    spec = HASH_DB.get(hash_type)
    if spec is None:
        result.error = f"Unknown hash type: {hash_type}"
        result.status = "error"
        return result

    if spec.impl == DETECT:
        result.category = CATEGORY_NAMES.get(spec.cat, "Unknown")
        result.status = "unsupported"
        result.error = (
            f"Hash type '{hash_type}' is detection-only — no compute implementation. "
            "Use a specialized tool (e.g. hashcat, john) for cracking."
        )
        return result

    cat_name = CATEGORY_NAMES.get(spec.cat, "Unknown")
    result.category = cat_name

    target_norm = target_hash.strip().lower()
    is_crypt = spec.impl == CRYPT
    is_salted = spec.impl == SALTED
    salt = ext_salt or extract_salt(target_hash, hash_type)

    if is_salted and not salt:
        result.error = (
            f"Hash type '{hash_type}' requires a salt. Use -s/--salt to provide one."
        )
        result.status = "error"
        return result

    try:
        total = _count_lines(wordlist_path)
    except OSError as e:
        result.error = f"Error reading wordlist: {e}"
        result.status = "error"
        return result

    start = time.time()

    if is_crypt or num_threads <= 1:
        found, word, attempts = _crack_single_thread(
            target_hash, target_norm, hash_type, wordlist_path,
            is_crypt, is_salted, salt, verbose, total, start, progress_cb,
        )
    else:
        found, word, attempts = _crack_multi_thread(
            target_hash, target_norm, hash_type, wordlist_path,
            is_salted, salt, verbose, total, num_threads, start, progress_cb,
        )

    elapsed = time.time() - start
    rate = attempts / elapsed if elapsed > 0 else 0

    result.attempts = attempts
    result.time = round(elapsed, 3)
    result.speed = round(rate, 1)

    if found:
        result.password = word
        result.status = "cracked"
    else:
        result.status = "not_found"

    return result


def crack_from_file(
    file_path: str,
    wordlist_path: str,
    hash_type_override: str | None = None,
    verbose: bool = False,
    num_threads: int = 5,
    salt: str = "",
) -> list[CrackResult]:
    """Crack multiple hashes from a file (one per line).

    Lines may optionally include a forced hash type via ``hash:type`` syntax.
    """
    if not os.path.isfile(file_path):
        print(f"[!] Hash file not found: {file_path}")
        return []

    with open(file_path, encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]

    results: list[CrackResult] = []
    for line in lines:
        if ":" in line and not line.startswith("$"):
            # Allow hash:type syntax
            parts = line.rsplit(":", 1)
            target_hash, user_type = parts[0].strip(), parts[1].strip()
        else:
            target_hash, user_type = line, None

        if hash_type_override:
            hash_type = hash_type_override
        elif user_type and user_type in HASH_DB:
            hash_type = user_type
        else:
            from donhash.detector import detect_hash_type
            detected = detect_hash_type(target_hash)
            if not detected:
                results.append(CrackResult(
                    hash=target_hash, type="",
                    status="not_found",
                    error="Could not detect hash type",
                ))
                continue
            hash_type = detected[0][0]

        res = crack_single_hash(
            target_hash, hash_type, wordlist_path,
            verbose=verbose, ext_salt=salt, num_threads=num_threads,
        )
        results.append(res)

    return results
