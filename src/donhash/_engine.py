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

"""Hash computation engine.

This module exposes :func:`compute_hash` (for plain hashes) and
:func:`compute_crypt_hash` (for hashes that require the full original hash
for salt/parameter extraction, e.g. bcrypt, MD5-crypt, SSHA).

The design goal is correctness: implementations match reference vectors from
RFCs, Hashcat example-hashes, and known test suites. Types without a working
implementation are explicitly marked ``impl='detect'`` in the registry and
return ``None`` here so callers can show a clear "detection-only" message
instead of silently producing wrong results.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re

from donhash._hash_db import CRYPT, DETECT, HASH_DB
from donhash._noncrypto import (
    _adler32,
    crc16,
    crc24,
    crc32_generic,
    crc64,
    djb2,
    elf_hash,
    fnv1_32,
    fnv1_64,
    fnv1a_32,
    fnv1a_64,
    java_hash_code,
    jenkins_one_at_a_time,
    sdbm,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _try_hashlib(name: str, data: bytes) -> str | None:
    """Try hashlib.new(name, data) — returns hex digest or None on failure."""
    try:
        return hashlib.new(name, data).hexdigest()
    except (ValueError, TypeError):
        return None


def _format(n: int, width: int) -> str:
    return format(n, f"0{width}x")


# ─── Pure-Python MD4 (RFC 1320) ──────────────────────────────────────────────
# OpenSSL 3.0+ ships MD4 in the legacy provider, which is often unavailable,
# so we provide a pure-Python implementation for NTLM/NT cracking.

# Per-round shift amounts
_S1 = [3, 7, 11, 19] * 4   # Round 1
_S2 = [3, 5, 9, 13] * 4    # Round 2
_S3 = [3, 9, 11, 15] * 4   # Round 3

# Message word indices for rounds 2 and 3
_K2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
_K3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _md4(msg: bytes) -> bytes:
    """Pure-Python MD4 implementation (RFC 1320)."""
    # Pre-processing: pad with 0x80 then zeros, then 64-bit little-endian length
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += ml.to_bytes(8, "little")

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]
        X = [int.from_bytes(chunk[i:i+4], "little") for i in range(0, 64, 4)]
        A, B, C, D = a0, b0, c0, d0

        # Round 1: F(B,C,D) = (B & C) | (~B & D)
        for i in range(16):
            T = (A + ((B & C) | (~B & D & 0xFFFFFFFF)) + X[i]) & 0xFFFFFFFF
            T = _rotl(T, _S1[i])
            A, D, C, B = D, C, B, T

        # Round 2: G(B,C,D) = (B & C) | (B & D) | (C & D)
        for i in range(16):
            G = (B & C) | (B & D) | (C & D)
            T = (A + G + X[_K2[i]] + 0x5A827999) & 0xFFFFFFFF
            T = _rotl(T, _S2[i])
            A, D, C, B = D, C, B, T

        # Round 3: H(B,C,D) = B ^ C ^ D
        for i in range(16):
            H = B ^ C ^ D
            T = (A + H + X[_K3[i]] + 0x6ED9EBA1) & 0xFFFFFFFF
            T = _rotl(T, _S3[i])
            A, D, C, B = D, C, B, T

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    return (a0.to_bytes(4, "little") + b0.to_bytes(4, "little") +
            c0.to_bytes(4, "little") + d0.to_bytes(4, "little"))


def md4_hex(msg: bytes) -> str:
    """MD4 hex digest (pure Python)."""
    return _md4(msg).hex()


# ─── Pure-Python MD2 (RFC 1319) ──────────────────────────────────────────────
# MD2 is deprecated (RFC 6149) and the PI table commonly seen in source code
# contains transcription errors from the original RFC. We mark MD2 as
# detection-only in the registry and do not ship a compute implementation.
# Use hashlib.new("md2", ...) on builds where OpenSSL legacy provider exposes
# it, or use a verified third-party implementation if you need MD2 cracking.


def md2_hex(msg: bytes) -> str:
    """MD2 hex digest — tries hashlib, falls back to None (deprecation notice)."""
    return _try_hashlib("md2", msg) or ""


# ─── Pure-Python LM hash (LANMAN) ────────────────────────────────────────────

def _expand_to_des_key(k7: bytes) -> bytes:
    """Expand 7 bytes to 8 bytes by inserting a parity bit after every 7 bits."""
    if len(k7) != 7:
        raise ValueError("Need exactly 7 bytes")
    bits: list[int] = []
    for byte in k7:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    out = bytearray(8)
    for i in range(8):
        val = 0
        for j in range(7):
            val = (val << 1) | bits[i * 7 + j]
        parity = bin(val).count("1") & 1
        out[i] = (val << 1) | (1 - parity)
    return bytes(out)


def _lm_hash(password: str) -> str:
    """LANMAN (LM) hash — DES-based, used in old Windows authentication.

    Requires ``pycryptodome`` (``pip install pycryptodome``) for DES support.
    Returns empty string if pycryptodome is unavailable.
    """
    try:
        from Crypto.Cipher import DES as _DES
    except ImportError:
        return ""

    pwd = password.upper().encode("latin-1", errors="replace")[:14]
    pwd = pwd.ljust(14, b"\x00")

    k1 = _expand_to_des_key(pwd[:7])
    k2 = _expand_to_des_key(pwd[7:14])

    constant = b"KGS!@#$%"
    c1 = _DES.new(k1, _DES.MODE_ECB).encrypt(constant)
    c2 = _DES.new(k2, _DES.MODE_ECB).encrypt(constant)
    return (c1 + c2).hex()


# ─── Main compute_hash ───────────────────────────────────────────────────────

def compute_hash(word: str, hash_type: str, salt: str = "") -> str | None:
    """Compute a hash for the given word.

    Returns hex string (or Base64 for some types) or ``None`` if the type is
    detection-only or unsupported by this build of Python.
    """
    spec = HASH_DB.get(hash_type)
    if spec is None:
        return None
    if spec.impl == DETECT:
        return None
    if spec.impl == CRYPT:
        return None  # caller must use compute_crypt_hash

    enc = word.encode("utf-8", errors="replace")
    enc16 = word.encode("utf-16le")
    salt_b = salt.encode("utf-8", errors="replace") if salt else b""

    ht = hash_type

    # ── CRC Family ──
    if ht == "CRC-16":
        return _format(crc16(enc, 0x8005), 4)
    if ht == "CRC-16-CCITT":
        return _format(crc16(enc, 0x1021, init=0xFFFF), 4)
    if ht == "CRC-16-IBM":
        return _format(crc16(enc, 0x8005, init=0, refin=True, refout=True), 4)
    if ht == "CRC-16-DNP":
        return _format(crc16(enc, 0x3D65, init=0, refin=True, refout=True, xorout=0xFFFF), 4)
    if ht == "CRC-16-Modbus":
        return _format(crc16(enc, 0x8005, init=0xFFFF, refin=True, refout=True), 4)
    if ht == "CRC-16-XMODEM":
        return _format(crc16(enc, 0x1021), 4)
    if ht == "CRC-16-USB":
        return _format(crc16(enc, 0x8005, init=0xFFFF, refin=True, refout=True, xorout=0xFFFF), 4)
    if ht == "CRC-24":
        return _format(crc24(enc), 6)
    if ht == "CRC-32":
        return _format(binascii.crc32(enc) & 0xFFFFFFFF, 8)
    if ht == "CRC-32B":
        # CRC-32/BZIP2 — same poly as zlib CRC-32 but MSB-first, no reflection,
        # init=0xFFFFFFFF, xorout=0xFFFFFFFF. Standard check value for
        # "123456789" is 0xfc891918.
        return _format(
            crc32_generic(enc, 0x04C11DB7, init=0xFFFFFFFF, xorout=0xFFFFFFFF,
                          refin=False, refout=False),
            8,
        )
    if ht == "CRC-32C":
        return _format(crc32_generic(enc, 0x1EDC6F41), 8)
    if ht == "CRC-32-MPEG-2":
        return _format(crc32_generic(enc, 0x04C11DB7, refin=False, refout=False, xorout=0), 8)
    if ht == "CRC-32D":
        return _format(crc32_generic(enc, 0xA833982B), 8)
    if ht == "CRC-32Q":
        # CRC-32Q (AVI / AIXM): poly=0x814141AB, init=0, refin=False, refout=False,
        # xorout=0. Standard check value for "123456789" is 0x3010bf7f.
        return _format(
            crc32_generic(enc, 0x814141AB, init=0, xorout=0,
                          refin=False, refout=False),
            8,
        )
    if ht == "CRC-64":
        return _format(crc64(enc, 0x42F0E1EBA9EA3693), 16)
    if ht == "CRC-64-ISO":
        return _format(crc64(enc, 0x000000000000001B), 16)
    if ht == "CRC-64-Jones":
        return _format(crc64(enc, 0xAD93D23594C935A9, refin=True, refout=True), 16)
    if ht == "Adler-32":
        return _format(_adler32(enc), 8)

    # ── Non-Cryptographic ──
    if ht in ("FNV-1-32", "FNV-132"):
        return _format(fnv1_32(enc), 8)
    if ht in ("FNV-1a-32",):
        return _format(fnv1a_32(enc), 8)
    if ht in ("FNV-1-64", "FNV-164"):
        return _format(fnv1_64(enc), 16)
    if ht == "FNV-1a-64":
        return _format(fnv1a_64(enc), 16)
    if ht == "DJB2":
        return _format(djb2(enc), 8)
    if ht == "SDBM":
        return _format(sdbm(enc), 8)
    if ht in ("Jenkins", "Joaat"):
        return _format(jenkins_one_at_a_time(enc), 8)
    if ht == "ELF-32":
        return _format(elf_hash(enc), 8)
    if ht == "JavaHashCode":
        return _format(java_hash_code(enc) & 0xFFFFFFFF, 8)

    # ── MD Family ──
    if ht == "MD2":
        # Detection-only — see registry note
        return None
    if ht == "MD4":
        return md4_hex(enc)
    if ht == "MD5":
        return hashlib.md5(enc).hexdigest()
    if ht == "Half-MD5":
        return hashlib.md5(enc).hexdigest()[:16]
    if ht == "Double-MD5":
        return hashlib.md5(hashlib.md5(enc).hexdigest().encode()).hexdigest()
    if ht == "Triple-MD5":
        h = hashlib.md5(enc).hexdigest().encode()
        h = hashlib.md5(h).hexdigest().encode()
        return hashlib.md5(h).hexdigest()
    if ht == "md5(md5(md5($pass)))":
        h = hashlib.md5(enc).hexdigest().encode()
        h = hashlib.md5(h).hexdigest().encode()
        return hashlib.md5(h).hexdigest()
    if ht == "md5(sha1($pass))":
        return hashlib.md5(hashlib.sha1(enc).hexdigest().encode()).hexdigest()
    if ht == "md5(sha1(md5($pass)))":
        return hashlib.md5(
            hashlib.sha1(hashlib.md5(enc).hexdigest().encode()).hexdigest().encode()
        ).hexdigest()
    if ht == "md5(strtoupper(md5))":
        return hashlib.md5(hashlib.md5(enc).hexdigest().upper().encode()).hexdigest()

    # ── SHA Family ──
    if ht == "SHA-1":
        return hashlib.sha1(enc).hexdigest()
    if ht == "Double-SHA1":
        return hashlib.sha1(hashlib.sha1(enc).hexdigest().encode()).hexdigest()
    if ht == "Triple-SHA1":
        h = hashlib.sha1(enc).hexdigest().encode()
        h = hashlib.sha1(h).hexdigest().encode()
        return hashlib.sha1(h).hexdigest()
    if ht == "sha1(sha1(sha1($pass)))":
        h = hashlib.sha1(enc).hexdigest().encode()
        h = hashlib.sha1(h).hexdigest().encode()
        return hashlib.sha1(h).hexdigest()
    if ht == "sha1(md5($pass))":
        return hashlib.sha1(hashlib.md5(enc).hexdigest().encode()).hexdigest()
    if ht == "SHA1-Base64":
        return base64.b64encode(hashlib.sha1(enc).digest()).decode("ascii")
    if ht == "LinkedIn":
        return hashlib.sha1(enc).hexdigest()  # unsalted SHA-1, alias

    # ── SHA-2 Family ──
    if ht == "SHA-224":
        return hashlib.sha224(enc).hexdigest()
    if ht == "SHA-256":
        return hashlib.sha256(enc).hexdigest()
    if ht == "SHA-384":
        return hashlib.sha384(enc).hexdigest()
    if ht == "SHA-512":
        return hashlib.sha512(enc).hexdigest()
    if ht == "SHA-512/224":
        # hashlib.new("sha512_224", ...) works on Python 3.6+
        try:
            return hashlib.new("sha512_224", enc).hexdigest()
        except (ValueError, TypeError):
            return None
    if ht == "SHA-512/256":
        try:
            return hashlib.new("sha512_256", enc).hexdigest()
        except (ValueError, TypeError):
            return None

    # ── SHA-3 / Keccak ──
    if ht == "SHA3-224":
        return hashlib.sha3_224(enc).hexdigest()
    if ht == "SHA3-256":
        return hashlib.sha3_256(enc).hexdigest()
    if ht == "SHA3-384":
        return hashlib.sha3_384(enc).hexdigest()
    if ht == "SHA3-512":
        return hashlib.sha3_512(enc).hexdigest()
    if ht == "SHAKE128":
        return hashlib.shake_128(enc).hexdigest(32)
    if ht == "SHAKE256":
        return hashlib.shake_256(enc).hexdigest(64)

    # ── BLAKE Family ──
    if ht == "BLAKE2b":
        return hashlib.blake2b(enc).hexdigest()
    if ht == "BLAKE2b-256":
        return hashlib.blake2b(enc, digest_size=32).hexdigest()
    if ht in ("BLAKE2b-512",):
        return hashlib.blake2b(enc, digest_size=64).hexdigest()
    if ht == "BLAKE2s":
        return hashlib.blake2s(enc).hexdigest()
    if ht == "BLAKE2s-128":
        return hashlib.blake2s(enc, digest_size=16).hexdigest()
    if ht == "BLAKE2s-256":
        return hashlib.blake2s(enc, digest_size=32).hexdigest()

    # ── RIPEMD ── (hashlib supports ripemd160 in legacy provider; may fail)
    if ht == "RIPEMD-128":
        return _try_hashlib("ripemd128", enc)
    if ht == "RIPEMD-160":
        return _try_hashlib("ripemd160", enc)
    if ht == "RIPEMD-256":
        return _try_hashlib("ripemd256", enc)
    if ht == "RIPEMD-320":
        return _try_hashlib("ripemd320", enc)

    # ── Whirlpool / GOST Streebog ──
    if ht == "Whirlpool":
        return _try_hashlib("whirlpool", enc)
    if ht == "Whirlpool-T":
        return _try_hashlib("whirlpool", enc)
    if ht == "Streebog-256":
        return _try_hashlib("streebog256", enc)
    if ht == "Streebog-512":
        return _try_hashlib("streebog512", enc)

    # ── Windows Auth ──
    if ht in ("NTLM", "NT"):
        # NTLM = MD4(UTF-16LE(password))
        return md4_hex(enc16)
    if ht == "LM":
        return _lm_hash(word) or None

    # ── Database ──
    if ht == "MySQL323":
        nr = 1345345333
        add = 7
        nr2 = 0x12345671
        # Iterate over UTF-8 bytes (matching MySQL's C implementation), not
        # over Python str codepoints — important for non-ASCII passwords.
        for c in enc:
            if c in (0x20, 0x09):  # space, tab
                continue
            tmp = c
            nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
            nr2 = (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
            add = (add + tmp) & 0xFFFFFFFF
        nr &= 0x7FFFFFFF
        nr2 &= 0x7FFFFFFF
        return format(nr, "08x") + format(nr2, "08x")
    if ht in ("MySQL4.1", "MySQL5.x"):
        s1 = hashlib.sha1(enc).digest()
        s2 = hashlib.sha1(s1).hexdigest().upper()
        return ("*" + s2) if ht == "MySQL4.1" else s2

    if ht == "Joomla-MD5" or ht == "Drupal-5-6":
        return hashlib.md5(enc).hexdigest()

    if ht == "OSX-10.4":
        # 8-byte hex salt + SHA1 digest, salt extracted from the original hash
        # (first 16 hex chars = 8-byte salt). Without salt, we cannot compute.
        if not salt:
            return None
        try:
            salt_bytes = bytes.fromhex(salt)
        except (ValueError, TypeError):
            return None
        return salt + hashlib.sha1(salt_bytes + enc).hexdigest()

    # ── HMAC variants ──
    if ht == "HMAC-MD5(pass)":
        return hmac.new(enc, salt_b, "md5").hexdigest()
    if ht == "HMAC-SHA1(pass)":
        return hmac.new(enc, salt_b, "sha1").hexdigest()
    if ht == "HMAC-SHA256(pass)":
        return hmac.new(enc, salt_b, "sha256").hexdigest()
    if ht == "HMAC-SHA512(pass)":
        return hmac.new(enc, salt_b, "sha512").hexdigest()
    if ht == "HMAC-MD5(salt)":
        return hmac.new(salt_b, enc, "md5").hexdigest()
    if ht == "HMAC-SHA1(salt)":
        return hmac.new(salt_b, enc, "sha1").hexdigest()
    if ht == "HMAC-SHA256(salt)":
        return hmac.new(salt_b, enc, "sha256").hexdigest()
    if ht == "HMAC-SHA512(salt)":
        return hmac.new(salt_b, enc, "sha512").hexdigest()
    if ht == "HMAC-RIPEMD160(pass)":
        # Treat the password as the HMAC key and the salt as the message
        # (consistent with the other HMAC-*-pass variants).
        try:
            return hmac.new(enc, salt_b, "ripemd160").hexdigest()
        except (ValueError, TypeError):
            return None
    if ht == "HMAC-RIPEMD160(salt)":
        try:
            return hmac.new(salt_b, enc, "ripemd160").hexdigest()
        except (ValueError, TypeError):
            return None
    if ht == "HMAC-SHA3-256":
        return hmac.new(salt_b, enc, "sha3_256").hexdigest()
    if ht == "HMAC-Streebog-256(pass)":
        try:
            return hmac.new(enc, salt_b, "streebog256").hexdigest()
        except (ValueError, TypeError):
            return None
    if ht == "HMAC-Streebog-256(salt)":
        try:
            return hmac.new(salt_b, enc, "streebog256").hexdigest()
        except (ValueError, TypeError):
            return None
    if ht == "HMAC-Streebog-512(pass)":
        try:
            return hmac.new(enc, salt_b, "streebog512").hexdigest()
        except (ValueError, TypeError):
            return None
    if ht == "HMAC-Streebog-512(salt)":
        try:
            return hmac.new(salt_b, enc, "streebog512").hexdigest()
        except (ValueError, TypeError):
            return None

    # ── Salted MD5 ──
    if ht == "md5(pass.salt)":
        return hashlib.md5(enc + salt_b).hexdigest()
    if ht == "md5(salt.pass)":
        return hashlib.md5(salt_b + enc).hexdigest()
    if ht == "md5(unicode(pass).salt)":
        return hashlib.md5(enc16 + salt_b).hexdigest()
    if ht == "md5(salt.unicode(pass))":
        return hashlib.md5(salt_b + enc16).hexdigest()
    if ht == "md5(salt.pass.$salt)":
        return hashlib.md5(salt_b + enc + salt_b).hexdigest()
    if ht == "md5(md5(pass).md5(salt))":
        return hashlib.md5(
            hashlib.md5(enc).hexdigest().encode() + hashlib.md5(salt_b).hexdigest().encode()
        ).hexdigest()
    if ht == "md5(md5(salt).pass)":
        return hashlib.md5(hashlib.md5(salt_b).hexdigest().encode() + enc).hexdigest()
    if ht == "md5(salt.md5(pass))":
        return hashlib.md5(salt_b + hashlib.md5(enc).hexdigest().encode()).hexdigest()
    if ht == "md5(pass.md5(salt))":
        return hashlib.md5(enc + hashlib.md5(salt_b).hexdigest().encode()).hexdigest()
    if ht == "md5(salt.md5(salt.$pass))":
        return hashlib.md5(salt_b + hashlib.md5(salt_b + enc).hexdigest().encode()).hexdigest()
    if ht == "md5(salt.md5(pass.$salt))":
        return hashlib.md5(salt_b + hashlib.md5(enc + salt_b).hexdigest().encode()).hexdigest()
    if ht == "md5(username.0.pass)":
        return hashlib.md5(salt_b + b"\x00" + enc).hexdigest()

    # ── Salted SHA-1 ──
    if ht == "sha1(pass.salt)":
        return hashlib.sha1(enc + salt_b).hexdigest()
    if ht == "sha1(salt.pass)":
        return hashlib.sha1(salt_b + enc).hexdigest()
    if ht == "sha1(unicode(pass).salt)":
        return hashlib.sha1(enc16 + salt_b).hexdigest()
    if ht == "sha1(salt.unicode(pass))":
        return hashlib.sha1(salt_b + enc16).hexdigest()
    if ht == "sha1(salt.pass.$salt)":
        return hashlib.sha1(salt_b + enc + salt_b).hexdigest()
    if ht == "sha1(sha1(salt.pass.$salt))":
        return hashlib.sha1(
            hashlib.sha1(salt_b + enc + salt_b).hexdigest().encode()
        ).hexdigest()
    if ht == "sha1(sha1(pass).salt)":
        return hashlib.sha1(hashlib.sha1(enc).hexdigest().encode() + salt_b).hexdigest()

    # ── Salted SHA-2 ──
    if ht == "sha256(pass.salt)":
        return hashlib.sha256(enc + salt_b).hexdigest()
    if ht == "sha256(salt.pass)":
        return hashlib.sha256(salt_b + enc).hexdigest()
    if ht == "sha512(pass.salt)":
        return hashlib.sha512(enc + salt_b).hexdigest()
    if ht == "sha512(salt.pass)":
        return hashlib.sha512(salt_b + enc).hexdigest()
    if ht == "sha256(unicode(pass).salt)":
        return hashlib.sha256(enc16 + salt_b).hexdigest()
    if ht == "sha512(unicode(pass).salt)":
        return hashlib.sha512(enc16 + salt_b).hexdigest()
    if ht == "sha256(salt.unicode(pass))":
        return hashlib.sha256(salt_b + enc16).hexdigest()
    if ht in ("sha256(salt.unicode)-2",):
        return hashlib.sha256(salt_b + enc16).hexdigest()
    if ht in ("sha512(salt.unicode)-2",):
        return hashlib.sha512(salt_b + enc16).hexdigest()

    # ── PBKDF2 (variable iterations — caller must supply via salt format) ──
    if ht == "PBKDF2-HMAC-MD5":
        return hashlib.pbkdf2_hmac("md5", enc, salt_b or b"salt", 100000).hex()
    if ht == "PBKDF2-HMAC-SHA1":
        return hashlib.pbkdf2_hmac("sha1", enc, salt_b or b"salt", 100000).hex()
    if ht == "PBKDF2-HMAC-SHA256":
        return hashlib.pbkdf2_hmac("sha256", enc, salt_b or b"salt", 100000).hex()
    if ht == "PBKDF2-HMAC-SHA512":
        return hashlib.pbkdf2_hmac("sha512", enc, salt_b or b"salt", 100000).hex()
    if ht == "PBKDF2-HMAC-RIPEMD160":
        try:
            return hashlib.pbkdf2_hmac("ripemd160", enc, salt_b or b"salt", 100000).hex()
        except (ValueError, TypeError):
            return None

    # ── PostgreSQL MD5 — md5 + MD5(pass + salt) ──
    # Note: a duplicate block previously lived in compute_crypt_hash but was
    # unreachable because PostgreSQL-MD5 has impl=SALTED, not CRYPT.
    if ht == "PostgreSQL-MD5":
        if not salt:
            return None  # username is required as salt
        return "md5" + hashlib.md5(enc + salt_b).hexdigest()

    return None


# ─── Crypt-style hashes (need original hash for salt/params) ─────────────────

def compute_crypt_hash(
    word: str, original_hash: str, hash_type: str, salt: str = ""
) -> str | None:
    """Compute a crypt-style hash.

    These hashes embed their salt/parameters in the original hash string, so
    we need it to extract them. We use Python's :mod:`hashlib` PBKDF2,
    :mod:`bcrypt`/`argon2` if installed, or fall back to OS crypt() via
    :mod:`crypt` (when available — Python <3.13 only).
    """
    spec = HASH_DB.get(hash_type)
    if spec is None or spec.impl != CRYPT:
        return None

    enc = word.encode("utf-8", errors="replace")
    ht = hash_type
    h = original_hash.strip()

    # ── bcrypt family ──
    if ht.startswith("bcrypt") or ht in {"Unix-Blowfish", "Rails-Devise", "passlib-bcrypt"}:
        try:
            import bcrypt as _bcrypt
        except ImportError:
            return None
        try:
            return _bcrypt.hashpw(enc, h.encode()).decode()
        except (ValueError, TypeError):
            return None

    # ── Argon2 family ──
    if ht.startswith("Argon2"):
        try:
            from argon2 import Type
            from argon2.low_level import verify_secret
        except ImportError:
            return None
        try:
            ok = verify_secret(h.encode(), enc, Type.I if ht == "Argon2i" else
                                 (Type.D if ht == "Argon2d" else Type.ID))
            return h if ok else None
        except Exception:
            return None

    # ── passlib-style hashes ──
    if ht.startswith("passlib-pbkdf2") or ht in {"PHPass", "WordPress-phpass",
                                                  "WordPress-2.6.2+", "WordPress-2.6.0",
                                                  "phpBB3", "passlib-scrypt"}:
        try:
            import passlib.hash
        except ImportError:
            return None
        try:
            if ht.startswith("passlib-pbkdf2"):
                scheme = ht.replace("passlib-", "").replace("-", "_")
                if hasattr(passlib.hash, scheme):
                    return getattr(passlib.hash, scheme).hash(word, salt=salt or None)
                return None
            if ht == "passlib-scrypt":
                if hasattr(passlib.hash, "scrypt"):
                    return passlib.hash.scrypt.hash(word, salt=salt or None)
                return None
            # PHPass — use verify against the original hash so we don't
            # auto-generate a random salt and never match.
            if passlib.hash.phpass.identify(h):
                ok = passlib.hash.phpass.verify(word, h)
                return h if ok else None
            return None
        except Exception:
            return None

    # ── Django ──
    if ht.startswith("Django("):
        parts = h.split("$")
        if len(parts) < 2:
            return None
        if ht in {"Django(MD5)", "Django(SHA-1)", "Django(SHA-256)"}:
            if len(parts) != 3:
                return None
            s = parts[1]
            algo = {"Django(MD5)": "md5", "Django(SHA-1)": "sha1",
                    "Django(SHA-256)": "sha256"}[ht]
            return f"{algo}${s}${hashlib.new(algo, f'{s}{word}'.encode()).hexdigest()}"
        if ht == "Django(PBKDF2-SHA256)":
            # Format: pbkdf2_sha256$<iters>$<salt>$<hash_b64>
            if len(parts) != 4:
                return None
            iters = int(parts[1])
            s = parts[2]
            dk = hashlib.pbkdf2_hmac("sha256", enc, s.encode(), iters)
            return f"pbkdf2_sha256${iters}${s}${base64.b64encode(dk).decode()}"
        if ht == "Django(PBKDF2-SHA1)":
            if len(parts) != 4:
                return None
            iters = int(parts[1])
            s = parts[2]
            dk = hashlib.pbkdf2_hmac("sha1", enc, s.encode(), iters)
            return f"pbkdf2_sha1${iters}${s}${base64.b64encode(dk).decode()}"
        if ht == "Django(bcrypt)":
            # Format: bcrypt$<hash> (note the double $ — split("$") yields
            # ["bcrypt", "", "2b", ...] so we use split("$", 1)[1]).
            try:
                import bcrypt as _bcrypt
                rest = h.split("$", 1)[1] if "$" in h else h
                return f"bcrypt${_bcrypt.hashpw(enc, rest.encode()).decode()}"
            except (ImportError, ValueError, TypeError):
                return None
        if ht == "Django(bcrypt-SHA256)":
            # Format: bcrypt_sha256$$<bcrypt hash> — pre-hash with SHA256(base64)
            try:
                import bcrypt as _bcrypt
                pre = base64.b64encode(hashlib.sha256(enc).digest()).decode()
                rest = h.split("$$", 1)[1] if "$$" in h else parts[1]
                return f"bcrypt_sha256$${_bcrypt.hashpw(pre.encode(), rest.encode()).decode()}"
            except (ImportError, ValueError, TypeError):
                return None

    # ── MD5/SHA-crypt — use crypt.crypt if available, else passlib ──
    if ht in {"MD5(Crypt)", "Unix-MD5", "FreeBSD-MD5", "MD5-Crypt-Cisco",
              "MD5(APR)", "Cisco-IOS-MD5", "SHA-256(Crypt)", "Unix-SHA256",
              "SHA-512(Crypt)", "Unix-SHA512", "AIX-smd5"}:
        try:
            import passlib.hash as _ph
            if ht in {"MD5(Crypt)", "Unix-MD5", "FreeBSD-MD5", "MD5-Crypt-Cisco", "AIX-smd5"}:
                # Extract salt from $1$salt$hash or use provided
                m = re.match(r"^\$1\$([^\$]+)\$", h) or re.match(r"^\{smd5\}([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _ph.md5_crypt.hash(word, salt=s)
            if ht == "MD5(APR)":
                m = re.match(r"^\$apr1\$([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _ph.apr_md5_crypt.hash(word, salt=s)
            if ht in {"SHA-256(Crypt)", "Unix-SHA256"}:
                m = re.match(r"^\$5\$([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _ph.sha256_crypt.hash(word, salt=s)
            if ht in {"SHA-512(Crypt)", "Unix-SHA512"}:
                m = re.match(r"^\$6\$([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _ph.sha512_crypt.hash(word, salt=s)
        except ImportError:
            pass
        # Fall back to crypt module (deprecated in 3.13, removed later)
        try:
            import crypt as _crypt
            if ht == "MD5(APR)":
                m = re.match(r"^\$apr1\$([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _crypt.crypt(word, f"$apr1${s}")
            if ht in {"SHA-256(Crypt)", "Unix-SHA256"}:
                m = re.match(r"^\$5\$([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _crypt.crypt(word, f"$5${s}")
            if ht in {"SHA-512(Crypt)", "Unix-SHA512"}:
                m = re.match(r"^\$6\$([^\$]+)\$", h)
                s = salt or (m.group(1) if m else "")
                return _crypt.crypt(word, f"$6${s}")
            m = re.match(r"^\$1\$([^\$]+)\$", h)
            s = salt or (m.group(1) if m else "")
            return _crypt.crypt(word, f"$1${s}")
        except ImportError:
            return None

    # ── SSHA / LDAP SHA ──
    if ht in {"Netscape-LDAP-SSHA", "OpenLDAP-SSHA", "SSHA1-Base64"}:
        try:
            b64 = h.split("}", 1)[-1] if "}" in h else h
            decoded = base64.b64decode(b64)
            salt_bytes = decoded[20:]
            digest = hashlib.sha1(enc + salt_bytes).digest()
            return "{SSHA}" + base64.b64encode(digest + salt_bytes).decode()
        except Exception:
            return None
    if ht == "Netscape-LDAP-SHA-2":
        try:
            digest = hashlib.sha1(enc).digest()
            return "{SHA}" + base64.b64encode(digest).decode()
        except Exception:
            return None
    if ht == "OpenLDAP-SSHA256":
        try:
            b64 = h.split("}", 1)[-1]
            decoded = base64.b64decode(b64)
            salt_bytes = decoded[32:]
            digest = hashlib.sha256(enc + salt_bytes).digest()
            return "{SSHA256}" + base64.b64encode(digest + salt_bytes).decode()
        except Exception:
            return None
    if ht in {"OpenLDAP-SSHA512", "SSHA512-Base64", "LDAP-SSHA512"}:
        try:
            b64 = h.split("}", 1)[-1]
            decoded = base64.b64decode(b64)
            salt_bytes = decoded[64:]
            digest = hashlib.sha512(enc + salt_bytes).digest()
            return "{SSHA512}" + base64.b64encode(digest + salt_bytes).decode()
        except Exception:
            return None

    return None


def extract_salt(hash_str: str, hash_type: str) -> str:
    """Extract salt from a hash string based on its type, if possible."""
    h = hash_str.strip()

    if hash_type.startswith("Django("):
        parts = h.split("$")
        return parts[1] if len(parts) >= 2 else ""

    if hash_type in {"MD5(Crypt)", "Unix-MD5", "FreeBSD-MD5", "MD5-Crypt-Cisco",
                     "MD5(APR)", "SHA-256(Crypt)", "Unix-SHA256",
                     "SHA-512(Crypt)", "Unix-SHA512", "Cisco-IOS-MD5"}:
        parts = h.split("$")
        return parts[2] if len(parts) >= 3 else ""

    if hash_type in {"Netscape-LDAP-SSHA", "OpenLDAP-SSHA", "SSHA1-Base64",
                     "OpenLDAP-SSHA256", "OpenLDAP-SSHA512",
                     "SSHA512-Base64", "LDAP-SSHA512"}:
        try:
            b64 = h.split("}", 1)[-1] if "}" in h else h
            decoded = base64.b64decode(b64)
            # salt is everything after the digest
            digest_lens = {"SSHA": 20, "SSHA256": 32, "SSHA512": 64}
            key = "SSHA512" if "512" in hash_type else ("SSHA256" if "256" in hash_type else "SSHA")
            dl = digest_lens[key]
            return decoded[dl:].hex()
        except Exception:
            return ""

    return ""
