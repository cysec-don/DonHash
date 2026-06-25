"""Non-cryptographic hash implementations (CRC, FNV, DJB2, SDBM, etc.).

All functions take ``bytes`` input and return ``int`` (raw digest) so callers
can format them as hex / decimal / etc. as needed.
"""

from __future__ import annotations

from collections.abc import Callable


def _reflect_bits(val: int, width: int) -> int:
    """Reflect the lowest ``width`` bits of ``val``."""
    result = 0
    for i in range(width):
        result = (result << 1) | ((val >> i) & 1)
    return result


def crc16(
    data: bytes,
    poly: int = 0x8005,
    init: int = 0,
    xorout: int = 0,
    refin: bool = False,
    refout: bool = False,
) -> int:
    """Generic CRC-16 calculator."""
    crc = init
    for byte in data:
        b = _reflect_bits(byte, 8) if refin else byte
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    if refout:
        crc = _reflect_bits(crc, 16)
    return crc ^ xorout


def crc24(data: bytes, poly: int = 0x864CFB, init: int = 0xB704CE, xorout: int = 0) -> int:
    """CRC-24 (OpenPGP, RFC 4880)."""
    crc = init
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            if crc & 0x800000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFF
    return crc ^ xorout


def crc32_generic(
    data: bytes,
    poly: int,
    init: int = 0xFFFFFFFF,
    xorout: int = 0xFFFFFFFF,
    refin: bool = True,
    refout: bool = True,
) -> int:
    """Generic CRC-32 calculator.

    For ``refin=True`` (reflected input — the common case for CRC-32, CRC-32C,
    etc.) we use the LSB-first algorithm with the bit-reflected polynomial.
    For ``refin=False`` we use the MSB-first algorithm with the normal poly.
    """
    crc = init
    if refin:
        # Reflect the polynomial for LSB-first processing
        poly_r = _reflect_bits(poly, 32)
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly_r
                else:
                    crc >>= 1
        if not refout:
            crc = _reflect_bits(crc, 32)
    else:
        # MSB-first with normal polynomial
        for byte in data:
            crc ^= byte << 24
            for _ in range(8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ poly
                else:
                    crc <<= 1
                crc &= 0xFFFFFFFF
        if refout:
            crc = _reflect_bits(crc, 32)
    return crc ^ xorout


def crc64(
    data: bytes,
    poly: int,
    init: int = 0,
    xorout: int = 0,
    refin: bool = False,
    refout: bool = False,
) -> int:
    """Generic CRC-64 calculator."""
    crc = init
    for byte in data:
        b = _reflect_bits(byte, 8) if refin else byte
        crc ^= b << 56
        for _ in range(8):
            if crc & 0x8000000000000000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFFFFFFFFFFFF
    if refout:
        crc = _reflect_bits(crc, 64)
    return crc ^ xorout


def adler32(data: bytes) -> int:
    """zlib Adler-32 (RFC 1950).

    a starts at 1, b starts at 0; for each byte: a = (a + byte) mod 65521,
    b = (b + a) mod 65521; result = (b << 16) | a.
    """
    a, b = 1, 0
    MOD = 65521
    for byte in data:
        a = (a + byte) % MOD
        b = (b + a) % MOD
    return (b << 16) | a


# Backwards-compat alias used internally; prefer ``adler32`` (no underscore).
_adler32 = adler32


def fnv1_32(data: bytes) -> int:
    """FNV-1 32-bit."""
    h = 0x811C9DC5
    for b in data:
        h = ((h * 0x01000193) & 0xFFFFFFFF) ^ b
    return h


def fnv1a_32(data: bytes) -> int:
    """FNV-1a 32-bit."""
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def fnv1_64(data: bytes) -> int:
    """FNV-1 64-bit."""
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF) ^ b
    return h


def fnv1a_64(data: bytes) -> int:
    """FNV-1a 64-bit."""
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def djb2(data: bytes) -> int:
    """Bernstein DJB2."""
    h = 5381
    for b in data:
        h = (((h << 5) + h) + b) & 0xFFFFFFFF
    return h


def sdbm(data: bytes) -> int:
    """SDBM hash."""
    h = 0
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def jenkins_one_at_a_time(data: bytes) -> int:
    """Jenkins one-at-a-time hash."""
    h = 0
    for b in data:
        h = (h + b) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= h >> 6
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= h >> 11
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h


def elf_hash(data: bytes) -> int:
    """ELF-32 hash (Unix System V)."""
    h = 0
    for b in data:
        h = ((h << 4) + b) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def java_hash_code(data: bytes) -> int:
    """Java String.hashCode() — sum of c*31^(len-1-i)."""
    h = 0
    for b in data:
        h = ((h << 5) - h + b) & 0xFFFFFFFF
    # interpret as signed 32-bit
    if h & 0x80000000:
        h -= 0x100000000
    return h


# Map of name → function for hash types we expose directly
NON_CRYPTO_HASHES: dict[str, Callable[[bytes], int]] = {
    "fnv1_32": fnv1_32,
    "fnv1a_32": fnv1a_32,
    "fnv1_64": fnv1_64,
    "fnv1a_64": fnv1a_64,
    "djb2": djb2,
    "sdbm": sdbm,
    "jenkins_one_at_a_time": jenkins_one_at_a_time,
    "elf_hash": elf_hash,
    "java_hash_code": java_hash_code,
    "adler32": _adler32,
}
