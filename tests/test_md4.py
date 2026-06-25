"""Tests for the pure-Python MD4 implementation against RFC 1320 vectors."""

from __future__ import annotations

import pytest

from donhash._engine import _md4, _rotl, md4_hex

# All test vectors from RFC 1320 Appendix B.5
RFC1320_VECTORS = [
    ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
    ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
    ("message digest", "d9130a8164549fe818874806e1c7014b"),
    ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "043f8582f241db351ce627e153e7f0e4"),
    ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "e33b4ddc9c38f2199c3e7b164fcc0536"),
]


class TestMD4Vectors:
    @pytest.mark.parametrize("msg,expected", RFC1320_VECTORS)
    def test_md4_rfc_vectors(self, msg, expected):
        assert md4_hex(msg.encode()) == expected


class TestRotl:
    def test_rotl_basic(self):
        assert _rotl(0x12345678, 4) == 0x23456781
        assert _rotl(1, 1) == 2
        assert _rotl(0x80000000, 1) == 1  # wrap-around

    def test_rotl_full(self):
        assert _rotl(0xDEADBEEF, 32) == 0xDEADBEEF  # 32-bit rotation = identity


class TestMD4Properties:
    def test_md4_avalanche(self):
        """Changing one bit must produce a completely different hash."""
        h1 = md4_hex(b"password")
        h2 = md4_hex(b"passwore")  # last bit flipped
        assert h1 != h2
        # At most 1/4 of hex digits should match by chance
        matching = sum(a == b for a, b in zip(h1, h2, strict=True))
        assert matching < 10  # 32 hex chars, expect ~2 random matches

    def test_md4_deterministic(self):
        assert md4_hex(b"test") == md4_hex(b"test")

    def test_md4_length(self):
        assert len(md4_hex(b"")) == 32
        assert len(md4_hex(b"a" * 1000)) == 32

    def test_md4_returns_bytes(self):
        result = _md4(b"abc")
        assert isinstance(result, bytes)
        assert len(result) == 16


class TestMD4LongInput:
    def test_md4_long_input(self):
        """Test that MD4 handles inputs longer than one block (64 bytes)."""
        # 1000 'a' chars
        result = md4_hex(b"a" * 1000)
        assert len(result) == 32
        # All hex chars
        int(result, 16)  # raises if not valid hex

    def test_md4_block_boundary(self):
        """Test inputs at 64-byte block boundary."""
        # 55 bytes: fits in one block after padding (55 + 1 + 8 = 64)
        r1 = md4_hex(b"a" * 55)
        # 56 bytes: needs two blocks (56 + 1 + 7 = 64, but + 8 for length = 72 > 64)
        r2 = md4_hex(b"a" * 56)
        # 64 bytes: definitely needs two blocks
        r3 = md4_hex(b"a" * 64)
        assert len(r1) == 32
        assert len(r2) == 32
        assert len(r3) == 32
        assert r1 != r2 != r3
