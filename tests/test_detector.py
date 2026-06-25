"""Tests for the detection engine."""

from __future__ import annotations

import pytest

from donhash.detector import best_guess, detect_hash_type


class TestDetectCommonHashes:
    """Verify detection picks the correct most-likely type."""

    @pytest.mark.parametrize("hash_str,expected", [
        ("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
        ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA-1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256"),
        ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-512"),
    ])
    def test_top_guess_is_correct(self, hash_str, expected):
        detected = detect_hash_type(hash_str)
        assert detected, f"No candidates for {hash_str}"
        assert detected[0][0] == expected, (
            f"Expected {expected} as top guess, got {detected[0][0]}; "
            f"candidates: {[d[0] for d in detected[:5]]}"
        )


class TestDetectPrefixHashes:
    @pytest.mark.parametrize("hash_str,expected", [
        ("$1$abc123$XxxxXxxxXxxxXxxxXxxx1", "MD5(Crypt)"),
        ("$2a$10$N9qo8uLOickgx2ZMRZoMy.Mrq8Vq3ZMRZoMy.Mrq8Vq3ZMRZoMy", "bcrypt"),
        ("$6$rounds=5000$salt$XxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxx", "SHA-512(Crypt)"),
        ("$5$rounds=5000$salt$XxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxxXxxx", "SHA-256(Crypt)"),
        ("$P$XXXXXXXXXXXXXXXXXXXXXX", "WordPress-phpass"),
        ("$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$hash", "Argon2id"),
    ])
    def test_prefix_detection(self, hash_str, expected):
        detected = detect_hash_type(hash_str)
        names = [d[0] for d in detected]
        assert expected in names, f"Expected {expected} in candidates, got {names}"


class TestMySQLDetection:
    def test_mysql4_1_star_prefix(self):
        # MySQL4.1 starts with * and is 41 chars total
        h = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
        detected = detect_hash_type(h)
        assert detected[0][0] == "MySQL4.1"


class TestEmptyInput:
    def test_empty_returns_empty(self):
        assert detect_hash_type("") == []

    def test_whitespace_returns_empty(self):
        assert detect_hash_type("   ") == []

    def test_none_returns_empty(self):
        assert detect_hash_type(None) == []  # type: ignore[arg-type]


class TestNonHexInput:
    def test_random_garbage(self):
        assert detect_hash_type("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") == []

    def test_wrong_length_hex(self):
        # 30-char hex doesn't match any registered type
        assert detect_hash_type("a" * 30) == []


class TestBestGuess:
    def test_best_guess_md5(self):
        result = best_guess("5f4dcc3b5aa765d61d8327deb882cf99")
        assert result is not None
        assert result[0] == "MD5"

    def test_best_guess_none(self):
        assert best_guess("garbage") is None


class TestPriorityRanking:
    """Common types should rank before exotic ones."""

    def test_md5_before_double_md5(self):
        # 32-char hex matches MD5, Double-MD5, NTLM, NT, MD4, LM, MD2, etc.
        # MD5 should be #1 due to priority list
        detected = detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99")
        assert detected[0][0] == "MD5"

    def test_sha256_before_others(self):
        # 64-char hex matches SHA-256, SHA3-256, BLAKE2s, RIPEMD-256, etc.
        detected = detect_hash_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert detected[0][0] == "SHA-256"
