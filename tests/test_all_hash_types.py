"""Smoke tests for every COMPUTE-implementation hash type — verifies each
returns a non-None value when called.

These tests don't validate against known vectors (that's test_engine.py);
they just verify that the implementation is wired up and doesn't crash.
"""

from __future__ import annotations

import hashlib

import pytest

from donhash._engine import compute_hash
from donhash._hash_db import COMPUTE, CRYPT, DETECT, HASH_DB, SALTED

# Hash types whose implementation depends on hashlib algorithms that may not
# be available in all OpenSSL builds (e.g., OpenSSL 3.0+ without legacy
# provider doesn't include RIPEMD, Whirlpool, Streebog).
_LEGACY_HASHLIB_TYPES = {
    "RIPEMD-128", "RIPEMD-256", "RIPEMD-320",
    "Whirlpool", "Whirlpool-T",
    "Streebog-256", "Streebog-512",
    "PBKDF2-HMAC-RIPEMD160",
    "HMAC-RIPEMD160(pass)", "HMAC-RIPEMD160(salt)",
    "HMAC-Streebog-256(pass)", "HMAC-Streebog-256(salt)",
    "HMAC-Streebog-512(pass)", "HMAC-Streebog-512(salt)",
}

# Hash types requiring optional third-party packages (pycryptodome for DES).
_REQUIRES_PYCRYPTODOME = {"LM"}


def _hashlib_supports(name: str) -> bool:
    try:
        hashlib.new(name, b"")
        return True
    except (ValueError, TypeError):
        return False


def _skip_if_unsupported(hash_type: str):
    """Return a pytest.skip if hash_type requires unavailable deps."""
    if hash_type in _REQUIRES_PYCRYPTODOME:
        try:
            import Crypto.Cipher.DES  # noqa: F401
        except ImportError:
            pytest.skip(f"{hash_type} requires pycryptodome")
    if hash_type in _LEGACY_HASHLIB_TYPES:
        algo_map = {
            "RIPEMD-128": "ripemd128", "RIPEMD-256": "ripemd256",
            "RIPEMD-320": "ripemd320",
            "Whirlpool": "whirlpool", "Whirlpool-T": "whirlpool",
            "Streebog-256": "streebog256", "Streebog-512": "streebog512",
            "PBKDF2-HMAC-RIPEMD160": "ripemd160",
            "HMAC-RIPEMD160(pass)": "ripemd160",
            "HMAC-RIPEMD160(salt)": "ripemd160",
            "HMAC-Streebog-256(pass)": "streebog256",
            "HMAC-Streebog-256(salt)": "streebog256",
            "HMAC-Streebog-512(pass)": "streebog512",
            "HMAC-Streebog-512(salt)": "streebog512",
        }
        algo = algo_map.get(hash_type, "")
        if algo and not _hashlib_supports(algo):
            pytest.skip(f"{hash_type} requires OpenSSL legacy provider ({algo})")


# All hash types whose compute_hash should return *something* for a normal
# input (no salt required).
PLAIN_COMPUTE_TYPES = sorted([
    name for name, spec in HASH_DB.items()
    if spec.impl == COMPUTE and not spec.name.startswith("OSX")
])

# Salted types — must accept a salt argument.
SALTED_COMPUTE_TYPES = sorted([
    name for name, spec in HASH_DB.items()
    if spec.impl == SALTED
])


@pytest.mark.parametrize("hash_type", PLAIN_COMPUTE_TYPES)
def test_plain_compute_returns_value(hash_type):
    """Every COMPUTE-impl type should return a non-None string for 'password'."""
    _skip_if_unsupported(hash_type)
    result = compute_hash("password", hash_type)
    assert result is not None, f"{hash_type} returned None — implementation broken"
    assert isinstance(result, str), f"{hash_type} returned {type(result)}, expected str"
    assert len(result) > 0, f"{hash_type} returned empty string"


@pytest.mark.parametrize("hash_type", SALTED_COMPUTE_TYPES)
def test_salted_compute_returns_value(hash_type):
    """Every SALTED-impl type should return a non-None string with salt='salt'."""
    _skip_if_unsupported(hash_type)
    if hash_type == "PostgreSQL-MD5":
        # Needs non-empty salt (username)
        result = compute_hash("password", hash_type, salt="postgres_user")
    else:
        result = compute_hash("password", hash_type, salt="salt")
    assert result is not None, f"{hash_type} returned None with salt='salt'"
    assert isinstance(result, str)


@pytest.mark.parametrize("hash_type", sorted([
    name for name, spec in HASH_DB.items() if spec.impl == DETECT
]))
def test_detect_only_returns_none(hash_type):
    """Every DETECT-impl type must return None — that's the contract."""
    result = compute_hash("password", hash_type)
    assert result is None, (
        f"{hash_type} returned {result!r} — should be None for DETECT-only types"
    )


@pytest.mark.parametrize("hash_type", sorted([
    name for name, spec in HASH_DB.items() if spec.impl == CRYPT
]))
def test_crypt_types_route_to_crypt_function(hash_type):
    """Every CRYPT-impl type returns None from compute_hash (use compute_crypt_hash)."""
    result = compute_hash("password", hash_type)
    assert result is None, (
        f"{hash_type} should return None from compute_hash (use compute_crypt_hash)"
    )


class TestDeterminism:
    """Hash functions must be deterministic — same input → same output."""

    @pytest.mark.parametrize("hash_type", PLAIN_COMPUTE_TYPES)
    def test_deterministic(self, hash_type):
        _skip_if_unsupported(hash_type)
        r1 = compute_hash("password", hash_type)
        r2 = compute_hash("password", hash_type)
        assert r1 == r2


class TestSaltSensitivity:
    """Salted hashes must change when the salt changes."""

    @pytest.mark.parametrize("hash_type", SALTED_COMPUTE_TYPES)
    def test_different_salt_different_hash(self, hash_type):
        _skip_if_unsupported(hash_type)
        # Use different salts; PostgreSQL-MD5 requires non-empty
        s1 = "user1" if hash_type == "PostgreSQL-MD5" else "salt1"
        s2 = "user2" if hash_type == "PostgreSQL-MD5" else "salt2"
        r1 = compute_hash("password", hash_type, salt=s1)
        r2 = compute_hash("password", hash_type, salt=s2)
        # They should be different (salt is part of the input)
        # Exception: HMAC-*-pass uses salt as message, HMAC-*-salt uses salt as key,
        # but PBKDF2-* with empty salt vs 'salt2' should also differ.
        assert r1 != r2, f"{hash_type} produced same output for different salts"


class TestInputSensitivity:
    """Hashes must change when input changes."""

    @pytest.mark.parametrize("hash_type", PLAIN_COMPUTE_TYPES[:30])  # sample first 30
    def test_different_input_different_hash(self, hash_type):
        _skip_if_unsupported(hash_type)
        r1 = compute_hash("password", hash_type)
        r2 = compute_hash("Password", hash_type)  # different case
        assert r1 != r2
