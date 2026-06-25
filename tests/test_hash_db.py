"""Tests for the hash database (registry, lookups, no duplicates)."""

from __future__ import annotations

from donhash._hash_db import (
    CATEGORY_NAMES,
    COMPUTE,
    CRYPT,
    DETECT,
    HASH_DB,
    LENGTH_MAP,
    PREFIX_MAP,
    SALTED,
    category_counts,
    get,
    implementation_stats,
)


class TestRegistryIntegrity:
    """The registry must be self-consistent."""

    def test_total_count(self):
        """Verify we still have 491 registered types."""
        assert len(HASH_DB) == 491

    def test_all_categories_present(self):
        assert len(CATEGORY_NAMES) == 30
        for i in range(1, 31):
            assert i in CATEGORY_NAMES

    def test_every_entry_has_valid_category(self):
        for name, spec in HASH_DB.items():
            assert 1 <= spec.cat <= 30, f"{name} has bad cat={spec.cat}"

    def test_every_entry_has_valid_impl(self):
        valid = {COMPUTE, CRYPT, SALTED, DETECT}
        for name, spec in HASH_DB.items():
            assert spec.impl in valid, f"{name} has bad impl={spec.impl}"

    def test_no_duplicate_descriptions_within_category(self):
        """Descriptions should be unique within a category."""
        seen = {}
        for name, spec in HASH_DB.items():
            key = (spec.cat, spec.desc)
            assert key not in seen, (
                f"Duplicate desc '{spec.desc}' in cat {spec.cat}: "
                f"{seen.get(key)} and {name}"
            )
            seen[key] = name

    def test_category_counts_sum_to_total(self):
        counts = category_counts()
        assert sum(counts.values()) == len(HASH_DB)

    def test_implementation_stats_sum_to_total(self):
        stats = implementation_stats()
        assert sum(stats.values()) == len(HASH_DB)


class TestLookups:
    """LENGTH_MAP and PREFIX_MAP must match HASH_DB."""

    def test_length_map_covers_all_with_hex_len(self):
        for name, spec in HASH_DB.items():
            if spec.hex_len:
                assert name in LENGTH_MAP[spec.hex_len], f"{name} missing from LENGTH_MAP"

    def test_prefix_map_covers_all_with_prefix(self):
        for name, spec in HASH_DB.items():
            if spec.prefix:
                assert name in PREFIX_MAP[spec.prefix], f"{name} missing from PREFIX_MAP"

    def test_prefix_map_sorted_by_descending_length(self):
        """Longer prefixes must come first (so $6$ matches before $)."""
        keys = list(PREFIX_MAP.keys())
        for i in range(len(keys) - 1):
            assert len(keys[i]) >= len(keys[i + 1]), (
                f"PREFIX_MAP not sorted: {keys[i]!r} before {keys[i+1]!r}"
            )


class TestCaseInsensitiveLookup:
    def test_get_exact(self):
        assert get("MD5").name == "MD5"

    def test_get_lowercase(self):
        assert get("md5").name == "MD5"

    def test_get_mixed_case(self):
        assert get("Md5").name == "MD5"
        assert get("sHa-256").name == "SHA-256"

    def test_get_unknown(self):
        assert get("not-a-real-hash") is None
