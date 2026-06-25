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

"""Integration tests covering the full CLI flow end-to-end."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest


@pytest.fixture
def large_wordlist(tmp_path):
    """A 1000-entry wordlist for performance/correctness testing."""
    p = tmp_path / "large.txt"
    words = [f"word_{i:04d}" for i in range(1000)]
    # Insert known password at known position
    words[500] = "password"
    words[501] = "letmein"
    words[999] = "admin"
    p.write_text("\n".join(words) + "\n", encoding="utf-8")
    return str(p)


class TestEndToEndCracking:
    """Test the full pipeline: detect → crack → output."""

    def test_md5_full_pipeline(self, large_wordlist, tmp_path):
        from donhash.cli import main
        out_file = tmp_path / "out.json"
        rc = main([
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5("password")
            "-w", large_wordlist,
            "-t", "MD5",
            "-T", "8",
            "-o", str(out_file),
            "--no-banner",
        ])
        assert rc == 0
        data = json.loads(out_file.read_text())
        assert data["results"][0]["password"] == "password"
        assert data["results"][0]["status"] == "cracked"

    def test_ntlm_full_pipeline(self, large_wordlist):
        from donhash.cli import main
        # NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
        rc = main([
            "-H", "8846f7eaee8fb117ad06bdd830b7586c",
            "-w", large_wordlist,
            "-t", "NTLM",
            "--no-banner",
        ])
        assert rc == 0

    def test_sha256_multithreaded(self, large_wordlist):
        from donhash.cracker import crack_single_hash
        target = hashlib.sha256(b"admin").hexdigest()
        result = crack_single_hash(target, "SHA-256", large_wordlist, num_threads=10)
        assert result.status == "cracked"
        assert result.password == "admin"
        # Must have actually searched a lot of words
        assert result.attempts >= 999  # admin is at position 999


class TestPerformance:
    """Benchmark tests — verify performance is reasonable."""

    def test_md5_throughput(self, large_wordlist):
        """Single-threaded MD5 cracking should achieve > 50k h/s on modern CPU."""
        from donhash.cracker import crack_single_hash
        # 'admin' is at position 999 in large_wordlist
        target = hashlib.md5(b"admin").hexdigest()
        result = crack_single_hash(target, "MD5", large_wordlist, num_threads=1)
        assert result.status == "cracked"
        # Allow generous threshold for CI environments
        assert result.speed > 1000, f"Speed too low: {result.speed} h/s"

    def test_multithread_speedup(self, large_wordlist):
        """Multi-threaded cracking should not be significantly slower than single-threaded.

        Note: Python's GIL means we don't expect a real speedup for pure-Python
        hashing, but multi-threaded should never be 5x+ slower (which would
        indicate a bug in the threading implementation).
        """
        from donhash.cracker import crack_single_hash
        target = hashlib.md5(b"admin").hexdigest()

        # Single-threaded
        r1 = crack_single_hash(target, "MD5", large_wordlist, num_threads=1)
        # Multi-threaded (4 threads)
        r4 = crack_single_hash(target, "MD5", large_wordlist, num_threads=4)

        assert r1.status == "cracked"
        assert r4.status == "cracked"
        # Generous threshold for CI noise — the goal is to detect regressions
        # where multi-threading makes things dramatically slower, not to
        # enforce a specific speedup.
        assert r4.time <= r1.time * 5.0 + 1.0, (
            f"Multi-threaded was dramatically slower: {r4.time}s vs {r1.time}s"
        )


class TestStreamingWordlist:
    """Verify the cracker uses bounded memory regardless of wordlist size."""

    def test_large_wordlist_does_not_oom(self, tmp_path):
        """A 100k-entry wordlist should crack without running out of memory."""
        from donhash.cracker import crack_single_hash

        p = tmp_path / "huge.txt"
        # Generate 100k words; target is the last one
        target_word = "secret_target_word"
        with open(p, "w") as f:
            for i in range(99999):
                f.write(f"filler_{i}\n")
            f.write(target_word + "\n")

        target = hashlib.md5(target_word.encode()).hexdigest()
        result = crack_single_hash(target, "MD5", str(p), num_threads=4)
        assert result.status == "cracked"
        assert result.password == target_word
        assert result.attempts == 100000


class TestEdgeCases:
    """Edge cases that must not crash the cracker."""

    def test_empty_wordlist(self, tmp_path):
        from donhash.cracker import crack_single_hash
        p = tmp_path / "empty.txt"
        p.write_text("", encoding="utf-8")
        result = crack_single_hash("5f4dcc3b5aa765d61d8327deb882cf99", "MD5", str(p))
        assert result.status == "not_found"
        assert result.attempts == 0

    def test_wordlist_with_blank_lines(self, tmp_path):
        from donhash.cracker import crack_single_hash
        p = tmp_path / "blanks.txt"
        p.write_text("\n\npassword\n\n", encoding="utf-8")
        result = crack_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99", "MD5", str(p)
        )
        assert result.status == "cracked"

    def test_wordlist_with_unicode(self, tmp_path):
        from donhash.cracker import crack_single_hash
        p = tmp_path / "unicode.txt"
        p.write_text("café\nmünchen\npassword\n日本語\n", encoding="utf-8")
        result = crack_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99", "MD5", str(p)
        )
        assert result.status == "cracked"

    def test_wordlist_with_special_chars(self, tmp_path):
        from donhash.cracker import crack_single_hash
        p = tmp_path / "special.txt"
        p.write_text('p@ssw0rd!\n"quoted"\npassword\n', encoding="utf-8")
        result = crack_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99", "MD5", str(p)
        )
        assert result.status == "cracked"

    def test_hash_with_whitespace(self, large_wordlist):
        """Whitespace around the hash should be stripped."""
        from donhash.cracker import crack_single_hash
        result = crack_single_hash(
            "  5f4dcc3b5aa765d61d8327deb882cf99  ", "MD5", large_wordlist
        )
        assert result.status == "cracked"


class TestSubprocessInvocation:
    """End-to-end tests via subprocess to catch import/startup issues."""

    def test_module_invocation_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "donhash", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "DonHash" in result.stdout

    def test_module_invocation_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "donhash", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "2." in result.stdout  # 2.x.x version

    def test_module_invocation_list_categories(self):
        result = subprocess.run(
            [sys.executable, "-m", "donhash", "--list-categories", "--no-banner"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "CRC" in result.stdout
        assert "Signatures" in result.stdout
        assert "491 hash types" in result.stdout

    def test_module_invocation_detect(self):
        result = subprocess.run(
            [sys.executable, "-m", "donhash", "--detect-only",
             "-H", "5f4dcc3b5aa765d61d8327deb882cf99", "--no-banner"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "MD5" in result.stdout

    def test_module_invocation_crack(self, tmp_path):
        wordlist = tmp_path / "wl.txt"
        wordlist.write_text("password\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "donhash",
             "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
             "-w", str(wordlist),
             "-t", "MD5",
             "--no-banner"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "HASH CRACKED" in result.stdout
        assert "password" in result.stdout


class TestPythonVersionCompatibility:
    """Tests that verify cross-Python-version behavior."""

    def test_no_crypt_import_required(self):
        """The package must import successfully even when crypt module is unavailable
        (Python 3.13+)."""
        # Try importing without crypt module
        import sys
        original_crypt = sys.modules.get("crypt")
        sys.modules["crypt"] = None  # block crypt import
        try:
            # Force re-import of donhash modules
            for mod in list(sys.modules.keys()):
                if mod.startswith("donhash"):
                    del sys.modules[mod]
            from donhash._engine import compute_hash
            from donhash.cli import main  # noqa: F401
            from donhash.cracker import crack_single_hash  # noqa: F401
            # If we got here without ImportError, the test passes
            assert True
        finally:
            if original_crypt is not None:
                sys.modules["crypt"] = original_crypt
            else:
                sys.modules.pop("crypt", None)
            # Re-import donhash modules for subsequent tests
            for mod in list(sys.modules.keys()):
                if mod.startswith("donhash"):
                    del sys.modules[mod]
            from donhash._engine import compute_hash  # noqa: F401
