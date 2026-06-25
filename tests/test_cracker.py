"""Tests for the cracking engine."""

from __future__ import annotations

from donhash.cracker import (
    CrackResult,
    _count_lines,
    crack_from_file,
    crack_single_hash,
)


class TestCountLines:
    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_text("", encoding="utf-8")
        assert _count_lines(str(p)) == 0

    def test_one_line_no_newline(self, tmp_path):
        p = tmp_path / "one.txt"
        p.write_text("hello", encoding="utf-8")
        # No trailing newline → 0 lines by \n count
        assert _count_lines(str(p)) == 0

    def test_one_line_with_newline(self, tmp_path):
        p = tmp_path / "one.txt"
        p.write_text("hello\n", encoding="utf-8")
        assert _count_lines(str(p)) == 1

    def test_multiple_lines(self, tmp_path):
        p = tmp_path / "multi.txt"
        p.write_text("a\nb\nc\nd\n", encoding="utf-8")
        assert _count_lines(str(p)) == 4

    def test_large_file(self, tmp_path):
        p = tmp_path / "large.txt"
        p.write_text("\n".join(["x"] * 10000) + "\n", encoding="utf-8")
        assert _count_lines(str(p)) == 10000


class TestCrackSingleHash:
    def test_crack_md5_success(self, tmp_wordlist):
        # MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        result = crack_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "MD5",
            tmp_wordlist,
        )
        assert result.status == "cracked"
        assert result.password == "password"
        assert result.attempts > 0
        assert result.time >= 0
        assert result.speed > 0

    def test_crack_sha1_success(self, tmp_wordlist):
        # SHA1("letmein") computed from hashlib to avoid hardcoding errors
        import hashlib
        target = hashlib.sha1(b"letmein").hexdigest()
        result = crack_single_hash(target, "SHA-1", tmp_wordlist)
        assert result.status == "cracked"
        assert result.password == "letmein"

    def test_crack_not_found(self, tmp_wordlist):
        # MD5 of a string not in the wordlist
        import hashlib
        target = hashlib.md5(b"not_in_wordlist_xyz").hexdigest()
        result = crack_single_hash(target, "MD5", tmp_wordlist)
        assert result.status == "not_found"
        assert result.password is None

    def test_crack_sha256(self, tmp_wordlist):
        import hashlib
        target = hashlib.sha256(b"admin").hexdigest()
        result = crack_single_hash(target, "SHA-256", tmp_wordlist)
        assert result.status == "cracked"
        assert result.password == "admin"

    def test_crack_ntlm(self, tmp_wordlist):
        # NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
        result = crack_single_hash(
            "8846f7eaee8fb117ad06bdd830b7586c",
            "NTLM",
            tmp_wordlist,
        )
        assert result.status == "cracked"
        assert result.password == "password"

    def test_wordlist_not_found(self):
        result = crack_single_hash("5f4dcc3b5aa765d61d8327deb882cf99", "MD5", "/nonexistent/path")
        assert result.status == "error"
        assert "Wordlist not found" in result.error

    def test_unknown_hash_type(self, tmp_wordlist):
        result = crack_single_hash("abc", "not-a-real-type", tmp_wordlist)
        assert result.status == "error"
        assert "Unknown hash type" in result.error

    def test_detect_only_type_returns_unsupported(self, tmp_wordlist):
        result = crack_single_hash("abc", "MD6", tmp_wordlist)
        assert result.status == "unsupported"
        assert "detection-only" in result.error

    def test_salted_without_salt_returns_error(self, tmp_wordlist):
        result = crack_single_hash("abc", "md5(pass.salt)", tmp_wordlist)
        assert result.status == "error"
        assert "requires a salt" in result.error

    def test_salted_with_salt(self, tmp_wordlist):
        import hashlib
        # md5(pass.salt) with pass="admin" and salt="xyz"
        target = hashlib.md5(b"adminxyz").hexdigest()
        result = crack_single_hash(target, "md5(pass.salt)", tmp_wordlist, ext_salt="xyz")
        assert result.status == "cracked"
        assert result.password == "admin"

    def test_multithreaded_crack(self, tmp_wordlist):
        # Same as test_crack_md5_success but with -T 4
        result = crack_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "MD5",
            tmp_wordlist,
            num_threads=4,
        )
        assert result.status == "cracked"
        assert result.password == "password"


class TestCrackFromFile:
    def test_batch_crack(self, tmp_hash_file, tmp_wordlist):
        results = crack_from_file(tmp_hash_file, tmp_wordlist)
        assert len(results) == 3
        # First two are MD5
        assert results[0].status == "cracked"
        assert results[0].password == "password"
        assert results[1].status == "cracked"
        assert results[1].password == "letmein"
        # Third is SHA-1 with explicit type via hash:type syntax
        assert results[2].status == "cracked"
        assert results[2].password == "password"

    def test_file_not_found(self, tmp_wordlist):
        results = crack_from_file("/nonexistent/hashes.txt", tmp_wordlist)
        assert results == []

    def test_hash_type_override(self, tmp_path, tmp_wordlist):
        # Write MD5 hashes but force SHA-1 type — should not crack
        p = tmp_path / "hashes.txt"
        p.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n", encoding="utf-8")
        results = crack_from_file(str(p), tmp_wordlist, hash_type_override="SHA-1")
        assert len(results) == 1
        assert results[0].status == "not_found"


class TestCrackResultDataclass:
    def test_default_values(self):
        r = CrackResult(hash="abc", type="MD5")
        assert r.password is None
        assert r.status == "not_found"
        assert r.attempts == 0

    def test_to_dict(self):
        r = CrackResult(
            hash="abc", type="MD5", category="MD Family",
            password="pw", attempts=10, time=0.5, speed=20.0, status="cracked",
        )
        d = r.to_dict()
        assert d["hash"] == "abc"
        assert d["password"] == "pw"
        assert d["status"] == "cracked"
        assert d["attempts"] == 10


class TestThreadingSafety:
    """Test that multi-threaded cracking is correct and bounded in memory."""

    def test_large_wordlist_multithreaded(self, tmp_path):
        """Verify multi-threaded crack on a larger wordlist."""
        p = tmp_path / "big.txt"
        # 5000 words; target = word at position 4999
        words = [f"word_{i}" for i in range(5000)]
        target_word = words[4999]
        import hashlib
        target_hash = hashlib.md5(target_word.encode()).hexdigest()
        p.write_text("\n".join(words) + "\n", encoding="utf-8")

        result = crack_single_hash(target_hash, "MD5", str(p), num_threads=8)
        assert result.status == "cracked"
        assert result.password == target_word

    def test_first_word_crack(self, tmp_wordlist):
        """Verify cracking succeeds when the password is the first word."""
        import hashlib
        target = hashlib.md5(b"password").hexdigest()
        result = crack_single_hash(target, "MD5", tmp_wordlist, num_threads=1)
        assert result.status == "cracked"
        assert result.attempts == 1
