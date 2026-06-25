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

"""End-to-end CLI tests."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from donhash.cli import main


class TestCLIHelp:
    def test_help_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main(["--help"])
        assert ex.value.code == 0

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main(["--version"])
        assert ex.value.code == 0

    def test_no_args_prints_help(self, capsys):
        rc = main([])
        out = capsys.readouterr().out
        assert "DonHash" in out
        assert rc == 0


class TestCLIListCategories:
    def test_list_categories(self, capsys):
        rc = main(["--list-categories", "--no-banner"])
        out = capsys.readouterr().out
        assert "30 HASH CATEGORIES" in out
        assert "CRC / Checksum" in out
        assert "Signatures" in out
        assert "Total: 491 hash types" in out
        assert rc == 0

    def test_list_categories_shows_crackable_count(self, capsys):
        main(["--list-categories", "--no-banner"])
        out = capsys.readouterr().out
        assert "crackable" in out
        assert "detection-only" in out


class TestCLIListTypes:
    def test_list_all_types(self, capsys):
        rc = main(["--list-types", "--no-banner"])
        out = capsys.readouterr().out
        assert "MD5" in out
        assert "SHA-256" in out
        assert "compute" in out
        assert "detect-only" in out
        assert rc == 0

    def test_list_types_filtered_by_category(self, capsys):
        main(["--list-types", "--category", "3", "--no-banner"])
        out = capsys.readouterr().out
        assert "MD Family" in out
        assert "MD5" in out
        # Should NOT contain other categories' types
        assert "SHA-256" not in out

    def test_invalid_category(self, capsys):
        rc = main(["--list-types", "--category", "99", "--no-banner"])
        assert rc == 2


class TestCLIDetectOnly:
    def test_detect_md5(self, capsys):
        rc = main(["--detect-only", "-H", "5f4dcc3b5aa765d61d8327deb882cf99", "--no-banner"])
        out = capsys.readouterr().out
        assert "MD5" in out
        assert "most likely" in out
        assert rc == 0

    def test_detect_unknown_hash(self, capsys):
        rc = main(["--detect-only", "-H", "garbage", "--no-banner"])
        assert rc == 1


class TestCLICrack:
    def test_crack_md5_success(self, capsys, tmp_wordlist):
        rc = main([
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-w", tmp_wordlist,
            "-t", "MD5",
            "--no-banner",
        ])
        out = capsys.readouterr().out
        assert "HASH CRACKED" in out
        assert "password" in out
        assert rc == 0

    def test_crack_not_found(self, capsys, tmp_wordlist):
        rc = main([
            "-H", "ffffffffffffffffffffffffffffffff",
            "-w", tmp_wordlist,
            "-t", "MD5",
            "--no-banner",
        ])
        out = capsys.readouterr().out
        assert "not found" in out.lower()
        assert rc == 1

    def test_crack_with_threads(self, capsys, tmp_wordlist):
        rc = main([
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-w", tmp_wordlist,
            "-t", "MD5",
            "-T", "4",
            "--no-banner",
        ])
        out = capsys.readouterr().out
        assert "HASH CRACKED" in out
        assert rc == 0

    def test_unknown_hash_type(self, capsys, tmp_wordlist):
        rc = main([
            "-H", "abc",
            "-w", tmp_wordlist,
            "-t", "not-a-real-type",
            "--no-banner",
        ])
        out = capsys.readouterr().out
        assert "Unknown hash type" in out
        assert rc == 2


class TestCLIBatch:
    def test_batch_crack(self, capsys, tmp_hash_file, tmp_wordlist):
        rc = main([
            "-f", tmp_hash_file,
            "-w", tmp_wordlist,
            "--no-banner",
        ])
        out = capsys.readouterr().out
        assert "CRACKING SUMMARY" in out
        assert "Cracked:" in out
        assert rc == 0  # at least some cracked


class TestCLIOutputFormats:
    @pytest.mark.parametrize("fmt,ext", [
        ("txt", "txt"), ("json", "json"), ("csv", "csv"),
        ("html", "html"), ("xml", "xml"), ("md", "md"),
    ])
    def test_output_file_created(self, tmp_path, tmp_wordlist, fmt, ext):
        out_file = tmp_path / f"results.{ext}"
        main([
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-w", tmp_wordlist,
            "-t", "MD5",
            "-o", str(out_file),
            "--no-banner",
        ])
        assert out_file.exists()
        assert out_file.stat().st_size > 0

    def test_json_output_structure(self, tmp_path, tmp_wordlist):
        out_file = tmp_path / "results.json"
        main([
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-w", tmp_wordlist,
            "-t", "MD5",
            "-o", str(out_file),
            "--no-banner",
        ])
        data = json.loads(out_file.read_text())
        assert data["tool"] == "DonHash"
        assert data["results"][0]["password"] == "password"
        assert data["results"][0]["status"] == "cracked"

    def test_explicit_format_overrides_extension(self, tmp_path, tmp_wordlist):
        """--format json should write JSON even if file ends in .txt."""
        out_file = tmp_path / "results.dat"
        main([
            "-H", "5f4dcc3b5aa765d61d8327deb882cf99",
            "-w", tmp_wordlist,
            "-t", "MD5",
            "-o", str(out_file),
            "--format", "json",
            "--no-banner",
        ])
        data = json.loads(out_file.read_text())
        assert data["tool"] == "DonHash"


class TestCLISubprocessInvocation:
    """Smoke test that `python -m donhash` works."""

    def test_module_invocation(self):
        result = subprocess.run(
            [sys.executable, "-m", "donhash", "--version"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "donhash" in result.stdout.lower()
