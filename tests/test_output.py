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

"""Tests for output writers."""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET

import pytest

from donhash.cracker import CrackResult
from donhash.output import (
    SUPPORTED_FORMATS,
    _esc,
    detect_output_format,
    write_output,
)


@pytest.fixture
def sample_results():
    return [
        CrackResult(
            hash="5f4dcc3b5aa765d61d8327deb882cf99",
            type="MD5",
            category="MD Family & Variants",
            password="password",
            attempts=1,
            time=0.001,
            speed=1000.0,
            status="cracked",
        ),
        CrackResult(
            hash="abcdef1234567890abcdef1234567890",
            type="MD5",
            category="MD Family & Variants",
            password=None,
            attempts=100,
            time=0.5,
            speed=200.0,
            status="not_found",
        ),
        CrackResult(
            hash="somehash",
            type="MD6",
            category="MD Family & Variants",
            password=None,
            attempts=0,
            time=0.0,
            speed=0.0,
            status="unsupported",
            error="detection-only",
        ),
    ]


class TestDetectOutputFormat:
    def test_explicit_format_overrides_extension(self):
        assert detect_output_format("out.txt", "json") == "json"

    def test_extension_detection(self):
        assert detect_output_format("out.txt") == "txt"
        assert detect_output_format("out.json") == "json"
        assert detect_output_format("out.csv") == "csv"
        assert detect_output_format("out.html") == "html"
        assert detect_output_format("out.xml") == "xml"
        assert detect_output_format("out.md") == "md"

    def test_unknown_extension_defaults_to_txt(self):
        assert detect_output_format("out.dat") == "txt"
        assert detect_output_format("out.bin") == "txt"
        assert detect_output_format("out") == "txt"

    def test_format_case_insensitive(self):
        assert detect_output_format("out", "JSON") == "json"


class TestWriteTxt:
    def test_writes_file(self, tmp_path, sample_results):
        out = tmp_path / "results.txt"
        write_output(sample_results, str(out), "txt")
        assert out.exists()
        content = out.read_text()
        assert "DonHash" in content
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in content
        assert "password" in content
        assert "Summary:" in content

    def test_handles_empty_results(self, tmp_path):
        out = tmp_path / "empty.txt"
        write_output([], str(out), "txt")
        content = out.read_text()
        assert "Summary: 0/0" in content


class TestWriteJson:
    def test_valid_json(self, tmp_path, sample_results):
        out = tmp_path / "results.json"
        write_output(sample_results, str(out), "json")
        data = json.loads(out.read_text())
        assert data["tool"] == "DonHash"
        assert data["version"] == "2.0"
        assert len(data["results"]) == 3
        assert data["results"][0]["password"] == "password"
        assert data["summary"]["total"] == 3
        assert data["summary"]["cracked"] == 1


class TestWriteCsv:
    def test_csv_structure(self, tmp_path, sample_results):
        out = tmp_path / "results.csv"
        write_output(sample_results, str(out), "csv")
        with open(str(out)) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 3
        assert rows[0]["password"] == "password"
        assert rows[0]["type"] == "MD5"
        assert rows[0]["status"] == "cracked"


class TestWriteHtml:
    def test_html_well_formed(self, tmp_path, sample_results):
        out = tmp_path / "results.html"
        write_output(sample_results, str(out), "html")
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in content

    def test_html_escapes_xss(self, tmp_path):
        """Critical: HTML output must escape user-supplied input to prevent XSS."""
        evil_password = "<script>alert('xss')</script>"
        evil_hash = "<img src=x onerror=alert(1)>"
        results = [
            CrackResult(
                hash=evil_hash,
                type="MD5",
                category="X",
                password=evil_password,
                attempts=1,
                time=0.0,
                speed=1.0,
                status="cracked",
            )
        ]
        out = tmp_path / "xss.html"
        write_output(results, str(out), "html")
        content = out.read_text()
        # The raw dangerous markup must NOT appear
        assert "<script>alert('xss')</script>" not in content
        assert "<img src=x onerror=alert(1)>" not in content
        # But the escaped form MUST appear
        assert "&lt;script&gt;" in content
        assert "&lt;img" in content

    def test_html_escapes_other_fields(self, tmp_path):
        """All user-controlled fields (hash, type, category, error) must be escaped."""
        results = [
            CrackResult(
                hash="usersupplied_hash",
                type="<b>MD5</b>",
                category="<i>cat</i>",
                password=None,
                attempts=0,
                time=0,
                speed=0,
                status="error",
                error="<script>evil()</script>",
            )
        ]
        out = tmp_path / "xss2.html"
        write_output(results, str(out), "html")
        content = out.read_text()
        # The user-supplied dangerous markup must NOT appear unescaped
        assert "<script>evil()</script>" not in content
        assert "<b>MD5</b>" not in content  # only escaped &lt;b&gt;
        assert "<i>cat</i>" not in content
        # But the escaped forms MUST appear
        assert "&lt;script&gt;" in content
        assert "&lt;b&gt;MD5&lt;/b&gt;" in content


class TestWriteXml:
    def test_xml_well_formed(self, tmp_path, sample_results):
        out = tmp_path / "results.xml"
        write_output(sample_results, str(out), "xml")
        tree = ET.parse(str(out))  # raises if malformed
        root = tree.getroot()
        assert root.tag == "donhash-results"
        assert root.get("version") == "2.0"
        results = root.findall("result")
        assert len(results) == 3

    def test_xml_escapes_special_chars(self, tmp_path):
        """XML must escape &, <, >."""
        results = [
            CrackResult(
                hash="a<b>&c",
                type="MD5",
                category="cat&dog",
                password="x<y",
                attempts=1,
                time=0,
                speed=1,
                status="cracked",
            )
        ]
        out = tmp_path / "esc.xml"
        write_output(results, str(out), "xml")
        # Parsing must succeed
        tree = ET.parse(str(out))
        root = tree.getroot()
        result = root.find("result")
        assert result.find("hash").text == "a<b>&c"
        assert result.find("password").text == "x<y"


class TestWriteMarkdown:
    def test_markdown_structure(self, tmp_path, sample_results):
        out = tmp_path / "results.md"
        write_output(sample_results, str(out), "md")
        content = out.read_text()
        assert "# DonHash" in content
        assert "| Hash |" in content
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in content
        assert "password" in content

    def test_markdown_escapes_pipes(self, tmp_path):
        """Pipes in user input must be escaped in markdown tables."""
        results = [
            CrackResult(
                hash="a|b",
                type="MD5",
                category="c|d",
                password="x|y",
                attempts=1,
                time=0,
                speed=1,
                status="cracked",
            )
        ]
        out = tmp_path / "pipe.md"
        write_output(results, str(out), "md")
        content = out.read_text()
        # The escaped form must appear; raw pipe inside cells would break the table
        assert "a\\|b" in content
        assert "c\\|d" in content
        assert "x\\|y" in content


class TestEscHelper:
    def test_escapes_lt_gt(self):
        assert _esc("<script>") == "&lt;script&gt;"

    def test_escapes_quotes(self):
        assert _esc('"hello"') == "&quot;hello&quot;"
        assert _esc("'hello'") == "&#x27;hello&#x27;"

    def test_escapes_ampersand(self):
        assert _esc("a & b") == "a &amp; b"

    def test_handles_none(self):
        assert _esc(None) == ""

    def test_handles_int(self):
        assert _esc(42) == "42"


class TestAllFormats:
    """Smoke test: every format should produce a non-empty file."""

    @pytest.mark.parametrize("fmt", SUPPORTED_FORMATS)
    def test_format_produces_output(self, tmp_path, sample_results, fmt):
        out = tmp_path / f"results.{fmt}"
        write_output(sample_results, str(out), fmt)
        assert out.exists()
        assert out.stat().st_size > 0
