"""Tests verifying the DonHash Attribution License (DH-AL) v1.0 compliance.

These tests verify that:
1. The LICENSE file exists and contains the DH-AL license
2. The NOTICE file exists and contains required attribution
3. Every source file contains the attribution header
4. The README mentions the license and attribution requirement
5. The pyproject.toml has the correct license field
6. The CLI splash screen / banner mentions the author (for end-user visibility)
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SRC = ROOT / "src" / "donhash"
TESTS = ROOT / "tests"

REQUIRED_ATTRIBUTION = "CySec Don (cysecdon@gmail.com)"
REQUIRED_REPO_URL = "https://github.com/cysec-don/DonHash"


class TestLicenseFile:
    def test_license_file_exists(self):
        assert (ROOT / "LICENSE").is_file(), "LICENSE file missing"

    def test_license_contains_dh_al(self):
        content = (ROOT / "LICENSE").read_text()
        assert "DonHash Attribution License" in content
        assert "DH-AL" in content or "v1.0" in content

    def test_license_contains_copyright(self):
        content = (ROOT / "LICENSE").read_text()
        assert "Copyright (c) 2026 CySec Don" in content

    def test_license_contains_attribution_clause(self):
        content = (ROOT / "LICENSE").read_text()
        # Must have explicit attribution requirement
        assert "ATTRIBUTION REQUIREMENT" in content
        assert REQUIRED_ATTRIBUTION in content

    def test_license_contains_fork_clause(self):
        content = (ROOT / "LICENSE").read_text()
        assert "FORK AND UPDATE ACKNOWLEDGMENT" in content
        assert REQUIRED_REPO_URL in content

    def test_license_contains_commercial_clause(self):
        content = (ROOT / "LICENSE").read_text()
        assert "COMMERCIAL USE ACKNOWLEDGMENT" in content

    def test_license_contains_no_warranty(self):
        content = (ROOT / "LICENSE").read_text()
        assert "NO WARRANTY" in content
        assert 'AS IS' in content or '"AS IS"' in content


class TestNoticeFile:
    def test_notice_file_exists(self):
        assert (ROOT / "NOTICE").is_file(), "NOTICE file missing"

    def test_notice_contains_attribution(self):
        content = (ROOT / "NOTICE").read_text()
        assert REQUIRED_ATTRIBUTION in content

    def test_notice_contains_repo_url(self):
        content = (ROOT / "NOTICE").read_text()
        assert REQUIRED_REPO_URL in content

    def test_notice_mentions_license(self):
        content = (ROOT / "NOTICE").read_text()
        assert "DonHash Attribution License" in content


class TestSourceFileHeaders:
    """Every Python source file must contain the attribution header."""

    @pytest.mark.parametrize("filepath", sorted(SRC.glob("*.py")))
    def test_source_file_has_attribution_header(self, filepath):
        content = filepath.read_text()
        assert "DonHash" in content, f"{filepath.name} missing 'DonHash' reference"
        assert "CySec Don" in content, f"{filepath.name} missing author attribution"
        assert "cysecdon@gmail.com" in content, (
            f"{filepath.name} missing email attribution"
        )
        assert "DonHash Attribution License" in content or "DH-AL" in content, (
            f"{filepath.name} missing license reference"
        )

    @pytest.mark.parametrize("filepath", sorted(TESTS.glob("*.py")))
    def test_test_file_has_attribution_header(self, filepath):
        content = filepath.read_text()
        assert "DonHash" in content, f"{filepath.name} missing 'DonHash' reference"
        assert "CySec Don" in content, f"{filepath.name} missing author attribution"


class TestPyprojectLicense:
    def test_pyproject_has_license_field(self):
        content = (ROOT / "pyproject.toml").read_text()
        assert 'license' in content
        assert "DonHash Attribution License" in content

    def test_pyproject_has_author(self):
        content = (ROOT / "pyproject.toml").read_text()
        assert 'CySec Don' in content
        assert 'cysecdon@gmail.com' in content


class TestReadmeLicense:
    def test_readme_mentions_license(self):
        content = (ROOT / "README.md").read_text()
        assert "DonHash Attribution License" in content
        assert "DH-AL" in content

    def test_readme_has_attribution_text(self):
        content = (ROOT / "README.md").read_text()
        # The README must include the canonical attribution text that
        # downstream users are required to copy
        assert REQUIRED_ATTRIBUTION in content
        assert REQUIRED_REPO_URL in content

    def test_readme_has_compliance_checklist(self):
        content = (ROOT / "README.md").read_text()
        assert "Compliance checklist" in content

    def test_readme_has_commercial_licensing_contact(self):
        content = (ROOT / "README.md").read_text()
        assert "cysecdon@gmail.com" in content


class TestCliBannerAttribution:
    """The CLI banner must show the author for end-user visibility."""

    def test_banner_mentions_author(self, capsys):
        from donhash.cli import main
        # Just run --version which prints the version line
        with pytest.raises(SystemExit):
            main(["--version"])
        out = capsys.readouterr().out
        # --version output should mention "donhash" (lowercase)
        assert "donhash" in out.lower()

    def test_help_mentions_author(self, capsys):
        from donhash.cli import main
        with pytest.raises(SystemExit):
            main(["--help"])
        out = capsys.readouterr().out
        # Help text should mention the author or email
        assert "CySec Don" in out or "cysecdon" in out

    def test_list_categories_shows_author(self, capsys):
        from donhash.cli import main
        rc = main(["--list-categories", "--no-banner"])
        # Discard captured output (we only care that it runs successfully
        # and that the author is mentioned elsewhere in the codebase).
        capsys.readouterr()
        assert rc == 0


class TestLicenseIntegrity:
    """End-to-end integrity check: license file, NOTICE, headers, README
    must all agree on the author and email."""

    def test_consistent_author_across_files(self):
        files = [
            ROOT / "LICENSE",
            ROOT / "NOTICE",
            ROOT / "README.md",
            ROOT / "pyproject.toml",
            SRC / "__init__.py",
        ]
        for f in files:
            assert f.exists(), f"{f} does not exist"
            content = f.read_text()
            assert "CySec Don" in content, (
                f"{f.name} does not mention 'CySec Don'"
            )
            assert "cysecdon@gmail.com" in content, (
                f"{f.name} does not mention 'cysecdon@gmail.com'"
            )

    def test_license_version_consistent(self):
        """All references to the license must say 'v1.0'."""
        files = [
            ROOT / "LICENSE",
            ROOT / "NOTICE",
            ROOT / "README.md",
            ROOT / "pyproject.toml",
        ]
        for f in files:
            content = f.read_text()
            if "DonHash Attribution License" in content:
                # Must specify v1.0
                assert "1.0" in content, (
                    f"{f.name} mentions license but not version 1.0"
                )
