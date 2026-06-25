"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

# Ensure src/ is on path for direct invocation (no install needed)
ROOT = pathlib.Path(__file__).parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Make src/ available to subprocess tests too (PYTHONPATH)
_SRC_STR = str(SRC)
_existing_pp = os.environ.get("PYTHONPATH", "")
if _SRC_STR not in _existing_pp.split(os.pathsep):
    os.environ["PYTHONPATH"] = (
        _SRC_STR + (os.pathsep + _existing_pp if _existing_pp else "")
    )


@pytest.fixture
def tmp_wordlist(tmp_path):
    """Create a small wordlist file with common passwords."""
    p = tmp_path / "wordlist.txt"
    p.write_text(
        "\n".join([
            "password", "123456", "admin", "letmein", "qwerty",
            "welcome", "monkey", "dragon", "master", "abc123",
            "",  # blank line should be skipped
            "test", "secret", "root",
        ]) + "\n",
        encoding="utf-8",
    )
    return str(p)


@pytest.fixture
def tmp_hash_file(tmp_path):
    """Create a hash file for batch mode testing."""
    p = tmp_path / "hashes.txt"
    # MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
    # MD5("letmein")  = 0d107d09f5bbe40cade3de5c71e9e9b7
    # SHA1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    p.write_text(
        "\n".join([
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "0d107d09f5bbe40cade3de5c71e9e9b7",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:SHA-1",
        ]) + "\n",
        encoding="utf-8",
    )
    return str(p)
