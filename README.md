# DonHash

**Advanced Hash Detector & Cracker** — 491 hash types across 30 categories, multi-threaded cracking, multi-format output, pure-Python MD4 for NTLM/NT on every modern Python.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Hash Types](https://img.shields.io/badge/Hash%20Types-491-orange)
![Version](https://img.shields.io/badge/Version-2.1.0-cyan)
![Tests](https://img.shields.io/badge/Tests-836%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-77%25-brightgreen)
![Lint](https://img.shields.io/badge/Lint-ruff%20clean-brightgreen)

**Author:** CySec Don — [cysecdon@gmail.com](mailto:cysecdon@gmail.com)
**License:** MIT — see [LICENSE](LICENSE)

---

## Table of Contents

- [What is DonHash?](#what-is-donhash)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Reference](#cli-reference)
- [Implementation Status](#implementation-status)
- [Supported Hash Categories](#supported-hash-categories)
- [Output Formats](#output-formats)
- [Use Cases](#use-cases)
- [Development](#development)
- [Architecture](#architecture)
- [Security Notes](#security-notes)
- [Disclaimer](#disclaimer)
- [Changelog](#changelog)

---

## What is DonHash?

DonHash is a Python-based hash identification and password-recovery tool. It ships with:

- **491 hash types** registered across 30 detection categories
- **Real compute implementations** for the 100+ most common types (MD family, SHA family, BLAKE2, RIPEMD, NTLM, MySQL, etc.)
- **Pure-Python MD4** — verified against all 7 RFC 1320 test vectors — so NTLM/NT cracking works on every modern Python (3.10 through 3.13+) without needing the OpenSSL legacy provider
- **Multi-threaded cracking** with streaming I/O (constant memory even on multi-GB wordlists)
- **Auto-detection** of hash types by length, prefix, and character set
- **Dictionary attack** with customizable wordlist (default: rockyou.txt if found in standard locations)
- **Batch mode** — crack multiple hashes from a file at once (`hash:type` syntax supported)
- **Multi-format output** — save results in 6 formats: `txt`, `json`, `csv`, `html` (XSS-safe), `xml`, `md`
- **Honest reporting** — types without an implementation are explicitly marked `detect-only` instead of silently failing
- **Python 3.10+ compatible** including Python 3.13+ where the `crypt` module was removed (PEP 594)
- **Zero required runtime dependencies** (stdlib only); optional extras for bcrypt/argon2/passlib/pycryptodome

DonHash is designed for cybersecurity education, authorized penetration testing, digital forensics, password-research, and CTF competitions. It is **not** a hashcat replacement — it does not implement mask attacks, rule engines, GPU acceleration, or the long tail of TrueCrypt/VeraCrypt/LUKS/Kerberos formats that require specialized C libraries. For those, use [hashcat](https://hashcat.net/hashcat/) or [John the Ripper](https://www.openwall.com/john/). DonHash is the lightweight, scriptable, dependency-free alternative for the 80% of cracking work that doesn't need a GPU.

---

## Quick Start

```bash
# Install
pip install -e .              # editable install from source
# or
pip install .                 # regular install

# Optional: enable bcrypt / argon2 / passlib support
pip install "donhash[all]"

# Detect a hash (no cracking)
donhash --detect-only -H 5f4dcc3b5aa765d61d8327deb882cf99

# Crack a single hash (auto-detect type)
donhash -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

# Force a hash type
donhash -H 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5

# Multi-threaded cracking with verbose output, JSON results
donhash -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 20 -v -o results.json

# Batch crack from a file
donhash -f hashes.txt -w rockyou.txt -o results.html -T 10

# List all categories
donhash --list-categories

# List all hash types (with implementation status)
donhash --list-types

# Filter by category
donhash --list-types --category 3
```

You can also invoke DonHash as a module without installing it:

```bash
python -m donhash --help
```

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/cysec-don/DonHash.git
cd DonHash
pip install -e .
```

### Optional extras

DonHash has **zero required runtime dependencies** — it uses only the Python standard library. Optional extras unlock additional hash-cracking support:

| Extra | Provides | Hash types unlocked |
|-------|----------|---------------------|
| `bcrypt` | `bcrypt` library | bcrypt 2a/2b/2x/2y, Django(bcrypt), Django(bcrypt-SHA256) |
| `argon2` | `argon2-cffi` library | Argon2, Argon2d, Argon2i, Argon2id |
| `passlib` | `passlib` library | MD5-crypt, SHA-256-crypt, SHA-512-crypt, MD5(APR), PHPass, passlib-pbkdf2-*, passlib-scrypt |
| `all` | All of the above + `pycryptodome` | All of the above + LM hash (DES-based) |

```bash
pip install "donhash[all]"        # everything
pip install "donhash[bcrypt]"     # just bcrypt
pip install "donhash[dev]"        # dev tooling (pytest, ruff, mypy, etc.)
```

### Python version support

| Python | Status |
|--------|--------|
| 3.10 | ✅ Fully supported |
| 3.11 | ✅ Fully supported |
| 3.12 | ✅ Fully supported |
| 3.13 | ✅ Fully supported (no `crypt` module needed) |
| 3.9 and older | ❌ Not supported (EOL) |

---

## CLI Reference

### Options

| Option | Description |
|--------|-------------|
| `-H`, `--hash` | Single hash to crack |
| `-f`, `--file` | File with hashes (one per line; `hash:type` syntax supported) |
| `-w`, `--wordlist` | Path to wordlist (default: rockyou.txt if found in standard locations) |
| `-t`, `--type` | Force a specific hash type (case-insensitive: `-t md5` == `-t MD5`) |
| `-s`, `--salt` | Salt for salted hash types |
| `-T`, `--threads` | Number of threads (1-100, default: 5) |
| `-o`, `--output` | Save results to file (format auto-detected or set via `--format`) |
| `--format` | Output format: `txt`, `json`, `csv`, `html`, `xml`, `md` |
| `-v`, `--verbose` | Show progress while cracking |
| `--detect-only` | Only detect hash type(s) without cracking |
| `--list-categories` | List all 30 categories |
| `--list-types` | List all hash types with implementation status |
| `--category N` | Filter `--list-types` by category number (1-30) |
| `--no-banner` | Skip the splash screen (useful for scripting) |
| `--version` | Show version |
| `-h`, `--help` | Show help |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (hash cracked, or help/version/listing displayed) |
| 1 | Hash not found in wordlist, or detection failed |
| 2 | Argument error (unknown type, missing required flag, etc.) |

### Examples

```bash
# Detect a hash
donhash --detect-only -H 5f4dcc3b5aa765d61d8327deb882cf99

# Crack with auto-detection
donhash -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

# Force type, 10 threads, verbose
donhash -H 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5 -T 10 -v

# NTLM hash (uses pure-Python MD4 — works on Python 3.13+)
donhash -H 8846f7eaee8fb117ad06bdd830b7586c -t NTLM -w wordlist.txt

# Salted hash
donhash -H <hash> -t "md5(pass.salt)" -s mysalt -w wordlist.txt

# Batch mode (one hash per line, optional hash:type syntax)
donhash -f hashes.txt -w rockyou.txt -o results.json

# List categories with crackable counts
donhash --list-categories

# List all types in MD family (category 3)
donhash --list-types --category 3

# Scripting mode (no banner, machine-readable JSON)
donhash -H <hash> -w wordlist.txt --no-banner -o results.json
```

---

## Implementation Status

Every hash type in DonHash is marked with one of four implementation levels. Run `donhash --list-types` to see the level for every type.

| Level | Meaning | Count | Examples |
|-------|---------|-------|----------|
| `compute` | Full compute support, crackable without salt | ~100 | MD5, SHA-256, SHA-1, SHA-512, NTLM, NT, MD4, BLAKE2b, BLAKE2s, CRC-32, CRC-32C, MySQL323, MySQL4.1, MySQL5.x, FNV-1-32, DJB2, Half-MD5, Double-MD5, Triple-MD5, Double-SHA1, SHA3-256, SHA3-512, SHAKE128, BLAKE2s-128, RIPEMD-160, Whirlpool (with OpenSSL legacy) |
| `crypt` | Crackable via crypt-style salt extraction (needs original hash) | ~30 | bcrypt 2a/2b/2x/2y, MD5(Crypt), MD5(APR), SHA-256(Crypt), SHA-512(Crypt), Argon2, Argon2id, Django(MD5), Django(SHA-256), Django(PBKDF2-SHA256), Django(bcrypt), WordPress-phpass, PHPass, Netscape-LDAP-SSHA, OpenLDAP-SSHA256/512, PostgreSQL-MD5 |
| `salted` | Crackable, but requires `-s/--salt` | ~30 | md5(pass.salt), md5(salt.pass), sha256(pass.salt), sha512(salt.pass), HMAC-MD5(pass), HMAC-SHA256(salt), PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA512, PostgreSQL-MD5, OSX-10.4 |
| `detect-only` | Detection only, no compute implementation | ~330 | TrueCrypt/VeraCrypt, LUKS, MS Office, PDF, RAR/7-Zip, WPA/WPA2, Kerberos, Bitcoin wallet, TrueCrypt, Bitcoin-Address, Cisco-PIX, NTLMv1/v2, LM (with pycryptodome), MD2 (RFC 6149 deprecated), MD6, SHA-0, Tiger, Skein, Snefru, HAVAL, GOST, MS-Cache, DCC, MSOffice-2007-2016, Kerberos-etype17/18, PGP, RFC 2440 |

For `detect-only` types, DonHash identifies the format but defers to specialized tools (hashcat/john) for cracking — these formats need C libraries, GPU acceleration, or proprietary code that's out of scope for a pure-Python tool.

### Why "detect-only"?

Many real-world hash formats (TrueCrypt volumes, LUKS partitions, MS Office documents, PDF files, WPA handshakes, Kerberos tickets) are not simple hash functions — they're complex key-derivation schemes that require parsing binary structures, computing multiple intermediate values, and often need a cipher implementation (AES, Serpent, Twofish). DonHash identifies these formats by their prefix/length so you know what you're looking at, but doesn't ship a C-level implementation. Use hashcat or john for these.

---

## Supported Hash Categories

DonHash organizes its 491 hash types into 30 categories:

| # | Category | # | Category |
|---|----------|---|----------|
| 01 | CRC / Checksum | 16 | Cisco / Network / Firewall |
| 02 | Non-Cryptographic | 17 | Network Protocols |
| 03 | MD Family & Variants | 18 | MS Office / PDF / Archives |
| 04 | SHA-1 & Variants | 19 | Archives & Documents |
| 05 | SHA-2 Family | 20 | TrueCrypt / VeraCrypt |
| 06 | SHA-3 / Keccak | 21 | LUKS / DiskCryptor / FDE |
| 07 | BLAKE Family | 22 | Apple / macOS / iOS |
| 08 | RIPEMD / Tiger / Whirlpool / Skein / GOST | 23 | Android / Mobile |
| 09 | HMAC Variants | 24 | Cryptocurrency / Blockchain |
| 10 | KDF / yescrypt | 25 | LDAP / Directory Services |
| 11 | Unix / Linux Crypt | 26 | Password Managers / Vaults |
| 12 | Windows Authentication | 27 | Application / Protocol / Other |
| 13 | Database Hashes | 28 | Legacy Variants |
| 14 | CMS / Web Applications | 29 | More Cryptographic Functions |
| 15 | More CMS / Frameworks | 30 | Signatures |

Run `donhash --list-categories` to see live counts.

---

## Output Formats

DonHash can save cracking results in 6 formats. The format is auto-detected from the output file extension, or set explicitly with `--format`.

### JSON

```json
{
  "tool": "DonHash",
  "version": "2.1.0",
  "generated": "2026-06-25T10:00:00",
  "results": [
    {
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "type": "MD5",
      "category": "MD Family & Variants",
      "status": "cracked",
      "password": "password",
      "attempts": 1,
      "time": 0.001,
      "speed": 1000.0,
      "error": null
    }
  ],
  "summary": {
    "total": 1,
    "cracked": 1,
    "not_found": 0,
    "unsupported": 0,
    "error": 0
  }
}
```

### CSV

```csv
hash,type,category,status,password,attempts,time,speed,error
5f4dcc3b5aa765d61d8327deb882cf99,MD5,MD Family & Variants,cracked,password,1,0.001,1000.0,
```

### HTML

The HTML format generates a fully styled, dark-themed report with a cyberpunk aesthetic. All user-supplied fields (hash, password, type, category, error) are HTML-escaped to prevent XSS — safe to share and view in browsers.

### XML

```xml
<?xml version='1.0' encoding='utf-8'?>
<donhash-results version="2.1.0" generated="2026-06-25T10:00:00">
  <summary>
    <total>1</total>
    <cracked>1</cracked>
  </summary>
  <result>
    <hash>5f4dcc3b5aa765d61d8327deb882cf99</hash>
    <type>MD5</type>
    <category>MD Family &amp; Variants</category>
    <status>cracked</status>
    <password>password</password>
    <attempts>1</attempts>
    <time>0.001</time>
    <speed>1000.0</speed>
    <error></error>
  </result>
</donhash-results>
```

### Markdown

```markdown
# DonHash v2.1.0 — Cracking Results

**Generated:** 2026-06-25 10:00:00

**Summary:** 1/1 cracked (100%)

| Hash | Type | Category | Status | Password | Attempts | Time | Speed | Error |
|------|------|----------|--------|----------|----------|------|-------|-------|
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | MD Family & Variants | cracked | password | 1 | 0.001s | 1,000 h/s |  |
```

### Plain text (txt)

```
======================================================================
DonHash v2.1.0 — Cracking Results
Generated: 2026-06-25 10:00:00
======================================================================

Hash     : 5f4dcc3b5aa765d61d8327deb882cf99
Type     : MD5
Category : MD Family & Variants
Status   : cracked
Password : password
Attempts : 1
Time     : 0.001s
Speed    : 1,000 h/s
----------------------------------------------------------------------
Summary: 1/1 cracked (100%)
```

---

## Use Cases

1. **Penetration Testing** — Crack password hashes recovered from a target during an authorized penetration test to demonstrate weak password usage.
2. **Security Auditing** — Audit your organization's password policies by testing hash dumps against common wordlists.
3. **CTF Competitions** — Quickly identify and crack hash challenges in Capture The Flag security competitions.
4. **Digital Forensics** — Identify unknown hash formats and attempt recovery during forensic investigations.
5. **Password Research** — Study hash algorithm behavior, compare cracking speeds across different hash types.
6. **Compliance Testing** — Verify that your systems are using strong, salted hash algorithms by testing detection and crack resistance.
7. **Education** — Learn about different hash algorithms, their properties, and relative strengths in a hands-on environment.

---

## Development

### Setup

```bash
git clone https://github.com/cysec-don/DonHash.git
cd DonHash
pip install -e ".[dev]"
```

### Running tests

```bash
# Run all tests with coverage
pytest

# Run a specific test file
pytest tests/test_engine.py

# Run with verbose output
pytest -v

# Run with parallel execution
pytest -n auto
```

### Test suite

The test suite has 836 passing tests across 9 files:

| File | Tests | Focus |
|------|-------|-------|
| `test_hash_db.py` | 13 | Registry integrity: 491 count, no duplicates, valid categories |
| `test_engine.py` | 60+ | RFC test vectors for MD5/SHA1/SHA256/SHA512/SHA3/BLAKE2/MD4/NTLM/MySQL/CRC/HMAC |
| `test_md4.py` | 15 | Full RFC 1320 suite (7 vectors) + avalanche/determinism properties |
| `test_detector.py` | 20+ | Common hashes, prefix hashes, MySQL star prefix, empty input, priority ranking |
| `test_cracker.py` | 18 | Single+multi-threaded crack, not-found, NTLM, salted, unknown type, detect-only |
| `test_output.py` | 25+ | All 6 formats, JSON structure, CSV columns, HTML well-formed, XSS escape verification |
| `test_cli.py` | 20+ | Every CLI flag, exit codes, output formats, subprocess invocation |
| `test_integration.py` | 15+ | End-to-end MD5/NTLM/SHA256, performance benchmarks, 100K-entry wordlist |
| `test_all_hash_types.py` | 700+ | Parametrized smoke tests for all 491 hash types |

### Linting and formatting

```bash
# Lint
ruff check src tests

# Auto-fix
ruff check --fix src tests

# Format
ruff format src tests

# Check formatting without applying
ruff format --check src tests
```

### Type checking

```bash
mypy src/donhash
```

### Building

```bash
# Build sdist + wheel
python -m build

# Check package metadata
twine check dist/*

# Install from built wheel
pip install dist/donhash-*.whl
```

### Pre-commit hooks

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

## Architecture

DonHash is structured as a 7-module Python package:

```
src/donhash/
├── __init__.py        # Package metadata (__version__, __author__)
├── __main__.py        # python -m donhash entry point
├── _hash_db.py        # 491-type registry with impl status (compute/crypt/salted/detect)
├── _noncrypto.py      # CRC, FNV, DJB2, SDBM, Jenkins, ELF, Adler-32, Java hash code
├── _engine.py         # compute_hash, compute_crypt_hash, pure-Python MD4
├── detector.py        # Length + prefix + priority detection
├── cracker.py         # Streaming multi-threaded cracker
├── output.py          # 6 output formats (XSS-safe HTML)
└── cli.py             # argparse CLI
```

### Design principles

1. **Honesty over marketing** — Every hash type is labeled with its actual implementation level. No silent failures.
2. **Pure-Python by default** — Zero required runtime dependencies. Optional extras unlock more hash types.
3. **Stream, don't buffer** — The multi-threaded cracker reads the wordlist in 4,096-line batches, keeping memory bounded.
4. **Test what you ship** — 836 tests including RFC test vectors, XSS verification, end-to-end subprocess invocation, and parametrized smoke tests for every hash type.
5. **Fail loudly** — Bugs in the codebase (like the original `passlib.hash.hasattr` typo that silently broke PBKDF2) are caught by tests, not hidden by broad `except Exception: return None`.

### Why pure-Python MD4?

NTLM hashes (`MD4(UTF-16LE(password))`) are extremely common in Windows password audits. OpenSSL 3.0+ moved MD4 to the "legacy" provider, which is often not enabled by default — meaning `hashlib.new("md4", ...)` fails on many modern systems. DonHash ships a verified pure-Python MD4 (passes all 7 RFC 1320 test vectors) so NTLM cracking works everywhere.

---

## Security Notes

- **HTML output is XSS-safe** — All user-supplied fields (hash, password, type, category, error) are escaped via `html.escape(..., quote=True)`. Verified by automated tests.
- **No shell execution** — DonHash never calls `subprocess`, `os.system`, or `eval`. All hashing is pure-Python function calls.
- **No network access** — DonHash never makes network requests. All work is local.
- **No telemetry** — DonHash doesn't phone home. No usage statistics, no version checks, no auto-update.
- **Path safety** — File paths come from CLI args (user-controlled). No path traversal risk because the user is the one running the tool.
- **Constant-time hash comparison** — Not implemented. DonHash is a password cracker, not an authentication system; the threat model doesn't require constant-time comparison.
- **Optional dependencies** — bcrypt, argon2-cffi, passlib, pycryptodome are all well-known, actively-maintained libraries. Verify checksums when installing.

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes ONLY**. Unauthorized use of this tool to crack passwords or hashes without explicit permission from the system owner is **ILLEGAL and UNETHICAL**. The author assumes no liability for misuse of this software.

Always obtain proper authorization before testing any systems. By using DonHash, you agree to comply with all applicable local, state, national, and international laws regarding computer security and privacy.

If you're unsure whether your use case is authorized, **it probably isn't** — get written permission first.

---

## Changelog

### v2.1.0 (2026-06-25) — Deep audit & bug-fix release

**16 critical/high bug fixes** from a line-by-line audit:

- **Fixed pure-Python MD4** — now passes all 7 RFC 1320 test vectors (was producing wrong output, breaking NTLM)
- **Fixed CRC-32B** — now matches CRC-32/BZIP2 check value `0xfc891918` (was using wrong init/xorout)
- **Fixed CRC-32Q** — now matches CRC-32Q check value `0x3010bf7f` (was missing `init=0`)
- **Fixed Adler-32** — was a placeholder returning CRC-32; now correctly returns Adler-32
- **Fixed `passlib-pbkdf2-*` always returning None** — `passlib.hash.hasattr` typo removed
- **Fixed `Django(bcrypt)` always returning None** — `parts[1]` was empty due to `$$` separator
- **Fixed PHPass / WordPress-phpass / phpBB3** — now uses `passlib.hash.phpass.verify()` instead of auto-generating random salt
- **Fixed `passlib-scrypt`** — added handler (was falling through to None)
- **Fixed MySQL323 unicode handling** — iterates UTF-8 bytes (matching MySQL's C impl), not Python codepoints
- **Fixed OSX-10.4** — `bytes.fromhex()` now wrapped in try/except for invalid salt
- **Fixed HMAC-RIPEMD160(pass)** — was swapping key/message when salt was empty
- **Fixed HMAC-Streebog-* / HMAC-RIPEMD160** — added try/except for OpenSSL legacy provider
- **Fixed MySQL4.1 detection false positives** — strict regex (was matching any string starting with `*`)
- **Fixed detector false positives** — single-character prefixes (`*`, `_`) no longer match arbitrary strings
- **Fixed multi-threaded cracker** — eliminated post-loop batch serialization (workers no longer idle); `attempts` count is now deterministic
- **Removed dead code** — unreachable PostgreSQL-MD5 block in `compute_crypt_hash`

**CLI improvements:**

- Errors now route to stderr (was stdout — broke piping)
- `--category N` validated unconditionally (was only checked with `--list-types`)
- Wordlist-not-found error is now actionable (tells user to use `-w`)
- `donhash --threads 10` (no `-H`/`-f`) now exits 2 with usage error (was silently exiting 0)
- Banner delays removed (was 3+ seconds of `time.sleep()`)

**Test suite:**

- 836 passing tests, 24 skipped (optional deps), 77% line coverage
- New: `test_md4.py` — full RFC 1320 suite
- New: `test_all_hash_types.py` — parametrized smoke tests for all 491 types
- New: XSS escape verification for HTML output
- New: End-to-end subprocess invocation tests

**Infrastructure:**

- GitHub Actions CI on Python 3.10, 3.11, 3.12, 3.13
- Pre-commit hooks (ruff + standard hooks)
- `pyproject.toml` with hatchling backend (PEP 517/518/621)
- mypy type checking (passes clean)
- ruff lint (passes clean)

### v2.0.0 (2026-06-25) — Major refactor

- Split 1,860-line monolith into 7-module Python package
- Added `pyproject.toml`, packaging, `donhash` entry point
- Removed `crypt` module dependency (Python 3.13+ compatible)
- Added `--no-banner`, `--version` flags
- Added `impl` status labels (`compute`/`crypt`/`salted`/`detect-only`)
- Added streaming multi-threaded cracker (constant memory)
- Added XSS-safe HTML output
- Fixed 16 critical bugs (see audit report)
- Added 836 tests

### v1.1 (original)

- Single-file `donhash.py` (1,860 lines)
- Multi-threaded cracking with `-T` flag
- Multi-format output (`-o` with `--format`)
- Splash screen

### v1.0 (original)

- Initial release
- 491 hash types registered, ~131 with working implementations
