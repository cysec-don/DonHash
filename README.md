# DonHash v1.1

**Advanced Hash Detector & Cracker** — 500+ hash types across 30 categories, multi-threaded cracking, and multi-format output.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Hash Types](https://img.shields.io/badge/Hash%20Types-500+-orange)
![Version](https://img.shields.io/badge/Version-1.1-cyan)

## Author

**CySec Don** — [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

---

## Features

- **500+ hash types** across 30 detection categories
- **Multi-threaded cracking** with configurable thread count (1-100, default: 5)
- **Auto-detection** of hash types by length, prefix, and character set
- **Dictionary attack** with customizable wordlist (default: rockyou.txt)
- **Batch mode** — crack multiple hashes from a file at once
- **Multi-format output** — save results in 6 formats: `txt`, `json`, `csv`, `html`, `xml`, `md`
- **Auto-format detection** — output format inferred from file extension
- **Pure-Python MD4** — NTLM/NT cracking works even on OpenSSL 3.0+
- **Metasploit-style splash screen** with cyberpunk aesthetic

## What's New in v1.1

- **Fixed splash screen** — ASCII art now clearly displays "DONHASH"
- **`-T` / `--threads` flag** — User-specified thread count from 1-100 (default: 5)
- **`-o` / `--output` flag** — Write cracking results to a file
- **`--format` flag** — Choose output format from 6 supported formats:
  - `txt` — Plain text with headers (default)
  - `json` — Structured JSON with metadata
  - `csv` — Comma-separated values (spreadsheet-friendly)
  - `html` — Styled HTML report with dark cyberpunk theme
  - `xml` — XML document with structured results
  - `md` — GitHub-flavored Markdown table
- Auto-detection of format from file extension (e.g., `-o results.json` → JSON)
- Version bumped to 1.1

## Supported Hash Categories

| # | Category | # | Category |
|---|----------|---|----------|
| 01 | CRC / Checksum | 16 | Cisco / Network / Firewall |
| 02 | Non-Cryptographic | 17 | Network Protocols |
| 03 | MD Family & Variants | 18 | MS Office / PDF / Archives |
| 04 | SHA-1 & Variants | 19 | Archives & Documents |
| 05 | SHA-2 Family | 20 | TrueCrypt / VeraCrypt |
| 06 | SHA-3 / Keccak | 21 | LUKS / DiskCryptor / FDE |
| 07 | BLAKE Family | 22 | Apple / macOS / iOS |
| 08 | RIPEMD/Tiger/Whirlpool/Skein/GOST | 23 | Android / Mobile |
| 09 | HMAC Variants | 24 | Cryptocurrency / Blockchain |
| 10 | KDF / yescrypt | 25 | LDAP / Directory Services |
| 11 | Unix / Linux Crypt | 26 | Password Managers / Vaults |
| 12 | Windows Authentication | 27 | Application / Protocol / Other |
| 13 | Database Hashes | 28 | Legacy Variants |
| 14 | CMS / Web Applications | 29 | More Cryptographic Functions |
| 15 | More CMS / Frameworks | 30 | Signatures |

## Installation

```bash
# Clone the repository
git clone https://github.com/cysec-don/DonHash.git
cd DonHash

# Make executable
chmod +x donhash.py

# Optional: Install bcrypt/argon2 support
pip install bcrypt argon2-cffi passlib
```

## Usage

### Basic Usage

```bash
# Detect hash type only
python3 donhash.py --detect-only -H 5f4dcc3b5aa765d61d8327deb882cf99

# Crack a single hash (auto-detect type)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99

# Crack with custom wordlist
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w my_wordlist.txt

# Force a specific hash type
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5

# Multi-threaded cracking with verbose output
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 20 -v
```

### Threading Control (v1.1+)

Control the number of threads used for cracking. Default is 5 threads. Range: 1-100.

```bash
# Use 10 threads
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 10

# Maximum threads for speed
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 100

# Single-threaded (for debugging or crypt-type hashes)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 1
```

> **Note:** Crypt-type hashes (bcrypt, MD5-Crypt, SHA-512-Crypt, etc.) automatically use single-threaded mode because they require the full hash context for `crypt.crypt()`.

### Output to File (v1.1+)

Save cracking results to a file in your preferred format:

```bash
# Save as plain text (auto-detected from .txt extension)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.txt

# Save as JSON (auto-detected from .json extension)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.json

# Save as CSV (for spreadsheet import)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.csv

# Save as HTML report (dark themed, styled)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o report.html

# Save as XML
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.xml

# Save as Markdown table
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.md

# Explicitly specify format (overrides extension)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o output.dat --format json
```

### Batch Mode with Output

```bash
# Crack hashes from a file and export as JSON
python3 donhash.py -f hashes.txt -w rockyou.txt -o batch_results.json

# Batch crack with threading and generate HTML report
python3 donhash.py -f hashes.txt -w rockyou.txt -o report.html -T 10 -v

# Batch crack and save as CSV for analysis
python3 donhash.py -f hashes.txt -w rockyou.txt -o results.csv --format csv
```

### Salted Hashes

```bash
# Provide salt for salted hash types
python3 donhash.py -H <hash> -t "md5(pass.salt)" -s mysalt
```

### Information & Listing

```bash
# List all 30 categories with hash counts
python3 donhash.py --list-categories

# List all hash types
python3 donhash.py --list-types

# List hash types for a specific category
python3 donhash.py --list-types --category 3
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-H`, `--hash` | Single hash to crack |
| `-f`, `--file` | File with hashes (one per line) |
| `-w`, `--wordlist` | Path to wordlist (default: rockyou.txt) |
| `-t`, `--type` | Force a specific hash type |
| `-s`, `--salt` | Salt for salted hash types |
| `-T`, `--threads` | Number of threads for cracking (1-100, default: 5) |
| `-o`, `--output` | Save results to file (format auto-detected or set via `--format`) |
| `--format` | Output format: `txt`, `json`, `csv`, `html`, `xml`, `md` |
| `-v`, `--verbose` | Show progress while cracking |
| `--detect-only` | Only detect hash type(s) |
| `--list-categories` | List all 30 categories |
| `--list-types` | List all hash types |
| `--category` | Filter by category number (1-30) |

## Output Format Examples

### JSON Output

```json
{
  "tool": "DonHash",
  "version": "1.1",
  "generated": "2026-04-25T10:49:05.123456",
  "results": [
    {
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "type": "MD5",
      "category": "MD Family & Variants",
      "status": "cracked",
      "password": "password",
      "attempts": 1,
      "time": 0.0,
      "speed": 1486.0
    }
  ],
  "summary": {
    "total": 1,
    "cracked": 1,
    "not_found": 0
  }
}
```

### CSV Output

```csv
hash,type,category,status,password,attempts,time,speed
5f4dcc3b5aa765d61d8327deb882cf99,MD5,MD Family & Variants,cracked,password,1,0.0,1486.0
```

### Markdown Output

```markdown
# DonHash v1.1 - Cracking Results

**Generated:** 2026-04-25 10:49:05

**Summary:** 1/1 cracked (100%)

| Hash | Type | Category | Status | Password | Attempts | Time | Speed |
|------|------|----------|--------|----------|----------|------|-------|
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | MD Family & Variants | cracked | password | 1 | 0.0s | 1,486 h/s |
```

### HTML Output

The HTML format generates a fully styled, dark-themed report with a cyberpunk aesthetic that matches the DonHash splash screen. It includes:
- Responsive table layout
- Color-coded cracked/not-found status
- Monospace hash display
- Summary statistics
- Footer with tool info

### XML Output

```xml
<?xml version='1.0' encoding='utf-8'?>
<donhash-results version="1.1" generated="2026-04-25T10:49:05">
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
    <time>0.0</time>
    <speed>1486.0</speed>
  </result>
</donhash-results>
```

## Use Cases

1. **Penetration Testing** — Crack password hashes recovered from a target during an authorized penetration test to demonstrate weak password usage
2. **Security Auditing** — Audit your organization's password policies by testing hash dumps against common wordlists
3. **CTF Competitions** — Quickly identify and crack hash challenges in Capture The Flag security competitions
4. **Digital Forensics** — Identify unknown hash formats and attempt recovery during forensic investigations
5. **Password Research** — Study hash algorithm behavior, compare cracking speeds across different hash types
6. **Compliance Testing** — Verify that your systems are using strong, salted hash algorithms by testing detection and crack resistance
7. **Education** — Learn about different hash algorithms, their properties, and relative strengths in a hands-on environment

## Examples

```
$ python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5 -w wordlist.txt -T 10

  ~~ DonHash v1.1 Splash Screen ~~

[*] Using forced hash type: MD5
[*] Starting crack for MD5 [MD Family & Variants]...
[*] Target: 5f4dcc3b5aa765d61d8327deb882cf99
[*] Wordlist: wordlist.txt (14,344,391 entries)
[*] Threads: 10

[+] HASH CRACKED!
    Password : password
    Hash Type: MD5
    Category : MD Family & Variants
    Attempts : 1
    Time     : 0.00s
    Speed    : 1,486 hash/sec
    Threads  : 10
```

```
$ python3 donhash.py -f hashes.txt -o report.html -T 20 -v

[*] Loaded 5 hash(es) from hashes.txt
[*] Starting crack for SHA-256 [SHA-2 Family]...
[*] Threads: 20
[+] HASH CRACKED!
    Password : letmein
...
[+] Results written to: report.html (html format)
```

## Requirements

- **Python 3.8+**
- Optional: `bcrypt` (for bcrypt hash cracking)
- Optional: `argon2-cffi` (for Argon2 hash cracking)
- Optional: `passlib` (for phpass/APR1 hash cracking)

## License

MIT License — Free to use, modify, and distribute.

## Disclaimer

This tool is intended for **authorized security testing and educational purposes ONLY**. Unauthorized use of this tool to crack passwords or hashes without explicit permission from the system owner is **ILLEGAL and UNETHICAL**. The author assumes no liability for misuse of this software. Always obtain proper authorization before testing any systems. By using DonHash, you agree to comply with all applicable local, state, national, and international laws regarding computer security and privacy.
