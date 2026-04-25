# DonHash v1.1

**Advanced Hash Detector & Cracker** — 500+ hash types across 30 categories, with multi-format output support.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Hash Types](https://img.shields.io/badge/Hash%20Types-500+-orange)
![Version](https://img.shields.io/badge/Version-1.1-cyan)

## Author

**CySec Don** — [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

---

## Features

- **500+ hash types** across 30 detection categories
- **Multi-threaded cracking** with configurable thread count (1-32)
- **Auto-detection** of hash types by length, prefix, and character set
- **Dictionary attack** with customizable wordlist (default: rockyou.txt)
- **Compressed wordlist support** — handles `.gz` files transparently
- **Batch mode** — crack multiple hashes from a file at once
- **Multi-format output** — save results in 7 formats: `txt`, `json`, `csv`, `html`, `xml`, `markdown`, `yaml`
- **Timeout support** — set max cracking time per hash
- **Pure-Python MD4** — NTLM/NT cracking works even on OpenSSL 3.0+
- **Metasploit-style splash screen** with cyberpunk aesthetic

## What's New in v1.1

- **`-o` / `--output` flag** — Write cracking results to a file
- **`--format` flag** — Choose output format from 7 supported formats:
  - `txt` — Plain text with headers (default)
  - `json` — Structured JSON with metadata
  - `csv` — Comma-separated values (spreadsheet-friendly)
  - `html` — Styled HTML report with dark cyberpunk theme
  - `xml` — XML document with structured results
  - `markdown` — GitHub-flavored Markdown table
  - `yaml` — YAML serialization
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
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 8 -v
```

### Output to File (v1.1+)

Save cracking results to a file in your preferred format:

```bash
# Save as plain text (default)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.txt

# Save as JSON
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.json --format json

# Save as CSV (for spreadsheet import)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.csv --format csv

# Save as HTML report (dark themed, styled)
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o report.html --format html

# Save as XML
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.xml --format xml

# Save as Markdown table
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.md --format markdown

# Save as YAML
python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -o results.yaml --format yaml
```

### Batch Mode with Output

```bash
# Crack hashes from a file and export as JSON
python3 donhash.py -f hashes.txt -w rockyou.txt -o batch_results.json --format json

# Batch crack and generate HTML report
python3 donhash.py -f hashes.txt -w rockyou.txt -o report.html --format html -v

# Batch crack and save as CSV for analysis
python3 donhash.py -f hashes.txt -w rockyou.txt -o results.csv --format csv
```

### Salted Hashes

```bash
# Provide salt for salted hash types
python3 donhash.py -H <hash> -t "md5(pass.salt)" -s mysalt

# PostgreSQL-MD5 (salt = username)
python3 donhash.py -H md5<hash> -t PostgreSQL-MD5 -s postgres
```

### Information & Listing

```bash
# List all 30 categories with hash counts
python3 donhash.py --list-categories

# List all hash types
python3 donhash.py --list-types

# List hash types for a specific category
python3 donhash.py --list-types --category 3

# Show wordlist statistics
python3 donhash.py --wordlist-info rockyou.txt
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-H`, `--hash` | Single hash to crack |
| `-f`, `--file` | File with hashes (one per line) |
| `-w`, `--wordlist` | Path to wordlist (default: rockyou.txt). Supports `.gz` |
| `-t`, `--type` | Force a specific hash type |
| `-s`, `--salt` | Salt for salted hash types |
| `-v`, `--verbose` | Show progress while cracking |
| `-T`, `--threads` | Number of threads (default: 4, max: 32) |
| `--no-thread` | Disable multi-threading |
| `--timeout` | Max cracking time in seconds per hash |
| `-o`, `--output` | Save results to file (format determined by `--format`) |
| `--format` | Output format: `txt`, `json`, `csv`, `html`, `xml`, `markdown`, `yaml` (default: `txt`) |
| `--detect-only` | Only detect hash type(s) |
| `--list-categories` | List all 30 categories |
| `--list-types` | List all hash types |
| `--category` | Filter by category number (1-30) |
| `--wordlist-info` | Show wordlist statistics |

## Output Format Examples

### JSON Output

```json
{
  "tool": "DonHash",
  "version": "1.1",
  "author": "CySec Don",
  "timestamp": "2026-04-25 10:49:05",
  "total_hashes": 1,
  "cracked": 1,
  "results": [
    {
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "hash_type": "MD5",
      "password": "password",
      "category": "MD Family",
      "attempts": 1,
      "time": 0.00,
      "speed": 1486
    }
  ]
}
```

### CSV Output

```csv
hash,hash_type,password,category,status,attempts,time,speed
5f4dcc3b5aa765d61d8327deb882cf99,MD5,password,MD Family,CRACKED,1,0.00,1486
```

### Markdown Output

```markdown
| # | Hash | Type | Password | Category | Status | Attempts | Time | Speed |
|---|------|------|----------|----------|--------|----------|------|-------|
| 1 | `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | **password** | MD Family | CRACKED | 1 | 0.00s | 1,486 h/s |
```

### HTML Output

The HTML format generates a fully styled, dark-themed report with a cyberpunk aesthetic that matches the DonHash splash screen. It includes:
- Responsive table layout
- Color-coded cracked/not-found status
- Monospace hash display with gold coloring
- Summary statistics at the bottom
- Footer with disclaimer

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
$ python3 donhash.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5 -w wordlist.txt

  ~~ DonHash Splash Screen ~~

[*] Using forced hash type: MD5
[*] Starting DonHash crack for MD5 [MD Family & Variants]...
[*] Target: 5f4dcc3b5aa765d61d8327deb882cf99
[*] Wordlist: wordlist.txt (14,344,391 entries)
[*] Mode: Multi-threaded (4 threads)

[+] HASH CRACKED!
    Password : password
    Hash Type: MD5
    Category : MD Family & Variants
    Attempts : 1
    Time     : 0.00s
    Speed    : 1,486 hash/sec
```

```
$ python3 donhash.py -f hashes.txt -o report.html --format html -v

[*] Loaded 5 hash(es) from hashes.txt
[*] Starting DonHash crack for SHA-256 [SHA-2 Family]...
[+] HASH CRACKED!
    Password : letmein
...
[+] Results saved to: report.html (format: html)
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
