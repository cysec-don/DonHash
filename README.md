# DonHash v3.0

**Advanced Hash Detector & Cracker** — 491+ hash types across 30 categories.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Hash Types](https://img.shields.io/badge/Hash%20Types-491+-orange)

## Author

**CySec Don** — [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

---

## Features

- **491+ hash types** across 30 detection categories
- **Multi-threaded cracking** with configurable thread count (1-32)
- **Auto-detection** of hash types by length, prefix, and character set
- **Dictionary attack** with customizable wordlist (default: rockyou.txt)
- **Compressed wordlist support** — handles `.gz` files transparently
- **Batch mode** — crack multiple hashes from a file at once
- **Output logging** — save cracked results to file
- **Timeout support** — set max cracking time per hash
- **Pure-Python MD4** — NTLM/NT cracking works even on OpenSSL 3.0+
- **Metasploit-style splash screen** with cyberpunk aesthetic

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

### Batch Mode

```bash
# Crack hashes from a file (one hash per line)
python3 donhash.py -f hashes.txt -w rockyou.txt -v

# With output logging
python3 donhash.py -f hashes.txt -w rockyou.txt -o cracked.txt
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
| `-o`, `--output` | Save cracked results to file |
| `--detect-only` | Only detect hash type(s) |
| `--list-categories` | List all 30 categories |
| `--list-types` | List all hash types |
| `--category` | Filter by category number (1-30) |
| `--wordlist-info` | Show wordlist statistics |

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

## Requirements

- **Python 3.8+**
- Optional: `bcrypt` (for bcrypt hash cracking)
- Optional: `argon2-cffi` (for Argon2 hash cracking)
- Optional: `passlib` (for phpass/APR1 hash cracking)

## License

MIT License — Free to use, modify, and distribute.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. The author is not responsible for any misuse of this software. Always ensure you have proper authorization before testing any systems.
