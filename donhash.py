#!/usr/bin/env python3
"""
DonHash v1.1 - Hash Detector & Cracker
======================================
Detects 500+ hash types and cracks them using a wordlist (default: rockyou.txt).
Supports custom wordlists, multi-threaded cracking, and 30 hash categories.

30 Categories: CRC, Non-Crypto, MD Family, SHA-1/Variants, SHA-2, SHA-3/Keccak,
BLAKE, RIPEMD/Tiger/Whirlpool/Skein/GOST, HMAC, KDF/yescrypt, Unix Crypt,
Windows Auth, Database, CMS/Web, More Frameworks, Cisco/Network, Network Protocols,
MS Office/PDF, Archives, TrueCrypt/VeraCrypt, LUKS/FDE, Apple/macOS,
Android/Mobile, Cryptocurrency, LDAP, Password Managers, App/Protocol,
Legacy Variants, More Crypto, Signatures

Author: CySec Don (cysecdon@gmail.com)
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import re
import binascii
import base64
import struct
import hmac as hmac_mod
import math
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Callable


# ──────────────────────────────────────────────
#  ANSI Colors
# ──────────────────────────────────────────────
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ──────────────────────────────────────────────
#  Splash Screen
# ──────────────────────────────────────────────
def print_banner():
    R  = Colors.RED;    G  = Colors.GREEN;   Y  = Colors.YELLOW
    B  = Colors.BLUE;   M  = Colors.MAGENTA; C  = Colors.CYAN
    W  = Colors.WHITE;  BD = Colors.BOLD;    DM = Colors.DIM
    RS = Colors.RESET

    import re as _re
    def _vis_len(s): return len(_re.sub(r'\033\[[0-9;]*m', '', s))
    def _pad(s, w): return s + ' ' * max(0, w - _vis_len(s))

    COL = 26
    print()
    print(f"  {C}{BD}{'~' * 72}{RS}")
    print()

    logo = [
        f"  {C}{BD}             /\\{RS}",
        f"  {C}{BD}            /  \\{RS}",
        f"  {C}{BD}           /    \\{RS}",
        f"  {C}{BD}          / {Y}{BD}.--.{C} \\{RS}",
        f"  {C}{BD}         /  {Y}{BD}|  |{C}  \\{RS}",
        f"  {C}{BD}        /   {Y}{BD}|  |{C}   \\{RS}",
        f"  {C}{BD}       / {R}{BD}._{Y}{BD}|__|{R}{BD}_.{C} \\{RS}",
        f"  {C}{BD}      /  {R}{BD}/ {Y}{BD}||{R}{BD} \\  {C} \\{RS}",
        f"  {C}{BD}     /  {R}{BD}/  {Y}{BD}||{R}{BD}  \\  {C} \\{RS}",
        f"  {C}{BD}    / {R}{BD}/   {Y}{BD}||{R}{BD}   \\  {C} \\{RS}",
        f"  {C}{BD}   / {R}{BD}/    {Y}{BD}||{R}{BD}    \\  {C} \\{RS}",
        f"  {C}{BD}  / {R}{BD}/_____{Y}{BD}||{R}{BD}_____\\  {C} \\{RS}",
        f"  {C}{BD} /___________________\\{RS}",
        f"  {Y}{BD} \\{R}{BD}==================={Y}{BD}/{RS}",
        f"  {R}{BD}  \\_________________/{RS}",
    ]
    right = [
        f"  {C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2557  {C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2557{C}{BD}\u2588\u2588\u2557  {C}{BD}\u2588\u2588\u2557{C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557{C}{BD}\u2588\u2588\u2557  {C}{BD}\u2588\u2588\u2557 {C}{BD}\u2588\u2588\u2588\u2588\u2588\u2557 {C}{BD}\u2588\u2588\u2588\u2588\u2557   {C}{BD}\u2588\u2588\u2557{RS}",
        f"  {C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2550\u2550\u255D {C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2557{C}{BD}\u2588\u2551 {C}{BD}\u2588\u2551\u255D{C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2550\u2550\u255D{C}{BD}\u2588\u2551  {C}{BD}\u2588\u2551{C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2550\u2551{C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2551  {C}{BD}\u2588\u2551{RS}",
        f"  {C}{BD}\u2588\u2551  {C}{BD}\u2588\u2588\u2588\u2557{C}{BD}\u2588\u2551     {C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255D {C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2557{C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551{C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551{C}{BD}\u2588\u2551\u2550\u2588\u2588\u2557 {C}{BD}\u2588\u2551{RS}",
        f"  {C}{BD}\u2588\u2551   {C}{BD}\u2588\u2551{C}{BD}\u2588\u2551     {C}{BD}\u2588\u2551\u2550\u2550\u2588\u2551\u255D {C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u255D{C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2588\u2551{C}{BD}\u2588\u2551\u2550\u2550\u2550\u2550\u2550\u2551{C}{BD}\u2588\u2551\u255D {C}{BD}\u2588\u2588\u2557{C}{BD}\u2588\u2551{RS}",
        f"  {C}{BD}\u255A\u2588\u2588\u2588\u2588\u2588\u2551\u255D{C}{BD}\u255A\u2588\u2588\u2588\u2588\u2588\u2557{C}{BD}\u2588\u2551  {C}{BD}\u2588\u2551\u255D{C}{BD}\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557{C}{BD}\u2588\u2551  {C}{BD}\u2588\u2551{C}{BD}\u2588\u2551  {C}{BD}\u2588\u2551{C}{BD}\u2588\u2551 {C}{BD}\u255A\u2588\u2588\u2588\u2551{RS}",
        f"  {C}{BD} \u255A\u2550\u2550\u2550\u2550\u2550\u255D  {C}{BD}\u255A\u2550\u2550\u2550\u2550\u2550\u255D{C}{BD}\u255A\u2550\u255D  {C}{BD}\u255A\u2550\u255D{C}{BD}\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u255D{C}{BD}\u255A\u2550\u255D  {C}{BD}\u255A\u2550\u255D{C}{BD}\u255A\u2550\u255D  {C}{BD}\u255A\u2550\u255D{C}{BD}\u255A\u2550\u255D  {C}{BD}\u255A\u2550\u2550\u2550\u255D{RS}",
        f"  ",
        f"  {DM}       HASH DETECTOR & CRACKER{RS}",
        f"  ",
        f"  {C}{BD}[+]{RS} {W}{BD}500+ HASH TYPES SUPPORTED{RS}     {DM}fingerprint{RS}",
        f"  {C}{BD}[+]{RS} {W}{BD}30 DETECTION CATEGORIES{RS}       {DM}target{RS}",
        f"  {C}{BD}[+]{RS} {W}{BD}MULTI-THREADED CRACKING{RS}      {DM}hexagon{RS}",
    ]
    for i in range(max(len(logo), len(right))):
        l = _pad(logo[i], COL) if i < len(logo) else ' ' * COL
        r = right[i] if i < len(right) else ""
        print(f"{l}  {r}")
    print()

    print(f"  {C}{BD}+------------------------------------------------------------+{RS}")
    print(f"  {C}{BD}|{RS}  {C}{BD}[*]{RS} {W}DonHash - Hash Detector & Cracker{RS}  {C}{BD}|{RS}  {G}{BD}Author : CySec Don{RS}            {C}{BD}|{RS}")
    print(f"  {C}{BD}|{RS}  {C}{BD}[*]{RS} {W}Detect & crack hashes w/ wordlists{RS} {C}{BD}|{RS}  {G}{BD}Email  : cysecdon@gmail.com{RS}  {C}{BD}|{RS}")
    print(f"  {C}{BD}|{RS}  {C}{BD}[*]{RS} {W}500+ hash algorithms supported{RS}    {C}{BD}|{RS}  {Y}{BD}Version: v1.1{RS}                  {C}{BD}|{RS}")
    print(f"  {C}{BD}+------------------------------------------------------------+{RS}")
    print()

    cats = [
        ("01 CRC / Checksum", "02 Non-Crypto", "03 MD Family", "04 SHA-1/Variants"),
        ("05 SHA-2 Family", "06 SHA-3/Keccak", "07 BLAKE Family", "08 RIPEMD/Tiger/Whirl"),
        ("09 HMAC Variants", "10 KDF/yescrypt", "11 Unix Crypt", "12 Windows Auth"),
        ("13 Database", "14 CMS/Web App", "15 Frameworks", "16 Cisco/Network"),
        ("17 Net Protocols", "18 MS Office/PDF", "19 Archives", "20 TrueCrypt/VC"),
        ("21 LUKS/FDE", "22 Apple/macOS", "23 Android/Mobile", "24 Cryptocurrency"),
        ("25 LDAP/DirSvc", "26 Pass Managers", "27 App/Protocol", "28 Legacy Variants"),
        ("29 More Crypto", "30 Signatures", "", ""),
    ]
    print(f"  {R}{BD}+------------------------------------------------------------+{RS}")
    print(f"  {R}{BD}|{RS}  {R}{BD}30 HASH CATEGORIES{RS}                                         {R}{BD}|{RS}")
    print(f"  {R}{BD}+------------------------------------------------------------+{RS}")
    for row in cats:
        parts = [f"{G}{c}{RS}" for c in row if c]
        line = "  |  ".join(parts)
        print(f"  {R}{BD}|{RS}  {line}")
    print(f"  {R}{BD}+------------------------------------------------------------+{RS}")
    print()

    print(f"  {C}{BD}{'~' * 72}{RS}")
    print(f"   {R}{BD}>>>{RS} {W}DETECT{RS}  {C}{BD}::{RS}  {W}CRACK{RS}  {C}{BD}::{RS}  {W}REVEAL{RS}  {C}{BD}::{RS}  {DM}v1.1{RS}")
    print(f"  {C}{BD}{'~' * 72}{RS}")
    print()

    for item in ["Initializing hash engine", "Loading 500+ detection modules", "Preparing wordlist handler", "Ready"]:
        print(f"  {Y}{BD}[*]{RS} {W}{item}...{RS}", end="", flush=True)
        time.sleep(0.12)
        for _ in range(3):
            print(f"{Y}.{RS}", end="", flush=True); time.sleep(0.06)
        print(f"  {G}{BD}done{RS}")

    print()
    print(f"  {C}[{RS}", end="", flush=True)
    for _ in range(50):
        time.sleep(0.01); print(f"{G}{BD}#{RS}", end="", flush=True)
    print(f"{C}]{RS}  {G}{BD}100%{RS}")
    print()
    print(f"  {G}{BD}>>>{RS} {W}Type {C}-h{RS} {W}for help or supply a hash to begin.{RS}")
    print()


# ──────────────────────────────────────────────
#  Non-Cryptographic Hash Implementations
# ──────────────────────────────────────────────

def _crc16(data: bytes, poly: int, init: int = 0, xorout: int = 0, refin: bool = False, refout: bool = False) -> int:
    """Generic CRC-16 calculator."""
    crc = init
    for byte in data:
        if refin:
            byte = int('{:08b}'.format(byte)[::-1], 2)
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    if refout:
        crc = int('{:016b}'.format(crc)[::-1], 2)
    return crc ^ xorout

def _crc32_generic(data: bytes, poly: int, init: int = 0xFFFFFFFF, xorout: int = 0xFFFFFFFF, refin: bool = True, refout: bool = True) -> int:
    """Generic CRC-32 calculator."""
    crc = init
    for byte in data:
        if refin:
            byte = int('{:08b}'.format(byte)[::-1], 2)
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFFFF
    if refout:
        crc = int('{:032b}'.format(crc)[::-1], 2)
    return crc ^ xorout

def _crc64(data: bytes, poly: int, init: int = 0, xorout: int = 0, refin: bool = False, refout: bool = False) -> int:
    """Generic CRC-64 calculator."""
    crc = init
    for byte in data:
        if refin:
            byte = int('{:08b}'.format(byte)[::-1], 2)
        crc ^= byte << 56
        for _ in range(8):
            if crc & 0x8000000000000000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFFFFFFFFFFFF
    if refout:
        crc = int('{:064b}'.format(crc)[::-1], 2)
    return crc ^ xorout

def _reflect_bits(val: int, width: int) -> int:
    return int('{:0{w}b}'.format(val, w=width)[::-1], 2)


def fnv1_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h * 0x01000193) & 0xFFFFFFFF) ^ b
    return h

def fnv1a_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = (h ^ b) * 0x01000193 & 0xFFFFFFFF
    return h

def fnv1_64(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF) ^ b
    return h

def fnv1a_64(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h = (h ^ b) * 0x100000001b3 & 0xFFFFFFFFFFFFFFFF
    return h

def djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h

def sdbm(data: bytes) -> int:
    h = 0
    for b in data:
        h = b + (h << 6) + (h << 16) - h & 0xFFFFFFFF
    return h

def jenkins_one_at_a_time(data: bytes) -> int:
    h = 0
    for b in data:
        h = (h + b) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= (h >> 6)
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11)
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h

def elf_hash(data: bytes) -> int:
    h = 0; g = 0
    for b in data:
        h = (h << 4) + b & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


# ──────────────────────────────────────────────
#  Hash Type Registry
# ──────────────────────────────────────────────
# Format: { "NAME": { "cat": category_number, "desc": description, "hex_len": int_or_None, "prefix": str_or_None } }

HASH_DB: Dict[str, dict] = {}

def _reg(name: str, cat: int, desc: str, hex_len: Optional[int] = None, prefix: Optional[str] = None):
    HASH_DB[name] = {"cat": cat, "desc": desc, "hex_len": hex_len, "prefix": prefix}

# ── Category 1: CRC / Checksum ──
_reg("CRC-16",           1, "CRC-16", 4)
_reg("CRC-16-CCITT",     1, "CRC-16-CCITT", 4)
_reg("CRC-16-IBM",       1, "CRC-16-IBM", 4)
_reg("CRC-16-DNP",       1, "CRC-16-DNP", 4)
_reg("CRC-16-Modbus",    1, "CRC-16-Modbus", 4)
_reg("CRC-16-XMODEM",    1, "CRC-16-XMODEM", 4)
_reg("CRC-16-USB",       1, "CRC-16-USB", 4)
_reg("CRC-16-ZMODEM",    1, "CRC-16-ZMODEM", 4)
_reg("CRC-24",           1, "CRC-24", 6)
_reg("CRC-32",           1, "CRC-32", 8)
_reg("CRC-32B",          1, "CRC-32B", 8)
_reg("CRC-32C",          1, "CRC-32C (Castagnoli)", 8)
_reg("CRC-32-MPEG-2",    1, "CRC-32-MPEG-2", 8)
_reg("CRC-32D",          1, "CRC-32D", 8)
_reg("CRC-32Q",          1, "CRC-32Q", 8)
_reg("CRC-40-GSM",       1, "CRC-40-GSM", 10)
_reg("CRC-64",           1, "CRC-64", 16)
_reg("CRC-64-ECMA",      1, "CRC-64-ECMA", 16)
_reg("CRC-64-ISO",       1, "CRC-64-ISO", 16)
_reg("CRC-64-Jones",     1, "CRC-64-Jones", 16)

# ── Category 2: Non-Cryptographic ──
_reg("Jenkins",          2, "Jenkins hash", 8)
_reg("MurmurHash32",     2, "MurmurHash (32-bit)", 8)
_reg("MurmurHash64",     2, "MurmurHash (64-bit)", 16)
_reg("MurmurHash3",      2, "MurmurHash3", 8)
_reg("FNV-1-32",         2, "FNV-1 (32-bit)", 8)
_reg("FNV-1-64",         2, "FNV-1 (64-bit)", 16)
_reg("FNV-1a-32",        2, "FNV-1a (32-bit)", 8)
_reg("FNV-1a-64",        2, "FNV-1a (64-bit)", 16)
_reg("FNV-132",          2, "FNV-132", 8)
_reg("FNV-164",          2, "FNV-164", 16)
_reg("ELF-32",           2, "ELF-32", 8)
_reg("ELF-64",           2, "ELF-64", 16)
_reg("Joaat",            2, "Jenkins one-at-a-time", 8)
_reg("DJB2",             2, "Bernstein hash (DJB2)", 8)
_reg("SDBM",             2, "SDBM hash", 8)
_reg("Zobrist",          2, "Zobrist hashing", None)
_reg("JavaHashCode",     2, "Java hashCode()", 8)
_reg("CityHash",         2, "CityHash", 16)
_reg("xxHash64",         2, "xxHash (64-bit)", 16)
_reg("xxHash3-128",      2, "xxHash3 (128-bit)", 32)

# ── Category 3: MD Family & Variants ──
_reg("MD2",              3, "MD2", 32)
_reg("MD4",              3, "MD4", 32)
_reg("MD5",              3, "MD5", 32)
_reg("MD6",              3, "MD6", None)
_reg("Half-MD5",         3, "Half MD5", 16)
_reg("Double-MD5",       3, "Double MD5", 32)
_reg("Triple-MD5",       3, "Triple MD5", 32)
_reg("md5(md5(md5($pass)))", 3, "md5(md5(md5(pass)))", 32)
_reg("md5(pass.salt)",   3, "md5(pass.salt)", 32)
_reg("md5(salt.pass)",   3, "md5(salt.pass)", 32)
_reg("md5(unicode(pass).salt)", 3, "md5(unicode(pass).salt)", 32)
_reg("md5(salt.unicode(pass))", 3, "md5(salt.unicode(pass))", 32)
_reg("md5(salt.pass.$salt)", 3, "md5(salt.pass.salt)", 32)
_reg("md5(md5(pass).md5(salt))", 3, "md5(md5(pass).md5(salt))", 32)
_reg("md5(md5(salt).pass)", 3, "md5(md5(salt).pass)", 32)
_reg("md5(salt.md5(pass))", 3, "md5(salt.md5(pass))", 32)
_reg("md5(pass.md5(salt))", 3, "md5(pass.md5(salt))", 32)
_reg("md5(salt.md5(salt.$pass))", 3, "md5(salt.md5(salt.pass))", 32)
_reg("md5(salt.md5(pass.$salt))", 3, "md5(salt.md5(pass.salt))", 32)
_reg("md5(username.0.pass)", 3, "md5(username.0.pass)", 32)
_reg("md5(sha1($pass))", 3, "md5(sha1(pass))", 32)
_reg("md5(strtoupper(md5))", 3, "md5(strtoupper(md5(pass)))", 32)
_reg("md5(sha1(md5($pass)))", 3, "md5(sha1(md5(pass)))", 32)
_reg("MD5(Crypt)",       3, "MD5 Crypt", prefix="$1$")
_reg("MD5(APR)",         3, "MD5(APR)", prefix="$apr1$")

# ── Category 4: SHA-1 & Variants ──
_reg("SHA-0",            4, "SHA-0", 40)
_reg("SHA-1",            4, "SHA-1", 40)
_reg("Double-SHA1",      4, "Double SHA-1", 40)
_reg("Triple-SHA1",      4, "Triple SHA-1", 40)
_reg("sha1(sha1(sha1($pass)))", 4, "sha1(sha1(sha1(pass)))", 40)
_reg("sha1(pass.salt)",  4, "sha1(pass.salt)", 40)
_reg("sha1(salt.pass)",  4, "sha1(salt.pass)", 40)
_reg("sha1(unicode(pass).salt)", 4, "sha1(unicode(pass).salt)", 40)
_reg("sha1(salt.unicode(pass))", 4, "sha1(salt.unicode(pass))", 40)
_reg("sha1(salt.pass.$salt)", 4, "sha1(salt.pass.salt)", 40)
_reg("sha1(md5($pass))", 4, "sha1(md5(pass))", 40)
_reg("sha1(sha1(salt.pass.$salt))", 4, "sha1(sha1(salt.pass.salt))", 40)
_reg("SHA1-Base64",      4, "SHA-1 (Base64)")
_reg("SHA-1(Crypt)",     4, "SHA-1 Crypt", prefix="$sha1$")
_reg("LinkedIn",         4, "LinkedIn (unsalted SHA-1)", 40)
_reg("Netscape-LDAP-SHA", 4, "Netscape LDAP SHA", prefix="{SHA}")
_reg("SSHA1-Base64",     4, "SSHA-1 (Base64)", prefix="{SSHA}")
_reg("sha1(CX)",         4, "sha1(CX)", 40)
_reg("SHA-1(Oracle)",    4, "SHA-1(Oracle)")
_reg("sha1(sha1(pass).salt)", 4, "sha1(sha1(pass).salt)", 40)

# ── Category 5: SHA-2 Family ──
_reg("SHA-224",          5, "SHA-224", 56)
_reg("SHA-256",          5, "SHA-256", 64)
_reg("SHA-384",          5, "SHA-384", 96)
_reg("SHA-512",          5, "SHA-512", 128)
_reg("SHA-512/224",      5, "SHA-512/224", 56)
_reg("SHA-512/256",      5, "SHA-512/256", 64)
_reg("sha256(pass.salt)",  5, "SHA-256(pass.salt)", 64)
_reg("sha256(salt.pass)",  5, "SHA-256(salt.pass)", 64)
_reg("sha512(pass.salt)",  5, "SHA-512(pass.salt)", 128)
_reg("sha512(salt.pass)",  5, "SHA-512(salt.pass)", 128)
_reg("sha256(unicode(pass).salt)", 5, "SHA-256(unicode(pass).salt)", 64)
_reg("sha512(unicode(pass).salt)", 5, "SHA-512(unicode(pass).salt)", 128)
_reg("SHA-256(Crypt)",   5, "SHA-256 Crypt", prefix="$5$")
_reg("SHA-512(Crypt)",   5, "SHA-512 Crypt", prefix="$6$")
_reg("sha256(salt.unicode(pass))", 5, "SHA-256(salt.unicode(pass))", 64)

# ── Category 6: SHA-3 / Keccak ──
_reg("SHA3-224",         6, "SHA3-224", 56)
_reg("SHA3-256",         6, "SHA3-256", 64)
_reg("SHA3-384",         6, "SHA3-384", 96)
_reg("SHA3-512",         6, "SHA3-512", 128)
_reg("SHAKE128",         6, "SHAKE128", None)
_reg("SHAKE256",         6, "SHAKE256", None)
_reg("Keccak-256",       6, "Keccak-256", 64)
_reg("Keccak-512",       6, "Keccak-512", 128)
_reg("Raw-Keccak-256",   6, "Raw Keccak-256", 64)
_reg("Raw-Keccak-512",   6, "Raw Keccak-512", 128)
_reg("SHA3-Keccak",      6, "SHA-3 (Keccak)")
_reg("Keccak-r40-c160",  6, "Keccak[r=40,c=160]")

# ── Category 7: BLAKE Family ──
_reg("BLAKE-256",        7, "BLAKE-256", 64)
_reg("BLAKE-512",        7, "BLAKE-512", 128)
_reg("BLAKE2b",          7, "BLAKE2b", 128)
_reg("BLAKE2b-256",      7, "BLAKE2b-256", 64)
_reg("BLAKE2b-512",      7, "BLAKE2b-512", 128)
_reg("BLAKE2s",          7, "BLAKE2s", 64)
_reg("BLAKE2s-128",      7, "BLAKE2s-128", 32)
_reg("BLAKE2s-256",      7, "BLAKE2s-256", 64)
_reg("BLAKE2bp",         7, "BLAKE2bp", 128)
_reg("BLAKE3-256",       7, "BLAKE3 (256-bit)", 64)
_reg("BLAKE3-512",       7, "BLAKE3-512", 128)

# ── Category 8: RIPEMD, Tiger, Whirlpool, Skein, GOST ──
_reg("RIPEMD-128",       8, "RIPEMD-128", 32)
_reg("RIPEMD-160",       8, "RIPEMD-160", 40)
_reg("RIPEMD-256",       8, "RIPEMD-256", 64)
_reg("RIPEMD-320",       8, "RIPEMD-320", 80)
_reg("Tiger-128",        8, "Tiger-128", 32)
_reg("Tiger-160",        8, "Tiger-160", 40)
_reg("Tiger-192",        8, "Tiger-192", 48)
_reg("Tiger2",           8, "Tiger2", 48)
_reg("Whirlpool",        8, "Whirlpool", 128)
_reg("Whirlpool-T",      8, "Whirlpool-T", 128)
_reg("Skein-256",        8, "Skein-256", 64)
_reg("Skein-512",        8, "Skein-512", 128)
_reg("Skein-1024",       8, "Skein-1024", 256)
_reg("Skein-256(512)",   8, "Skein-256(512)", 128)
_reg("Skein-512(256)",   8, "Skein-512(256)", 64)
_reg("Snefru-128",       8, "Snefru-128", 32)
_reg("Snefru-256",       8, "Snefru-256", 64)
_reg("HAVAL-256",        8, "HAVAL-256", 64)
_reg("GOST-R-34.11-94",  8, "GOST R 34.11-94", 64)
_reg("Streebog-256",     8, "GOST R 34.11-2012 (Streebog-256)", 64)
_reg("Streebog-512",     8, "GOST R 34.11-2012 (Streebog-512)", 128)

# ── Category 9: HMAC Variants ──
_reg("HMAC-MD5(pass)",     9, "HMAC-MD5 (key=pass)", 32)
_reg("HMAC-MD5(salt)",     9, "HMAC-MD5 (key=salt)", 32)
_reg("HMAC-SHA1(pass)",    9, "HMAC-SHA1 (key=pass)", 40)
_reg("HMAC-SHA1(salt)",    9, "HMAC-SHA1 (key=salt)", 40)
_reg("HMAC-SHA256(pass)",  9, "HMAC-SHA256 (key=pass)", 64)
_reg("HMAC-SHA256(salt)",  9, "HMAC-SHA256 (key=salt)", 64)
_reg("HMAC-SHA512(pass)",  9, "HMAC-SHA512 (key=pass)", 128)
_reg("HMAC-SHA512(salt)",  9, "HMAC-SHA512 (key=salt)", 128)
_reg("HMAC-RIPEMD160(pass)", 9, "HMAC-RIPEMD160 (key=pass)", 40)
_reg("HMAC-RIPEMD160(salt)", 9, "HMAC-RIPEMD160 (key=salt)", 40)
_reg("HMAC-Tiger",       9, "HMAC-Tiger", 48)
_reg("HMAC-Whirlpool",   9, "HMAC-Whirlpool", 128)
_reg("HMAC-GOST",        9, "HMAC-GOST", 64)
_reg("HMAC-Streebog-256(pass)", 9, "HMAC-Streebog-256 (key=pass)", 64)
_reg("HMAC-Streebog-256(salt)", 9, "HMAC-Streebog-256 (key=salt)", 64)
_reg("HMAC-Streebog-512(pass)", 9, "HMAC-Streebog-512 (key=pass)", 128)
_reg("HMAC-Streebog-512(salt)", 9, "HMAC-Streebog-512 (key=salt)", 128)
_reg("HMAC-Skein-256",   9, "HMAC-Skein-256", 64)
_reg("HMAC-Skein-512",   9, "HMAC-Skein-512", 128)
_reg("HMAC-SHA3-256",    9, "HMAC-SHA3-256", 64)

# ── Category 10: KDF / yescrypt ──
_reg("yescrypt",         10, "yescrypt", prefix="$y$")
_reg("yescrypt-v1",      10, "yescrypt v1", prefix="$y$1$")
_reg("yescrypt-v2",      10, "yescrypt v2", prefix="$y$2$")
_reg("gost-yescrypt",    10, "gost-yescrypt", prefix="$gy$")
_reg("scrypt",           10, "scrypt", prefix="$scrypt$")
_reg("scrypt-Colin",     10, "scrypt (Colin Percival)", prefix="$7$")
_reg("scrypt-Litecoin",  10, "scrypt (Litecoin)")
_reg("scrypt-Dogecoin",  10, "scrypt (Dogecoin)")
_reg("bcrypt",           10, "bcrypt 2a", prefix="$2a$")
_reg("bcrypt-2b",        10, "bcrypt 2b", prefix="$2b$")
_reg("bcrypt-2x",        10, "bcrypt 2x", prefix="$2x$")
_reg("bcrypt-2y",        10, "bcrypt 2y", prefix="$2y$")
_reg("bcrypt-OpenBSD",   10, "bcrypt-OpenBSD", prefix="$2b$")
_reg("bcrypt(SHA256)",   10, "bcrypt(SHA-256)", prefix="$2b$")
_reg("bcrypt(SHA512)",   10, "bcrypt(SHA-512)", prefix="$2b$")
_reg("PBKDF2-HMAC-MD5",  10, "PBKDF2-HMAC-MD5")
_reg("PBKDF2-HMAC-SHA1", 10, "PBKDF2-HMAC-SHA1")
_reg("PBKDF2-HMAC-SHA256", 10, "PBKDF2-HMAC-SHA256")
_reg("PBKDF2-HMAC-SHA512", 10, "PBKDF2-HMAC-SHA512")
_reg("PBKDF2-HMAC-RIPEMD160", 10, "PBKDF2-HMAC-RIPEMD160")
_reg("Argon2",           10, "Argon2", prefix="$argon2")
_reg("Argon2d",          10, "Argon2d", prefix="$argon2d")
_reg("Argon2i",          10, "Argon2i", prefix="$argon2i")
_reg("Argon2id",         10, "Argon2id", prefix="$argon2id")
_reg("Balloon",          10, "Balloon hashing")

# ── Category 11: Unix / Linux crypt ──
_reg("descrypt",         11, "descrypt (Traditional DES)")
_reg("bigcrypt",         11, "bigcrypt")
_reg("BSDi-Crypt",       11, "BSDi Crypt", prefix="_")
_reg("Crypt16",          11, "Crypt16")
_reg("Unix-DES",         11, "Unix DES")
_reg("Unix-MD5",         11, "Unix MD5", prefix="$1$")
_reg("Unix-Blowfish",    11, "Unix Blowfish", prefix="$2a$")
_reg("Unix-SHA256",      11, "Unix SHA-256", prefix="$5$")
_reg("Unix-SHA512",      11, "Unix SHA-512", prefix="$6$")
_reg("AIX-smd5",         11, "AIX {smd5}", prefix="{smd5}")
_reg("AIX-ssha1",        11, "AIX {ssha1}", prefix="{ssha1}")
_reg("AIX-ssha256",      11, "AIX {ssha256}", prefix="{ssha256}")
_reg("AIX-ssha512",      11, "AIX {ssha512}", prefix="{ssha512}")
_reg("GRUB2-pbkdf2",     11, "GRUB 2 pbkdf2", prefix="grub.pbkdf2")

# ── Category 12: Windows Authentication ──
_reg("LM",               12, "LM hash", 32)
_reg("NTLM",             12, "NTLM hash", 32)
_reg("NT",               12, "NT hash", 32)
_reg("NTLMv1",           12, "NTLMv1")
_reg("NTLMv2",           12, "NTLMv2")
_reg("NetNTLMv1",        12, "NetNTLMv1")
_reg("NetNTLMv1+ESS",    12, "NetNTLMv1+ESS")
_reg("NetNTLMv2",        12, "NetNTLMv2")
_reg("DCC",              12, "Domain Cached Credentials", 32)
_reg("DCC2",             12, "Domain Cached Credentials 2")
_reg("MS-Cache",         12, "MS Cache", 32)
_reg("MS-Cache2",        12, "MS Cache 2", 32)
_reg("SAM",              12, "SAM (LM:NT)")
_reg("WinPhone8-PIN",    12, "Windows Phone 8+ PIN")
_reg("Kerberos-AS-REQ-23", 12, "Kerberos 5 AS-REQ (etype 23)")
_reg("Kerberos-TGS-REP-23", 12, "Kerberos 5 TGS-REP (etype 23)")
_reg("Kerberos-etype17", 12, "Kerberos 5 etype 17")
_reg("Kerberos-etype18", 12, "Kerberos 5 etype 18")

# ── Category 13: Database Hashes ──
_reg("MySQL323",         13, "MySQL 323", 16)
_reg("MySQL4.1",         13, "MySQL 4.1", prefix="*")
_reg("MySQL5.x",         13, "MySQL 5.x", 40)
_reg("MySQL-CR-SHA1",    13, "MySQL Challenge-Response (SHA1)")
_reg("MSSQL-2000",       13, "MSSQL (2000)", prefix="0x0100")
_reg("MSSQL-2005",       13, "MSSQL (2005)", prefix="0x0100")
_reg("MSSQL-2008",       13, "MSSQL (2008)", prefix="0x0100")
_reg("MSSQL-2012",       13, "MSSQL (2012)", prefix="0x0200")
_reg("MSSQL-2014",       13, "MSSQL (2014)", prefix="0x0200")
_reg("MSSQL-2016",       13, "MSSQL (2016)", prefix="0x0200")
_reg("Oracle-7-10g",     13, "Oracle 7-10g")
_reg("Oracle-11g-12c",   13, "Oracle 11g/12c", prefix="S:")
_reg("Oracle-12c+",      13, "Oracle 12c+")
_reg("Oracle-H-Type",    13, "Oracle H: Type")
_reg("Oracle-TM-SHA256", 13, "Oracle Transportation Management (SHA256)")
_reg("PostgreSQL-MD5",   13, "PostgreSQL MD5", prefix="md5")
_reg("PostgreSQL-CR-MD5", 13, "PostgreSQL Challenge-Response (MD5)")
_reg("PostgreSQL-SCRAM",  13, "PostgreSQL SCRAM-SHA-256", prefix="SCRAM-SHA-256$")
_reg("Sybase-ASE",       13, "Sybase ASE")
_reg("SAP-BCODE",        13, "SAP CODVN B (BCODE)")

# ── Category 14: CMS / Web Applications ──
_reg("SAP-PASSCODE",     14, "SAP CODVN F/G (PASSCODE)")
_reg("SAP-ISSHA1",       14, "SAP CODVN H (PWDSALTEDHASH) iSSHA-1")
_reg("WordPress-phpass", 14, "WordPress MD5 (phpass)", prefix="$P$")
_reg("WordPress-2.6.2+", 14, "WordPress >= v2.6.2", prefix="$P$")
_reg("WordPress-2.6.0",  14, "WordPress v2.6.0/2.6.1", prefix="$H$")
_reg("Joomla-MD5",       14, "Joomla MD5", 32)
_reg("Joomla-old",       14, "Joomla < v2.5.18")
_reg("Joomla-new",       14, "Joomla >= v2.5.18", prefix="$2y$")
_reg("Drupal-5-6",       14, "Drupal 5/6", 32)
_reg("Drupal-7",         14, "Drupal > v7.x", prefix="$S$")
_reg("Drupal-8+",        14, "Drupal 8+")
_reg("Drupal-PBKDF2",    14, "Drupal PBKDF2")
_reg("phpBB3",           14, "phpBB v3.x", prefix="$H$")
_reg("vBulletin-old",    14, "vBulletin < v3.8.5")
_reg("vBulletin-new",    14, "vBulletin >= v3.8.5")
_reg("IPBoard",          14, "IP.Board >= v2+")
_reg("MyBB",             14, "MyBB >= v1.2+")
_reg("SMF",              14, "SMF >= v1.1")
_reg("WBB3",             14, "Woltlab Burning Board 3.x")
_reg("WBB4",             14, "Woltlab Burning Board 4.x")
_reg("PrestaShop",       14, "PrestaShop")
_reg("osCommerce",       14, "osCommerce")
_reg("xtCommerce",       14, "xt:Commerce")
_reg("MediaWiki",        14, "MediaWiki")
_reg("Django(MD5)",      14, "Django (MD5)", prefix="md5$")
_reg("Django(SHA-1)",    14, "Django (SHA-1)", prefix="sha1$")
_reg("Django(SHA-256)",  14, "Django (SHA-256)", prefix="sha256$")

# ── Category 15: More CMS / Frameworks ──
_reg("Django(PBKDF2-SHA1)",   15, "Django (PBKDF2-HMAC-SHA1)", prefix="pbkdf2_sha256$")
_reg("Django(PBKDF2-SHA256)", 15, "Django (PBKDF2-HMAC-SHA256)", prefix="pbkdf2_sha256$")
_reg("Django(bcrypt)",         15, "Django (bcrypt)", prefix="bcrypt$")
_reg("Django(bcrypt-SHA256)",  15, "Django (bcrypt-SHA256)", prefix="bcrypt_sha256$")
_reg("WebEdition",             15, "WebEdition CMS")
_reg("Rails-RestfulAuth",      15, "Ruby on Rails Restful Auth")
_reg("Rails-Devise",           15, "Ruby on Rails Devise", prefix="$2a$")
_reg("Rails-Authlogic",        15, "Ruby on Rails Authlogic")
_reg("passlib-pbkdf2-sha512",  15, "Python passlib pbkdf2-sha512", prefix="$pbkdf2-sha512$")
_reg("passlib-pbkdf2-sha256",  15, "Python passlib pbkdf2-sha256", prefix="$pbkdf2-sha256$")
_reg("passlib-pbkdf2-sha1",    15, "Python passlib pbkdf2-sha1", prefix="$pbkdf2$")
_reg("passlib-bcrypt",         15, "Python passlib bcrypt", prefix="$2a$")
_reg("passlib-scrypt",         15, "Python passlib scrypt", prefix="$scrypt$")
_reg("Web2py-pbkdf2",          15, "Web2py pbkdf2-sha512")
_reg("PHPass",                 15, "PHPass Portable Hash", prefix="$P$")

# ── Category 16: Cisco / Network / Firewall ──
_reg("Cisco-PIX",         16, "Cisco-PIX (MD5)")
_reg("Cisco-ASA",         16, "Cisco-ASA (MD5)")
_reg("Cisco-IOS-MD5",     16, "Cisco-IOS (MD5)")
_reg("Cisco-IOS-SHA256",  16, "Cisco-IOS (SHA-256)", prefix="$4$")
_reg("Cisco-Type4",       16, "Cisco Type 4", prefix="$4$")
_reg("Cisco-Type7",       16, "Cisco Type 7")
_reg("Cisco-Type8",       16, "Cisco Type 8", prefix="$8$")
_reg("Cisco-Type9",       16, "Cisco Type 9", prefix="$9$")
_reg("Cisco-VPN-PCF",     16, "Cisco VPN Client (PCF-File)")
_reg("Cisco-ISE-SHA256",  16, "Cisco-ISE Hashed Password (SHA256)")
_reg("Juniper-Netscreen",  16, "Juniper Netscreen/SSG (ScreenOS)")
_reg("Fortigate",         16, "Fortigate (FortiOS)")
_reg("WPA-WPA2",          16, "WPA/WPA2")
_reg("WPA-WPA2-PMK",      16, "WPA/WPA2 PMK", 64)
_reg("WPA3",              16, "WPA3")

# ── Category 17: Network Protocols ──
_reg("IKE-PSK-MD5",      17, "IKE-PSK MD5")
_reg("IKE-PSK-SHA1",     17, "IKE-PSK SHA1")
_reg("IPMI2-RAKP-SHA1",  17, "IPMI2 RAKP HMAC-SHA1")
_reg("IPMI2-RAKP-MD5",   17, "IPMI2 RAKP HMAC-MD5")
_reg("SNMPv3-HMAC-MD5-96", 17, "SNMPv3 HMAC-MD5-96")
_reg("SNMPv3-HMAC-SHA1-96", 17, "SNMPv3 HMAC-SHA1-96")
_reg("SNMPv3-HMAC-SHA256-128", 17, "SNMPv3 HMAC-SHA256-128")
_reg("SNMPv3-HMAC-SHA512-384", 17, "SNMPv3 HMAC-SHA512-384")
_reg("SCRAM-SHA1",       17, "SCRAM-SHA-1")
_reg("SCRAM-SHA256",     17, "SCRAM-SHA-256")

# ── Category 18: MS Office / PDF ──
_reg("MSOffice-2003-MD5",    18, "MS Office <=2003 (MD5+RC4)")
_reg("MSOffice-2003-MD5-C1", 18, "MS Office <=2003 (MD5+RC4) collider #1")
_reg("MSOffice-2003-MD5-C2", 18, "MS Office <=2003 (MD5+RC4) collider #2")
_reg("MSOffice-2003-SHA1",   18, "MS Office <=2003 (SHA1+RC4)")
_reg("MSOffice-2007",        18, "MS Office 2007")
_reg("MSOffice-2010",        18, "MS Office 2010")
_reg("MSOffice-2013",        18, "MS Office 2013")
_reg("MSOffice-2016",        18, "MS Office 2016")
_reg("PDF-1.1-1.3",          18, "PDF 1.1-1.3 (Acrobat 2-4)")
_reg("PDF-1.4-1.6",          18, "PDF 1.4-1.6 (Acrobat 5-8)")
_reg("PDF-1.7-L3",           18, "PDF 1.7 Level 3")
_reg("PDF-1.7-L8",           18, "PDF 1.7 Level 8")
_reg("PKZIP",                18, "PKZIP")
_reg("PKZIP-MasterKey",      18, "PKZIP Master Key")
_reg("ZIP-archive",          18, "ZIP archive")

# ── Category 19: Archives & Documents ──
_reg("RAR-archive",       19, "RAR archive")
_reg("RAR3-hp",           19, "RAR3-hp")
_reg("RAR5",              19, "RAR5")
_reg("7-Zip",             19, "7-Zip", prefix="$7z$")
_reg("WinZip",            19, "WinZip")
_reg("Outlook-PST",       19, "Microsoft Outlook PST")
_reg("MSTSC-RDP",         19, "Microsoft MSTSC (RDP-File)")
_reg("PeopleSoft",        19, "PeopleSoft")
_reg("Stuffit5",          19, "Stuffit5")
_reg("ENCsecurity",       19, "ENCsecurity Datavault")

# ── Category 20: TrueCrypt / VeraCrypt ──
_reg("TC-RIPEMD160-AES",       20, "TrueCrypt RIPEMD160+AES")
_reg("TC-RIPEMD160-Serpent",   20, "TrueCrypt RIPEMD160+Serpent")
_reg("TC-RIPEMD160-Twofish",   20, "TrueCrypt RIPEMD160+Twofish")
_reg("TC-SHA512-AES",          20, "TrueCrypt SHA512+AES")
_reg("TC-SHA512-Serpent",      20, "TrueCrypt SHA512+Serpent")
_reg("TC-Whirlpool-AES",       20, "TrueCrypt Whirlpool+AES")
_reg("TC-Whirlpool-Serpent",   20, "TrueCrypt Whirlpool+Serpent")
_reg("TC-Whirlpool-Twofish",   20, "TrueCrypt Whirlpool+Twofish")
_reg("VC-RIPEMD160-AES",       20, "VeraCrypt RIPEMD160+AES")
_reg("VC-SHA256-AES",          20, "VeraCrypt SHA256+AES")
_reg("VC-Whirlpool-AES",       20, "VeraCrypt Whirlpool+AES")
_reg("VC-Streebog512-XTS512",  20, "VeraCrypt Streebog-512+XTS 512")
_reg("VC-Streebog512-XTS1024", 20, "VeraCrypt Streebog-512+XTS 1024")
_reg("VC-Streebog512-XTS1536", 20, "VeraCrypt Streebog-512+XTS 1536")
_reg("VC-RIPEMD160-AES-Twofish", 20, "VeraCrypt RIPEMD160+AES-Twofish")
_reg("VC-SHA256-Serpent-AES",    20, "VeraCrypt SHA256+Serpent-AES")
_reg("VC-SHA256-Serpent-Twofish-AES", 20, "VeraCrypt SHA256+Serpent-Twofish-AES")
_reg("VC-Whirlpool-Twofish",     20, "VeraCrypt Whirlpool+Twofish")
_reg("VC-Whirlpool-Twofish-Serpent", 20, "VeraCrypt Whirlpool+Twofish-Serpent")
_reg("VC-boot-PIM",             20, "VeraCrypt boot-mode + PIM")

# ── Category 21: LUKS / DiskCryptor / FDE ──
_reg("LUKS1-SHA1-AES",        21, "LUKS v1 SHA-1+AES")
_reg("LUKS1-SHA256-AES",      21, "LUKS v1 SHA-256+AES")
_reg("LUKS1-SHA512-AES",      21, "LUKS v1 SHA-512+AES")
_reg("LUKS1-RIPEMD160-AES",   21, "LUKS v1 RIPEMD-160+AES")
_reg("LUKS1-SHA1-Serpent",    21, "LUKS v1 SHA-1+Serpent")
_reg("LUKS1-SHA1-Twofish",    21, "LUKS v1 SHA-1+Twofish")
_reg("LUKS1-SHA256-Serpent",  21, "LUKS v1 SHA-256+Serpent")
_reg("LUKS1-SHA256-Twofish",  21, "LUKS v1 SHA-256+Twofish")
_reg("LUKS1-SHA512-Serpent",  21, "LUKS v1 SHA-512+Serpent")
_reg("LUKS1-SHA512-Twofish",  21, "LUKS v1 SHA-512+Twofish")
_reg("LUKS1-RIPEMD160-Serpent", 21, "LUKS v1 RIPEMD-160+Serpent")
_reg("LUKS1-RIPEMD160-Twofish", 21, "LUKS v1 RIPEMD-160+Twofish")
_reg("LUKS2",                 21, "LUKS v2")
_reg("DiskCryptor-SHA512-XTS512", 21, "DiskCryptor SHA512+XTS 512")
_reg("DiskCryptor-SHA512-XTS1024", 21, "DiskCryptor SHA512+XTS 1024")

# ── Category 22: Apple / macOS / iOS ──
_reg("OSX-10.4",          22, "OSX v10.4 (salted SHA-1)", 56)
_reg("OSX-10.5",          22, "OSX v10.5 (salted SHA-1)")
_reg("OSX-10.6",          22, "OSX v10.6 (salted SHA-1)")
_reg("OSX-10.7-xsha512",  22, "OSX v10.7 (xsha512)")
_reg("OSX-10.8-pbkdf2",   22, "OSX v10.8 (pbkdf2-hmac-sha512)")
_reg("OSX-10.9-pbkdf2",   22, "OSX v10.9 (pbkdf2-hmac-sha512)")
_reg("macOS-10.15+",      22, "macOS 10.15+")
_reg("Apple-Keychain",    22, "Apple Keychain")
_reg("iTunes-<10.0",      22, "iTunes backup < 10.0")
_reg("iTunes-10.0+",      22, "iTunes backup 10.0+")
_reg("iOS-Passcode",      22, "iOS Passcode")
_reg("iOS7-Backup",       22, "iOS 7+ Backup")
_reg("iOS-Keychain",      22, "iOS Keychain")
_reg("Apple-FileVault",   22, "Apple FileVault")
_reg("Apple-FileVault2",  22, "Apple FileVault 2")

# ── Category 23: Android / Mobile ──
_reg("Samsung-Android-PIN", 23, "Samsung Android Password/PIN")
_reg("Android-PIN",       23, "Android PIN")
_reg("Android-FDE-4.3",   23, "Android FDE <= 4.3")
_reg("Android-FDE-5.0+",  23, "Android FDE 5.0+")
_reg("Android-FBE",       23, "Android FBE")
_reg("Android-Backup",    23, "Android Backup")
_reg("Android-KeyStore",  23, "Android KeyStore")
_reg("BlackBerry",        23, "BlackBerry")
_reg("BlackBerry-10",     23, "BlackBerry 10")
_reg("WinPhone8-PIN-2",   23, "Windows Phone 8+ PIN")

# ── Category 24: Cryptocurrency / Blockchain ──
_reg("Bitcoin-Address",   24, "Bitcoin Address")
_reg("Bitcoin-PrivKey",   24, "Bitcoin Private Key")
_reg("Bitcoin-Wallet",    24, "Bitcoin Wallet")
_reg("Bitcoin-Core-wallet", 24, "Bitcoin Core (wallet.dat)")
_reg("Ethereum-Address",  24, "Ethereum Address")
_reg("Ethereum-Wallet",   24, "Ethereum Wallet")
_reg("Ethereum-Keystore", 24, "Ethereum Keystore")
_reg("Litecoin-Wallet",   24, "Litecoin Wallet")
_reg("Dogecoin-Wallet",   24, "Dogecoin Wallet")
_reg("Electrum-Wallet",   24, "Electrum Wallet")
_reg("Terra-Wallet",      24, "Terra Station Wallet")
_reg("Bisq-wallet",       24, "Bisq .wallet (scrypt)")
_reg("Monero",            24, "Monero")
_reg("Ripple",            24, "Ripple")
_reg("Stellar",           24, "Stellar")

# ── Category 25: LDAP / Directory Services ──
_reg("Netscape-LDAP-SHA-2", 25, "Netscape LDAP SHA", prefix="{SHA}")
_reg("Netscape-LDAP-SSHA", 25, "Netscape LDAP SSHA", prefix="{SSHA}")
_reg("SSHA512-Base64",     25, "SSHA-512 (Base64)", prefix="{SSHA512}")
_reg("LDAP-SSHA512",       25, "LDAP (SSHA-512)", prefix="{SSHA512}")
_reg("OpenLDAP-SSHA",      25, "OpenLDAP {SSHA}", prefix="{SSHA}")
_reg("OpenLDAP-SSHA256",   25, "OpenLDAP {SSHA256}", prefix="{SSHA256}")
_reg("OpenLDAP-SSHA512",   25, "OpenLDAP {SSHA512}", prefix="{SSHA512}")
_reg("AD-NTDS",            25, "Active Directory NTDS.dit")
_reg("AD-Kerberos",        25, "Active Directory Kerberos")

# ── Category 26: Password Managers / Vaults ──
_reg("1Password-Agile",    26, "1Password (Agile Keychain)")
_reg("1Password-Cloud",    26, "1Password (Cloud Keychain)")
_reg("LastPass",           26, "LastPass")
_reg("LastPass-sniffed",   26, "LastPass sniffed")
_reg("KeePass1",           26, "KeePass 1 (AES/Twofish)")
_reg("KeePass2",           26, "KeePass 2 (AES)")
_reg("Bitwarden",          26, "Bitwarden")
_reg("Dashlane",           26, "Dashlane")
_reg("NordPass",           26, "NordPass")
_reg("RoboForm",           26, "RoboForm")

# ── Category 27: Application / Protocol / Other ──
_reg("Eggdrop",           27, "Eggdrop IRC Bot")
_reg("Skype",             27, "Skype")
_reg("Lotus-Notes-5",     27, "Lotus Notes/Domino 5")
_reg("Lotus-Notes-6",     27, "Lotus Notes/Domino 6")
_reg("Lotus-Notes-8",     27, "Lotus Notes/Domino 8")
_reg("Siemens-S7",        27, "Siemens-S7")
_reg("Dahua",             27, "Dahua")
_reg("Dahua-MD5",         27, "Dahua Authentication MD5")
_reg("SolarWinds-Orion",  27, "SolarWinds Orion")
_reg("SolarWinds-Orion-v2", 27, "SolarWinds Orion v2")
_reg("Umbraco-HMAC-SHA1", 27, "Umbraco HMAC-SHA1")
_reg("SipHash",           27, "SipHash")
_reg("CRAM-MD5",          27, "CRAM-MD5")
_reg("S-Key",             27, "S/Key")
_reg("OPIE",              27, "OPIE")
_reg("OTP",               27, "OTP")
_reg("HOTP",              27, "HOTP")
_reg("TOTP",              27, "TOTP")
_reg("FSHP",              27, "Fairly Secure Hashed Password")

# ── Category 28: Legacy Variants ──
_reg("MD5-CHAP",          28, "MD5(Chap)")
_reg("iSCSI-CHAP",        28, "iSCSI CHAP Authentication")
_reg("MD5-Crypt-Cisco",   28, "MD5 Crypt (Cisco-IOS)", prefix="$1$")
_reg("FreeBSD-MD5",       28, "FreeBSD MD5", prefix="$1$")
_reg("Sun-MD5-Crypt",     28, "Sun MD5 Crypt", prefix="$md5$")
_reg("AIX-smd5-2",        28, "AIX (smd5)", prefix="{smd5}")
_reg("MD5(Oracle)",       28, "MD5(Oracle)")
_reg("SHA-1(Oracle)-2",   28, "SHA-1(Oracle)")
_reg("sha256(salt.unicode)-2", 28, "SHA-256(salt.unicode(pass))", 64)
_reg("sha512(salt.unicode)-2", 28, "SHA-512(salt.unicode(pass))", 128)
_reg("Groestl-256",       28, "Groestl-256", 64)
_reg("Groestl-512",       28, "Groestl-512", 128)
_reg("JH-256",            28, "JH-256", 64)
_reg("JH-512",            28, "JH-512", 128)
_reg("ECHO-256",          28, "ECHO-256", 64)
_reg("ECHO-512",          28, "ECHO-512", 128)
_reg("CubeHash-256",      28, "CubeHash-256", 64)
_reg("CubeHash-512",      28, "CubeHash-512", 128)

# ── Category 29: More Cryptographic Functions ──
_reg("Panama",            29, "Panama")
_reg("RadioGatun-32",     29, "RadioGatun[32]")
_reg("RadioGatun-64",     29, "RadioGatun[64]")
_reg("FSB-160",           29, "FSB-160", 40)
_reg("FSB-256",           29, "FSB-256", 64)
_reg("FSB-384",           29, "FSB-384", 96)
_reg("FSB-512",           29, "FSB-512", 128)
_reg("ECOH",              29, "ECOH")
_reg("SWIFFT",            29, "SWIFFT")
_reg("Shabal-256",        29, "Shabal-256", 64)
_reg("Shabal-512",        29, "Shabal-512", 128)
_reg("SIMD-256",          29, "SIMD-256", 64)
_reg("SIMD-512",          29, "SIMD-512", 128)

# ── Category 30: Signatures ──
_reg("HMAC-Skein-1024",   30, "HMAC-Skein-1024")
_reg("HMAC-SHA3-224",     30, "HMAC-SHA3-224")
_reg("HMAC-SHA3-384",     30, "HMAC-SHA3-384")
_reg("HMAC-SHA3-512",     30, "HMAC-SHA3-512")
_reg("RSA-MD5",           30, "RSA-MD5")
_reg("RSA-SHA1",          30, "RSA-SHA1")
_reg("RSA-SHA256",        30, "RSA-SHA256")
_reg("DSA-SHA1",          30, "DSA-SHA1")
_reg("ECDSA-SHA256",      30, "ECDSA-SHA256")
_reg("Ed25519",           30, "Ed25519")
_reg("Ed448",             30, "Ed448")
_reg("RSA-PSS",           30, "RSA-PSS")
_reg("RSA-OAEP",          30, "RSA-OAEP")
_reg("EdDSA-Ed25519",     30, "EdDSA (Ed25519)")


# ──────────────────────────────────────────────
#  Build lookup structures
# ──────────────────────────────────────────────
LENGTH_MAP: Dict[int, List[str]] = {}
PREFIX_MAP: Dict[str, List[str]] = {}

for name, info in HASH_DB.items():
    hl_val = info.get("hex_len")
    if hl_val:
        LENGTH_MAP.setdefault(hl_val, []).append(name)
    pfx = info.get("prefix")
    if pfx:
        PREFIX_MAP.setdefault(pfx, []).append(name)

CATEGORY_NAMES = {
    1: "CRC / Checksum", 2: "Non-Cryptographic", 3: "MD Family & Variants",
    4: "SHA-1 & Variants", 5: "SHA-2 Family", 6: "SHA-3 / Keccak",
    7: "BLAKE Family", 8: "RIPEMD/Tiger/Whirlpool/Skein/GOST",
    9: "HMAC Variants", 10: "KDF / yescrypt", 11: "Unix / Linux Crypt",
    12: "Windows Authentication", 13: "Database Hashes", 14: "CMS / Web Applications",
    15: "More CMS / Frameworks", 16: "Cisco / Network / Firewall",
    17: "Network Protocols", 18: "MS Office / PDF / Archives",
    19: "Archives & Documents", 20: "TrueCrypt / VeraCrypt",
    21: "LUKS / DiskCryptor / FDE", 22: "Apple / macOS / iOS",
    23: "Android / Mobile", 24: "Cryptocurrency / Blockchain",
    25: "LDAP / Directory Services", 26: "Password Managers / Vaults",
    27: "Application / Protocol / Other", 28: "Legacy Variants",
    29: "More Cryptographic Functions", 30: "Signatures",
}


# ──────────────────────────────────────────────
#  Hash Detection
# ──────────────────────────────────────────────
def detect_hash_type(hash_str: str) -> List[Tuple[str, str, int]]:
    """Detect possible hash types. Returns [(name, desc, category), ...]."""
    results = []
    h = hash_str.strip()

    # Prefix-based detection (highest confidence)
    for pfx, names in sorted(PREFIX_MAP.items(), key=lambda x: -len(x[0])):
        if h.startswith(pfx):
            for n in names:
                results.append((n, HASH_DB[n]["desc"], HASH_DB[n]["cat"]))

    # MySQL4+ style: starts with *
    if re.match(r"^\*[a-fA-F0-9]{40}$", h):
        for n in ["MySQL4.1"]:
            if n in HASH_DB:
                results.insert(0, (n, HASH_DB[n]["desc"], HASH_DB[n]["cat"]))

    # Hex-only detection by length
    if re.match(r"^[a-fA-F0-9]+$", h):
        length = len(h)
        if length in LENGTH_MAP:
            for n in LENGTH_MAP[length]:
                results.append((n, HASH_DB[n]["desc"], HASH_DB[n]["cat"]))

    # Base64 detection patterns
    if re.match(r"^\{SSHA\}[A-Za-z0-9+/]+=*$", h):
        if ("Netscape-LDAP-SSHA",) not in [(r[0],) for r in results]:
            results.insert(0, ("Netscape-LDAP-SSHA", "Netscape LDAP SSHA", 25))
    if re.match(r"^\{SHA\}[A-Za-z0-9+/]+=*$", h):
        results.insert(0, ("Netscape-LDAP-SHA-2", "Netscape LDAP SHA", 25))

    # Deduplicate preserving order
    seen = set()
    deduped = []
    for r in results:
        if r[0] not in seen:
            seen.add(r[0])
            deduped.append(r)
    results = deduped

    # Priority ranking: most common types first
    priority = [
        "MD5", "SHA-256", "SHA-1", "SHA-512", "NTLM", "NT", "MD4", "LM",
        "CRC-32", "SHA-224", "SHA-384", "RIPEMD-160", "Whirlpool", "BLAKE2b",
        "BLAKE2s", "SHA3-256", "Keccak-256", "BLAKE-256", "RIPEMD-256",
        "MySQL5.x", "MySQL4.1", "PostgreSQL-MD5", "Django(SHA-256)",
    ]
    results.sort(key=lambda x: priority.index(x[0]) if x[0] in priority else 999)

    return results


# ──────────────────────────────────────────────
#  Hash Computation
# ──────────────────────────────────────────────
SALTED_TYPES = {
    "md5(pass.salt)", "md5(salt.pass)", "md5(unicode(pass).salt)", "md5(salt.unicode(pass))",
    "md5(salt.pass.$salt)", "md5(md5(pass).md5(salt))", "md5(md5(salt).pass)",
    "md5(salt.md5(pass))", "md5(pass.md5(salt))", "md5(salt.md5(salt.$pass))",
    "md5(salt.md5(pass.$salt))", "md5(username.0.pass)", "md5(sha1($pass))",
    "md5(strtoupper(md5))", "md5(sha1(md5($pass)))",
    "sha1(pass.salt)", "sha1(salt.pass)", "sha1(unicode(pass).salt)", "sha1(salt.unicode(pass))",
    "sha1(salt.pass.$salt)", "sha1(md5($pass))", "sha1(sha1(salt.pass.$salt))",
    "sha1(sha1(pass).salt)",
    "sha256(pass.salt)", "sha256(salt.pass)", "sha512(pass.salt)", "sha512(salt.pass)",
    "sha256(unicode(pass).salt)", "sha512(unicode(pass).salt)", "sha256(salt.unicode(pass))",
    "HMAC-MD5(salt)", "HMAC-SHA1(salt)", "HMAC-SHA256(salt)", "HMAC-SHA512(salt)",
    "HMAC-RIPEMD160(salt)", "HMAC-Streebog-256(salt)", "HMAC-Streebog-512(salt)",
}

CRYPT_TYPES = {
    "MD5(Crypt)", "MD5(APR)", "SHA-256(Crypt)", "SHA-512(Crypt)", "SHA-1(Crypt)",
    "bcrypt", "bcrypt-2b", "bcrypt-2x", "bcrypt-2y", "bcrypt-OpenBSD",
    "bcrypt(SHA256)", "bcrypt(SHA512)",
    "scrypt", "scrypt-Colin",
    "yescrypt", "yescrypt-v1", "yescrypt-v2", "gost-yescrypt",
    "Argon2", "Argon2d", "Argon2i", "Argon2id",
    "PBKDF2-HMAC-MD5", "PBKDF2-HMAC-SHA1", "PBKDF2-HMAC-SHA256", "PBKDF2-HMAC-SHA512",
    "Django(SHA-256)", "Django(SHA-1)", "Django(MD5)",
    "Django(PBKDF2-SHA1)", "Django(PBKDF2-SHA256)", "Django(bcrypt)", "Django(bcrypt-SHA256)",
    "WordPress-phpass", "WordPress-2.6.2+", "PHPass",
    "Netscape-LDAP-SSHA", "Netscape-LDAP-SSHA", "SSHA1-Base64",
    "OpenLDAP-SSHA", "OpenLDAP-SSHA256", "OpenLDAP-SSHA512", "SSHA512-Base64", "LDAP-SSHA512",
    "Cisco-Type8", "Cisco-Type9", "Cisco-IOS-SHA256", "Cisco-Type4",
    "GRUB2-pbkdf2", "AIX-smd5", "AIX-ssha1", "AIX-ssha256", "AIX-ssha512",
    "Unix-MD5", "Unix-SHA256", "Unix-SHA512", "Unix-Blowfish",
    "FreeBSD-MD5", "Sun-MD5-Crypt", "MD5-Crypt-Cisco",
    "passlib-pbkdf2-sha512", "passlib-pbkdf2-sha256", "passlib-pbkdf2-sha1",
    "7-Zip", "PostgreSQL-SCRAM",
}


def _try_hashlib(name: str, data: bytes) -> Optional[str]:
    try:
        return hashlib.new(name, data).hexdigest()
    except (ValueError, TypeError):
        return None


def compute_hash(word: str, hash_type: str, salt: str = "") -> Optional[str]:
    """Compute a hash for the given word. Returns hex string or None."""
    enc = word.encode("utf-8", errors="replace")
    enc16 = word.encode("utf-16le")

    # ── CRC Family ──
    if hash_type == "CRC-16":          return format(_crc16(enc, 0x8005), '04x')
    if hash_type == "CRC-16-CCITT":    return format(_crc16(enc, 0x1021, init=0xFFFF), '04x')
    if hash_type == "CRC-16-IBM":      return format(_crc16(enc, 0x8005, init=0, refin=True, refout=True), '04x')
    if hash_type == "CRC-16-DNP":      return format(_crc16(enc, 0x3D65, init=0, refin=True, refout=True, xorout=0xFFFF), '04x')
    if hash_type == "CRC-16-Modbus":   return format(_crc16(enc, 0x8005, init=0xFFFF, refin=True, refout=True), '04x')
    if hash_type == "CRC-16-XMODEM":   return format(_crc16(enc, 0x1021), '04x')
    if hash_type == "CRC-16-USB":      return format(_crc16(enc, 0x8005, init=0xFFFF, refin=True, refout=True, xorout=0xFFFF), '04x')
    if hash_type == "CRC-16-ZMODEM":   return format(_crc16(enc, 0x1021), '04x')
    if hash_type == "CRC-24":          return format(_crc16(enc, 0x864CFB) & 0xFFFFFF, '06x')  # simplified
    if hash_type == "CRC-32":          return format(binascii.crc32(enc) & 0xFFFFFFFF, '08x')
    if hash_type == "CRC-32B":         return format(binascii.crc32(enc) & 0xFFFFFFFF, '08x')
    if hash_type == "CRC-32C":         return format(_crc32_generic(enc, 0x1EDC6F41), '08x')
    if hash_type == "CRC-32-MPEG-2":   return format(_crc32_generic(enc, 0x04C11DB7, refin=False, refout=False, xorout=0), '08x')
    if hash_type == "CRC-32D":         return format(_crc32_generic(enc, 0xA833982B), '08x')
    if hash_type == "CRC-32Q":         return format(_crc32_generic(enc, 0x814141AB, refin=False, refout=False, xorout=0), '08x')
    if hash_type == "CRC-40-GSM":      return None  # requires specialized implementation
    if hash_type == "CRC-64":          return format(_crc64(enc, 0x42F0E1EBA9EA3693), '016x')
    if hash_type == "CRC-64-ECMA":     return format(_crc64(enc, 0x42F0E1EBA9EA3693), '016x')
    if hash_type == "CRC-64-ISO":      return format(_crc64(enc, 0x000000000000001B), '016x')
    if hash_type == "CRC-64-Jones":    return format(_crc64(enc, 0xAD93D23594C935A9), '016x')

    # ── Non-Cryptographic ──
    if hash_type == "FNV-1-32":      return format(fnv1_32(enc), '08x')
    if hash_type == "FNV-1a-32":     return format(fnv1a_32(enc), '08x')
    if hash_type == "FNV-1-64":      return format(fnv1_64(enc), '016x')
    if hash_type == "FNV-1a-64":     return format(fnv1a_64(enc), '016x')
    if hash_type == "FNV-132":       return format(fnv1_32(enc), '08x')
    if hash_type == "FNV-164":       return format(fnv1_64(enc), '016x')
    if hash_type == "DJB2":          return format(djb2(enc), '08x')
    if hash_type == "SDBM":          return format(sdbm(enc), '08x')
    if hash_type == "Jenkins":       return format(jenkins_one_at_a_time(enc), '08x')
    if hash_type == "Joaat":         return format(jenkins_one_at_a_time(enc), '08x')
    if hash_type == "ELF-32":        return format(elf_hash(enc), '08x')
    if hash_type == "JavaHashCode":  return format(word.__hash__() & 0xFFFFFFFF, '08x')

    # ── MD Family ──
    if hash_type == "MD2":           return _try_hashlib("md2", enc)
    if hash_type == "MD4":           return _try_hashlib("md4", enc)
    if hash_type == "MD5":           return hashlib.md5(enc).hexdigest()
    if hash_type == "MD6":           return None
    if hash_type == "Half-MD5":      return hashlib.md5(enc).hexdigest()[:16]
    if hash_type == "Double-MD5":    return hashlib.md5(hashlib.md5(enc).hexdigest().encode()).hexdigest()
    if hash_type == "Triple-MD5":    return hashlib.md5(hashlib.md5(hashlib.md5(enc).hexdigest().encode()).hexdigest().encode()).hexdigest()
    if hash_type == "md5(md5(md5($pass)))":
        h = hashlib.md5(enc).hexdigest().encode()
        h = hashlib.md5(h).hexdigest().encode()
        return hashlib.md5(h).hexdigest()
    if hash_type == "md5(sha1($pass))":
        return hashlib.md5(hashlib.sha1(enc).hexdigest().encode()).hexdigest()
    if hash_type == "md5(sha1(md5($pass)))":
        return hashlib.md5(hashlib.sha1(hashlib.md5(enc).hexdigest().encode()).hexdigest().encode()).hexdigest()
    if hash_type == "md5(strtoupper(md5))":
        return hashlib.md5(hashlib.md5(enc).hexdigest().upper().encode()).hexdigest()

    # ── SHA Family ──
    if hash_type == "SHA-0":         return _try_hashlib("sha0", enc)
    if hash_type == "SHA-1":         return hashlib.sha1(enc).hexdigest()
    if hash_type == "Double-SHA1":   return hashlib.sha1(hashlib.sha1(enc).hexdigest().encode()).hexdigest()
    if hash_type == "Triple-SHA1":
        h = hashlib.sha1(enc).hexdigest().encode()
        h = hashlib.sha1(h).hexdigest().encode()
        return hashlib.sha1(h).hexdigest()
    if hash_type == "sha1(sha1(sha1($pass)))":
        h = hashlib.sha1(enc).hexdigest().encode()
        h = hashlib.sha1(h).hexdigest().encode()
        return hashlib.sha1(h).hexdigest()
    if hash_type == "sha1(md5($pass))":
        return hashlib.sha1(hashlib.md5(enc).hexdigest().encode()).hexdigest()

    # ── SHA-2 Family ──
    if hash_type == "SHA-224":       return hashlib.sha224(enc).hexdigest()
    if hash_type == "SHA-256":       return hashlib.sha256(enc).hexdigest()
    if hash_type == "SHA-384":       return hashlib.sha384(enc).hexdigest()
    if hash_type == "SHA-512":       return hashlib.sha512(enc).hexdigest()
    if hash_type == "SHA-512/224":   return hashlib.new("sha512_224", enc).hexdigest() if hasattr(hashlib, 'sha512_224') else _try_hashlib("sha512_224", enc)
    if hash_type == "SHA-512/256":   return hashlib.new("sha512_256", enc).hexdigest() if hasattr(hashlib, 'sha512_256') else _try_hashlib("sha512_256", enc)

    # ── SHA-3 / Keccak ──
    if hash_type == "SHA3-224":      return hashlib.sha3_224(enc).hexdigest()
    if hash_type == "SHA3-256":      return hashlib.sha3_256(enc).hexdigest()
    if hash_type == "SHA3-384":      return hashlib.sha3_384(enc).hexdigest()
    if hash_type == "SHA3-512":      return hashlib.sha3_512(enc).hexdigest()
    if hash_type in ("Keccak-256", "Raw-Keccak-256"): return hashlib.sha3_256(enc).hexdigest()  # approximate
    if hash_type in ("Keccak-512", "Raw-Keccak-512"): return hashlib.sha3_512(enc).hexdigest()  # approximate
    if hash_type == "SHAKE128":      return hashlib.shake_128(enc).hexdigest(32)
    if hash_type == "SHAKE256":      return hashlib.shake_256(enc).hexdigest(64)

    # ── BLAKE Family ──
    if hash_type == "BLAKE2b":       return hashlib.blake2b(enc).hexdigest()
    if hash_type == "BLAKE2b-256":   return hashlib.blake2b(enc, digest_size=32).hexdigest()
    if hash_type == "BLAKE2b-512":   return hashlib.blake2b(enc, digest_size=64).hexdigest()
    if hash_type == "BLAKE2s":       return hashlib.blake2s(enc).hexdigest()
    if hash_type == "BLAKE2s-128":   return hashlib.blake2s(enc, digest_size=16).hexdigest()
    if hash_type == "BLAKE2s-256":   return hashlib.blake2s(enc, digest_size=32).hexdigest()
    if hash_type in ("BLAKE-256",):  return hashlib.blake2s(enc, digest_size=32).hexdigest()  # approximate
    if hash_type in ("BLAKE-512",):  return hashlib.blake2b(enc, digest_size=64).hexdigest()  # approximate

    # ── RIPEMD Family ──
    if hash_type == "RIPEMD-128":    return _try_hashlib("ripemd128", enc)
    if hash_type == "RIPEMD-160":    return _try_hashlib("ripemd160", enc)
    if hash_type == "RIPEMD-256":    return _try_hashlib("ripemd256", enc)
    if hash_type == "RIPEMD-320":    return _try_hashlib("ripemd320", enc)

    # ── Whirlpool / Tiger ──
    if hash_type == "Whirlpool":     return _try_hashlib("whirlpool", enc)
    if hash_type == "Whirlpool-T":   return _try_hashlib("whirlpool", enc)

    # ── Windows Auth ──
    if hash_type in ("NTLM", "NT"):
        try: return hashlib.new("md4", enc16).hexdigest()
        except ValueError: return None

    # ── Database ──
    if hash_type == "MySQL323":
        nr = 1345345333; add = 7; nr2 = 0x12345671
        for c in word:
            if c in (' ', '\t'): continue
            tmp = ord(c)
            nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
            nr2 = (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
            add = (add + tmp) & 0xFFFFFFFF
        nr &= 0x7FFFFFFF; nr2 &= 0x7FFFFFFF
        return format(nr, '08x') + format(nr2, '08x')
    if hash_type == "MySQL4.1" or hash_type == "MySQL5.x":
        s1 = hashlib.sha1(enc).digest()
        s2 = hashlib.sha1(s1).hexdigest()
        return ("*" + s2.upper()) if hash_type == "MySQL4.1" else s2.upper()

    # ── HMAC variants (key = pass) ──
    if hash_type == "HMAC-MD5(pass)":     return hmac_mod.new(enc, salt.encode(), 'md5').hexdigest() if salt else hmac_mod.new(b'', enc, 'md5').hexdigest()
    if hash_type == "HMAC-SHA1(pass)":    return hmac_mod.new(enc, salt.encode(), 'sha1').hexdigest() if salt else hmac_mod.new(b'', enc, 'sha1').hexdigest()
    if hash_type == "HMAC-SHA256(pass)":  return hmac_mod.new(enc, salt.encode(), 'sha256').hexdigest() if salt else hmac_mod.new(b'', enc, 'sha256').hexdigest()
    if hash_type == "HMAC-SHA512(pass)":  return hmac_mod.new(enc, salt.encode(), 'sha512').hexdigest() if salt else hmac_mod.new(b'', enc, 'sha512').hexdigest()
    if hash_type == "HMAC-MD5(salt)":     return hmac_mod.new(salt.encode(), enc, 'md5').hexdigest()
    if hash_type == "HMAC-SHA1(salt)":    return hmac_mod.new(salt.encode(), enc, 'sha1').hexdigest()
    if hash_type == "HMAC-SHA256(salt)":  return hmac_mod.new(salt.encode(), enc, 'sha256').hexdigest()
    if hash_type == "HMAC-SHA512(salt)":  return hmac_mod.new(salt.encode(), enc, 'sha512').hexdigest()
    if hash_type == "HMAC-RIPEMD160(pass)": return hmac_mod.new(enc, salt.encode(), 'ripemd160').hexdigest() if salt else hmac_mod.new(b'', enc, 'ripemd160').hexdigest()
    if hash_type == "HMAC-SHA3-256":      return hmac_mod.new(salt.encode() if salt else b'', enc, 'sha3_256').hexdigest()

    # ── Salted MD5 variants ──
    if hash_type == "md5(pass.salt)":      return hashlib.md5(enc + salt.encode()).hexdigest()
    if hash_type == "md5(salt.pass)":      return hashlib.md5(salt.encode() + enc).hexdigest()
    if hash_type == "md5(unicode(pass).salt)": return hashlib.md5(enc16 + salt.encode()).hexdigest()
    if hash_type == "md5(salt.unicode(pass))": return hashlib.md5(salt.encode() + enc16).hexdigest()
    if hash_type == "md5(salt.pass.$salt)": return hashlib.md5(salt.encode() + enc + salt.encode()).hexdigest()
    if hash_type == "md5(md5(pass).md5(salt))": return hashlib.md5(hashlib.md5(enc).hexdigest().encode() + hashlib.md5(salt.encode()).hexdigest().encode()).hexdigest()
    if hash_type == "md5(md5(salt).pass)": return hashlib.md5(hashlib.md5(salt.encode()).hexdigest().encode() + enc).hexdigest()
    if hash_type == "md5(salt.md5(pass))": return hashlib.md5(salt.encode() + hashlib.md5(enc).hexdigest().encode()).hexdigest()
    if hash_type == "md5(pass.md5(salt))": return hashlib.md5(enc + hashlib.md5(salt.encode()).hexdigest().encode()).hexdigest()
    if hash_type == "md5(salt.md5(salt.$pass))": return hashlib.md5(salt.encode() + hashlib.md5(salt.encode() + enc).hexdigest().encode()).hexdigest()
    if hash_type == "md5(salt.md5(pass.$salt))": return hashlib.md5(salt.encode() + hashlib.md5(enc + salt.encode()).hexdigest().encode()).hexdigest()
    if hash_type == "md5(username.0.pass)": return hashlib.md5(salt.encode() + b'\x00' + enc).hexdigest()  # salt=username

    # ── Salted SHA-1 variants ──
    if hash_type == "sha1(pass.salt)":     return hashlib.sha1(enc + salt.encode()).hexdigest()
    if hash_type == "sha1(salt.pass)":     return hashlib.sha1(salt.encode() + enc).hexdigest()
    if hash_type == "sha1(unicode(pass).salt)": return hashlib.sha1(enc16 + salt.encode()).hexdigest()
    if hash_type == "sha1(salt.unicode(pass))": return hashlib.sha1(salt.encode() + enc16).hexdigest()
    if hash_type == "sha1(salt.pass.$salt)": return hashlib.sha1(salt.encode() + enc + salt.encode()).hexdigest()
    if hash_type == "sha1(sha1(salt.pass.$salt))": return hashlib.sha1(hashlib.sha1(salt.encode() + enc + salt.encode()).hexdigest().encode()).hexdigest()
    if hash_type == "sha1(sha1(pass).salt)": return hashlib.sha1(hashlib.sha1(enc).hexdigest().encode() + salt.encode()).hexdigest()

    # ── Salted SHA-2 variants ──
    if hash_type == "sha256(pass.salt)":    return hashlib.sha256(enc + salt.encode()).hexdigest()
    if hash_type == "sha256(salt.pass)":    return hashlib.sha256(salt.encode() + enc).hexdigest()
    if hash_type == "sha512(pass.salt)":    return hashlib.sha512(enc + salt.encode()).hexdigest()
    if hash_type == "sha512(salt.pass)":    return hashlib.sha512(salt.encode() + enc).hexdigest()
    if hash_type == "sha256(unicode(pass).salt)": return hashlib.sha256(enc16 + salt.encode()).hexdigest()
    if hash_type == "sha512(unicode(pass).salt)": return hashlib.sha512(enc16 + salt.encode()).hexdigest()
    if hash_type == "sha256(salt.unicode(pass))": return hashlib.sha256(salt.encode() + enc16).hexdigest()

    # ── Crypt-style (handled in compute_crypt_hash) ──
    if hash_type in CRYPT_TYPES:
        return None

    return None


def compute_crypt_hash(word: str, original_hash: str, hash_type: str, salt: str = "") -> Optional[str]:
    """Compute crypt-style / salted hashes that need the original hash for salt extraction."""
    import crypt

    if hash_type in ("MD5(Crypt)", "Unix-MD5", "FreeBSD-MD5", "MD5-Crypt-Cisco", "AIX-smd5"):
        s = salt or (original_hash.split("$")[2] if "$" in original_hash else "")
        return crypt.crypt(word, f"$1${s}$")

    if hash_type == "MD5(APR)":
        s = salt or (original_hash.split("$")[2] if "$" in original_hash else "")
        try:
            import passlib.hash
            return passlib.hash.apr_md5_crypt.hash(word, salt=s)
        except ImportError:
            return crypt.crypt(word, f"$1${s}$")

    if hash_type in ("SHA-256(Crypt)", "Unix-SHA256"):
        s = salt or (original_hash.split("$")[2] if len(original_hash.split("$")) > 2 else "")
        return crypt.crypt(word, f"$5${s}$")

    if hash_type in ("SHA-512(Crypt)", "Unix-SHA512"):
        s = salt or (original_hash.split("$")[2] if len(original_hash.split("$")) > 2 else "")
        return crypt.crypt(word, f"$6${s}$")

    if hash_type in ("bcrypt", "bcrypt-2b", "bcrypt-OpenBSD", "bcrypt(SHA256)", "bcrypt(SHA512)"):
        try:
            import bcrypt as _bcrypt
            return _bcrypt.hashpw(word.encode(), original_hash.encode()).decode()
        except ImportError:
            return None

    if hash_type in ("bcrypt-2y",):
        try:
            import bcrypt as _bcrypt
            return _bcrypt.hashpw(word.encode(), original_hash.encode()).decode()
        except ImportError:
            return None

    if hash_type in ("scrypt", "scrypt-Colin"):
        try:
            return hashlib.scrypt(word.encode(), salt=salt.encode() or b'\x00'*16, n=16384, r=8, p=1).hex()
        except Exception:
            return None

    if hash_type in ("Django(SHA-256)", "Django(SHA-1)", "Django(MD5)"):
        parts = original_hash.split("$")
        if len(parts) >= 3:
            s = parts[1]
            algo = {"Django(SHA-256)": "sha256", "Django(SHA-1)": "sha1", "Django(MD5)": "md5"}[hash_type]
            h = hashlib.new(algo, f"{s}{word}".encode()).hexdigest()
            return f"{algo}${s}${h}"
        return None

    if hash_type in ("WordPress-phpass", "WordPress-2.6.2+", "PHPass"):
        try:
            import passlib.hash
            return passlib.hash.phpass.hash(word, salt=salt or None)
        except ImportError:
            return None

    if hash_type in ("PBKDF2-HMAC-SHA256", "Django(PBKDF2-SHA256)"):
        try:
            dk = hashlib.pbkdf2_hmac('sha256', word.encode(), salt.encode() or b'salt', 100000)
            return dk.hex()
        except Exception:
            return None

    if hash_type == "PBKDF2-HMAC-SHA512":
        try:
            dk = hashlib.pbkdf2_hmac('sha512', word.encode(), salt.encode() or b'salt', 100000)
            return dk.hex()
        except Exception:
            return None

    if hash_type == "PBKDF2-HMAC-SHA1":
        try:
            dk = hashlib.pbkdf2_hmac('sha1', word.encode(), salt.encode() or b'salt', 100000)
            return dk.hex()
        except Exception:
            return None

    if hash_type in ("Netscape-LDAP-SSHA", "OpenLDAP-SSHA", "SSHA1-Base64"):
        try:
            b64 = original_hash.split("}", 1)[-1] if "}" in original_hash else original_hash
            decoded = base64.b64decode(b64)
            s = decoded[20:]
            h = hashlib.sha1(word.encode() + s).digest()
            return "{SSHA}" + base64.b64encode(h + s).decode()
        except Exception:
            return None

    if hash_type in ("OpenLDAP-SSHA256",):
        try:
            b64 = original_hash.split("}", 1)[-1]
            decoded = base64.b64decode(b64)
            s = decoded[32:]
            h = hashlib.sha256(word.encode() + s).digest()
            return "{SSHA256}" + base64.b64encode(h + s).decode()
        except Exception:
            return None

    if hash_type in ("OpenLDAP-SSHA512", "SSHA512-Base64", "LDAP-SSHA512"):
        try:
            b64 = original_hash.split("}", 1)[-1]
            decoded = base64.b64decode(b64)
            s = decoded[64:]
            h = hashlib.sha512(word.encode() + s).digest()
            return "{SSHA512}" + base64.b64encode(h + s).decode()
        except Exception:
            return None

    if hash_type in ("Argon2", "Argon2d", "Argon2i", "Argon2id"):
        try:
            import argon2
            ph = argon2.PasswordHasher()
            return ph.hash(word)
        except ImportError:
            return None

    if hash_type in ("PostgreSQL-MD5",):
        return "md5" + hashlib.md5(word.encode() + salt.encode()).hexdigest()

    return None


def extract_salt(hash_str: str, hash_type: str) -> str:
    """Extract salt from a hash string based on its type."""
    h = hash_str.strip()

    # Django formats: algo$salt$hash
    if hash_type in ("Django(SHA-256)", "Django(SHA-1)", "Django(MD5)",
                      "Django(PBKDF2-SHA1)", "Django(PBKDF2-SHA256)"):
        parts = h.split("$")
        return parts[1] if len(parts) >= 2 else ""

    # Crypt-style: $id$salt$hash
    if hash_type in ("MD5(Crypt)", "Unix-MD5", "FreeBSD-MD5", "MD5-Crypt-Cisco",
                      "MD5(APR)", "SHA-256(Crypt)", "Unix-SHA256",
                      "SHA-512(Crypt)", "Unix-SHA512"):
        parts = h.split("$")
        return parts[2] if len(parts) >= 3 else ""

    # PostgreSQL MD5: md5<hash> — salt is username
    if hash_type == "PostgreSQL-MD5":
        return ""  # needs external username

    return ""


# ──────────────────────────────────────────────
#  Hash Cracking - Helper Functions
# ──────────────────────────────────────────────
def _check_word(word, target_norm, hash_type, salt, is_salted, is_crypt, target_hash):
    """Check a single word against the target hash. Returns True if match."""
    if is_crypt:
        cand = compute_crypt_hash(word, target_hash, hash_type, salt)
        return cand is not None and cand == target_hash
    elif is_salted:
        cand = compute_hash(word, hash_type, salt)
        return cand is not None and cand.lower() == target_norm
    else:
        cand = compute_hash(word, hash_type)
        return cand is not None and cand.lower() == target_norm


def _crack_single_thread(target_hash, target_norm, hash_type, wordlist_path,
                          is_crypt, is_salted, salt, verbose, total, start_time):
    """Single-threaded cracking."""
    found = False
    word = ""
    attempts = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\n\r")
                attempts += 1
                if _check_word(word, target_norm, hash_type, salt, is_salted, is_crypt, target_hash):
                    found = True
                    break
                if verbose and attempts % 50000 == 0:
                    el = time.time() - start_time
                    rate = attempts / el if el > 0 else 0
                    print(f"  {Colors.DIM}[Progress] {attempts:,}/{total:,} "
                          f"({attempts/total*100:.1f}%) | {rate:,.0f} h/s | "
                          f"{el:.1f}s{Colors.RESET}", end="\r")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted.{Colors.RESET}")
    return found, word, attempts


def _crack_multi_thread(target_hash, target_norm, hash_type, wordlist_path,
                         is_salted, salt, verbose, total, num_threads, start_time):
    """Multi-threaded cracking using ThreadPoolExecutor."""
    found = False
    found_word = ""
    total_attempts = 0
    lock = threading.Lock()
    stop_event = threading.Event()

    # Read all words into memory
    words = []
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                words.append(line.rstrip("\n\r"))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted while reading wordlist.{Colors.RESET}")
        return False, "", 0

    chunk_size = max(1, len(words) // num_threads)
    chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]

    def process_chunk(chunk, chunk_id):
        nonlocal found, found_word, total_attempts
        local_attempts = 0
        for word in chunk:
            if stop_event.is_set():
                return
            local_attempts += 1
            if _check_word(word, target_norm, hash_type, salt, is_salted, False, target_hash):
                with lock:
                    if not found:
                        found = True
                        found_word = word
                        stop_event.set()
        with lock:
            total_attempts += local_attempts

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(process_chunk, chunk, i) for i, chunk in enumerate(chunks)]
            for future in as_completed(futures):
                if stop_event.is_set():
                    break
    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n{Colors.YELLOW}[!] Interrupted.{Colors.RESET}")

    return found, found_word, total_attempts


# ──────────────────────────────────────────────
#  Hash Cracking
# ──────────────────────────────────────────────
def crack_single_hash(
    target_hash: str, hash_type: str, wordlist_path: str,
    verbose: bool = False, ext_salt: str = "", num_threads: int = 5
) -> dict:
    """Attempt to crack a single hash using the provided wordlist with multi-threading."""
    result = {
        "hash": target_hash,
        "type": hash_type,
        "category": "",
        "password": None,
        "attempts": 0,
        "time": 0.0,
        "speed": 0.0,
        "status": "not_found"
    }

    if not os.path.isfile(wordlist_path):
        print(f"{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.RESET}")
        return result

    target_norm = target_hash.strip().lower()
    is_crypt = hash_type in CRYPT_TYPES
    is_salted = hash_type in SALTED_TYPES
    salt = ext_salt or extract_salt(target_hash, hash_type)

    # Warn if salt is needed but not provided
    if is_salted and not salt and hash_type in SALTED_TYPES:
        print(f"{Colors.YELLOW}[!] This hash type requires a salt. Use -s/--salt to provide one.{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Cracking without salt will likely fail for: {hash_type}{Colors.RESET}")

    # Count lines
    total = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in f: total += 1
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading wordlist: {e}{Colors.RESET}")
        return result

    cat = HASH_DB.get(hash_type, {}).get("cat", 0)
    cat_name = CATEGORY_NAMES.get(cat, "Unknown")
    result["category"] = cat_name

    print(f"{Colors.BLUE}[*] Starting crack for {Colors.BOLD}{hash_type}{Colors.RESET}{Colors.BLUE} [{cat_name}]...{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Target: {target_hash}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Wordlist: {wordlist_path} ({total:,} entries){Colors.RESET}")
    print(f"{Colors.BLUE}[*] Threads: {num_threads}{Colors.RESET}")
    if salt:
        print(f"{Colors.BLUE}[*] Salt: {salt}{Colors.RESET}")
    print()

    start = time.time()

    # For crypt types that need the full hash for crypt.crypt(), use single-threaded
    if is_crypt or num_threads <= 1:
        found, word, attempts = _crack_single_thread(
            target_hash, target_norm, hash_type, wordlist_path,
            is_crypt, is_salted, salt, verbose, total, start
        )
    else:
        found, word, attempts = _crack_multi_thread(
            target_hash, target_norm, hash_type, wordlist_path,
            is_salted, salt, verbose, total, num_threads, start
        )

    elapsed = time.time() - start
    rate = attempts / elapsed if elapsed > 0 else 0

    result["attempts"] = attempts
    result["time"] = round(elapsed, 2)
    result["speed"] = round(rate, 1)

    if found:
        result["password"] = word
        result["status"] = "cracked"
        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] HASH CRACKED!{Colors.RESET}")
        print(f"{Colors.GREEN}    Password : {Colors.BOLD}{word}{Colors.RESET}")
        print(f"{Colors.GREEN}    Hash Type: {hash_type}{Colors.RESET}")
        print(f"{Colors.GREEN}    Category : {cat_name}{Colors.RESET}")
        print(f"{Colors.GREEN}    Attempts : {attempts:,}{Colors.RESET}")
        print(f"{Colors.GREEN}    Time     : {elapsed:.2f}s{Colors.RESET}")
        print(f"{Colors.GREEN}    Speed    : {rate:,.0f} hash/sec{Colors.RESET}")
        print(f"{Colors.GREEN}    Threads  : {num_threads}{Colors.RESET}")
    else:
        result["status"] = "not_found"
        print(f"\n{Colors.RED}[-] Password not found in wordlist.{Colors.RESET}")
        print(f"{Colors.RED}    Attempts: {attempts:,} | Time: {elapsed:.2f}s | Speed: {rate:,.0f} h/s | Threads: {num_threads}{Colors.RESET}")

    return result


# ──────────────────────────────────────────────
#  Batch Mode
# ──────────────────────────────────────────────
def crack_from_file(file_path: str, wordlist_path: str, hash_type_override: Optional[str], verbose: bool, num_threads: int = 5):
    if not os.path.isfile(file_path):
        print(f"{Colors.RED}[!] Hash file not found: {file_path}{Colors.RESET}")
        return []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]

    print(f"{Colors.BLUE}[*] Loaded {len(lines)} hash(es) from {file_path}{Colors.RESET}\n")
    results = []

    for i, line in enumerate(lines, 1):
        if ":" in line:
            parts = line.rsplit(":", 1)
            target_hash, user_type = parts[0].strip(), parts[1].strip()
        else:
            target_hash, user_type = line.strip(), None

        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}[Hash {i}/{len(lines)}]{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        if hash_type_override:
            hash_type = hash_type_override
        elif user_type:
            hash_type = user_type
        else:
            detected = detect_hash_type(target_hash)
            if not detected:
                print(f"{Colors.RED}[!] Could not detect hash type for: {target_hash}{Colors.RESET}")
                results.append({
                    "hash": target_hash, "type": "", "category": "",
                    "password": None, "attempts": 0, "time": 0.0,
                    "speed": 0.0, "status": "not_found"
                })
                continue
            hash_type = detected[0][0]
            if len(detected) > 1:
                print(f"{Colors.YELLOW}[*] Detected: {hash_type} (most likely of {len(detected)} candidates){Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[*] Detected: {hash_type}{Colors.RESET}")

        res = crack_single_hash(target_hash, hash_type, wordlist_path, verbose, num_threads=num_threads)
        results.append(res)
        print()

    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  CRACKING SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    cracked = sum(1 for r in results if r.get("status") == "cracked")
    total = len(results)
    for r in results:
        pw = r.get("password")
        st = f"{Colors.GREEN}{pw}{Colors.RESET}" if pw else f"{Colors.RED}Not found{Colors.RESET}"
        print(f"  {r.get('type', 'Unknown'):<25} | {r.get('hash', '')[:40]:<42} | {st}")
    if total:
        print(f"\n  Cracked: {Colors.GREEN}{cracked}{Colors.RESET}/{total} ({cracked/total*100:.0f}%)")

    return results


# ──────────────────────────────────────────────
#  Output Writers
# ──────────────────────────────────────────────
SUPPORTED_FORMATS = ["txt", "json", "csv", "html", "xml", "md"]

def detect_output_format(output_path: str, explicit_format: Optional[str] = None) -> str:
    """Detect output format from file extension or use explicit format."""
    if explicit_format:
        return explicit_format.lower()
    ext = os.path.splitext(output_path)[1].lstrip(".").lower()
    if ext in SUPPORTED_FORMATS:
        return ext
    return "txt"  # default


def write_output(results: list, output_path: str, fmt: str = "txt"):
    """Write cracking results to a file in the specified format."""
    if fmt == "txt":
        _write_txt(results, output_path)
    elif fmt == "json":
        _write_json(results, output_path)
    elif fmt == "csv":
        _write_csv(results, output_path)
    elif fmt == "html":
        _write_html(results, output_path)
    elif fmt == "xml":
        _write_xml(results, output_path)
    elif fmt == "md":
        _write_markdown(results, output_path)
    else:
        _write_txt(results, output_path)

    print(f"{Colors.GREEN}[+] Results written to: {output_path} ({fmt} format){Colors.RESET}")


def _write_txt(results, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("DonHash v1.1 - Cracking Results\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            f.write(f"Hash     : {r['hash']}\n")
            f.write(f"Type     : {r['type']}\n")
            f.write(f"Category : {r['category']}\n")
            f.write(f"Status   : {r['status']}\n")
            if r['password']:
                f.write(f"Password : {r['password']}\n")
            else:
                f.write("Password : (not found)\n")
            f.write(f"Attempts : {r['attempts']:,}\n")
            f.write(f"Time     : {r['time']}s\n")
            f.write(f"Speed    : {r['speed']:,.0f} h/s\n")
            f.write("-" * 70 + "\n")
        cracked = sum(1 for r in results if r['status'] == 'cracked')
        total = len(results)
        pct = cracked / total * 100 if total else 0
        f.write(f"\nSummary: {cracked}/{total} cracked ({pct:.0f}%)\n")


def _write_json(results, path):
    data = {
        "tool": "DonHash",
        "version": "1.1",
        "generated": datetime.now().isoformat(),
        "results": results,
        "summary": {
            "total": len(results),
            "cracked": sum(1 for r in results if r['status'] == 'cracked'),
            "not_found": sum(1 for r in results if r['status'] == 'not_found')
        }
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["hash", "type", "category", "status", "password", "attempts", "time", "speed"])
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def _write_html(results, path):
    cracked = sum(1 for r in results if r['status'] == 'cracked')
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DonHash v1.1 - Cracking Results</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
  h1 {{ color: #00ffcc; text-align: center; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }}
  h2 {{ color: #ff6600; }}
  .summary {{ background: #1a1a2e; padding: 15px; border-radius: 8px; margin: 20px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th {{ background: #16213e; color: #00ffcc; padding: 12px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #333; }}
  tr:hover {{ background: #1a1a2e; }}
  .cracked {{ color: #00ff66; font-weight: bold; }}
  .not-found {{ color: #ff4444; }}
  .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>DonHash v1.1 - Cracking Results</h1>
<div class="summary">
  <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
  <p><strong>Total:</strong> {len(results)} | <strong>Cracked:</strong> {cracked} | <strong>Not Found:</strong> {len(results) - cracked}</p>
</div>
<h2>Results</h2>
<table>
<tr><th>Hash</th><th>Type</th><th>Category</th><th>Status</th><th>Password</th><th>Attempts</th><th>Time</th><th>Speed</th></tr>
"""
    for r in results:
        status_class = "cracked" if r['status'] == 'cracked' else "not-found"
        pw = r['password'] if r['password'] else "(not found)"
        html += f'<tr><td><code>{r["hash"][:60]}</code></td><td>{r["type"]}</td><td>{r["category"]}</td>'
        html += f'<td class="{status_class}">{r["status"]}</td><td class="{status_class}">{pw}</td>'
        html += f'<td>{r["attempts"]:,}</td><td>{r["time"]}s</td><td>{r["speed"]:,.0f} h/s</td></tr>\n'
    html += """</table>
<div class="footer">DonHash v1.1 | Author: CySec Don | cysecdon@gmail.com</div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def _write_xml(results, path):
    root = ET.Element("donhash-results")
    root.set("version", "1.1")
    root.set("generated", datetime.now().isoformat())

    summary = ET.SubElement(root, "summary")
    ET.SubElement(summary, "total").text = str(len(results))
    ET.SubElement(summary, "cracked").text = str(sum(1 for r in results if r['status'] == 'cracked'))

    for r in results:
        entry = ET.SubElement(root, "result")
        for key in ["hash", "type", "category", "status", "password", "attempts", "time", "speed"]:
            elem = ET.SubElement(entry, key)
            val = r.get(key, "")
            elem.text = str(val) if val is not None else ""

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="unicode", xml_declaration=True)


def _write_markdown(results, path):
    cracked = sum(1 for r in results if r['status'] == 'cracked')
    total = len(results)
    pct = cracked / total * 100 if total else 0
    with open(path, "w", encoding="utf-8") as f:
        f.write("# DonHash v1.1 - Cracking Results\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Summary:** {cracked}/{total} cracked ({pct:.0f}%)\n\n")
        f.write("| Hash | Type | Category | Status | Password | Attempts | Time | Speed |\n")
        f.write("|------|------|----------|--------|----------|----------|------|-------|\n")
        for r in results:
            pw = r['password'] if r['password'] else "(not found)"
            f.write(f"| `{r['hash'][:50]}` | {r['type']} | {r['category']} | {r['status']} | {pw} | {r['attempts']:,} | {r['time']}s | {r['speed']:,.0f} h/s |\n")


# ──────────────────────────────────────────────
#  Main CLI
# ──────────────────────────────────────────────
def find_rockyou() -> str:
    for p in ["/usr/share/wordlists/rockyou.txt", "/opt/rockyou.txt",
              os.path.expanduser("~/rockyou.txt"), "./rockyou.txt"]:
        if os.path.isfile(p): return p
    return "rockyou.txt"


def list_categories():
    """Print all 30 categories with hash counts."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  30 HASH CATEGORIES{Colors.RESET}\n")
    for cat_id in range(1, 31):
        name = CATEGORY_NAMES.get(cat_id, "Unknown")
        count = sum(1 for v in HASH_DB.values() if v["cat"] == cat_id)
        print(f"  {Colors.YELLOW}{cat_id:>2}.{Colors.RESET} {Colors.WHITE}{name:<40}{Colors.RESET} {Colors.GREEN}({count} types){Colors.RESET}")
    total = len(HASH_DB)
    print(f"\n  {Colors.BOLD}{Colors.CYAN}Total: {total} hash types{Colors.RESET}\n")


def list_hash_types(filter_cat: Optional[int] = None):
    """Print all hash types, optionally filtered by category."""
    cats = range(1, 31) if filter_cat is None else [filter_cat]
    for cat_id in cats:
        name = CATEGORY_NAMES.get(cat_id, "Unknown")
        types = [(k, v) for k, v in HASH_DB.items() if v["cat"] == cat_id]
        if not types: continue
        print(f"\n{Colors.CYAN}{Colors.BOLD}  [{cat_id}] {name}{Colors.RESET}")
        print(f"  {'-'*50}")
        for tname, tinfo in types:
            crackable = compute_hash("test", tname) is not None or tname in CRYPT_TYPES or tname in SALTED_TYPES
            tag = f"{Colors.GREEN}crack{Colors.RESET}" if crackable else f"{Colors.YELLOW}detect{Colors.RESET}"
            print(f"    {tname:<35} {tinfo['desc']:<45} [{tag}]")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="DonHash v1.1 — Hash Detector & Cracker — 500+ hash types, 30 categories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -w custom_wordlist.txt
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -T 20 -o results.json
  %(prog)s -f hashes.txt -w rockyou.txt -v -T 10
  %(prog)s -f hashes.txt -o results.html
  %(prog)s -f hashes.txt -o output.csv --format csv
  %(prog)s --list-categories
  %(prog)s --list-types
  %(prog)s --list-types --category 3
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("-H", "--hash", dest="target_hash", help="Single hash to crack")
    input_group.add_argument("-f", "--file", help="File with hashes (one per line)")

    parser.add_argument("-w", "--wordlist", default=None, help="Path to wordlist (default: rockyou.txt)")
    parser.add_argument("-t", "--type", dest="hash_type", help="Force a specific hash type")
    parser.add_argument("-s", "--salt", default="", help="Salt for salted hash types")
    parser.add_argument("-T", "--threads", type=int, default=5, choices=range(1, 101),
                        metavar="1-100", help="Number of threads for cracking (default: 5)")
    parser.add_argument("-o", "--output", help="Output file path for results")
    parser.add_argument("--format", dest="output_format", default=None,
                        choices=["txt", "json", "csv", "html", "xml", "md"],
                        help="Output format (default: auto-detect from file extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress while cracking")
    parser.add_argument("--detect-only", action="store_true", help="Only detect hash type(s)")
    parser.add_argument("--list-categories", action="store_true", help="List all 30 categories")
    parser.add_argument("--list-types", action="store_true", help="List all hash types")
    parser.add_argument("--category", type=int, default=None, help="Filter by category number (1-30)")

    args = parser.parse_args()

    if args.list_categories:
        list_categories()
        return

    if args.list_types:
        list_hash_types(args.category)
        return

    if not args.target_hash and not args.file:
        parser.print_help()
        return

    print_banner()

    wordlist = args.wordlist or find_rockyou()

    # ── Detect-only mode ──
    if args.detect_only:
        if args.target_hash:
            detected = detect_hash_type(args.target_hash)
            if detected:
                print(f"{Colors.YELLOW}[*] Possible hash types for: {args.target_hash}{Colors.RESET}\n")
                for idx, (htype, desc, cat) in enumerate(detected, 1):
                    cat_name = CATEGORY_NAMES.get(cat, "Unknown")
                    likely = f" {Colors.GREEN}(most likely){Colors.RESET}" if idx == 1 else ""
                    print(f"  {Colors.BOLD}{idx}.{Colors.RESET} {htype:<30} [{cat_name}] {desc}{likely}")
            else:
                print(f"{Colors.RED}[!] Could not detect hash type.{Colors.RESET}")
        return

    # ── Single hash mode ──
    if args.target_hash:
        target_hash = args.target_hash.strip()

        if args.hash_type:
            hash_type = args.hash_type
            # Find exact match in HASH_DB (case-insensitive)
            matches = [k for k in HASH_DB if k.lower() == hash_type.lower()]
            if matches:
                hash_type = matches[0]
            print(f"{Colors.YELLOW}[*] Using forced hash type: {hash_type}{Colors.RESET}")
        else:
            detected = detect_hash_type(target_hash)
            if not detected:
                print(f"{Colors.RED}[!] Could not detect hash type for: {target_hash}{Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Try specifying the type with -t (e.g., -t md5){Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Use --list-types to see all supported types{Colors.RESET}")
                sys.exit(1)

            hash_type = detected[0][0]
            if len(detected) == 1:
                cat_name = CATEGORY_NAMES.get(detected[0][2], "")
                print(f"{Colors.YELLOW}[*] Detected: {hash_type} [{cat_name}]{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[*] {len(detected)} possible types detected. Using: {hash_type} (most likely){Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Override with -t flag. Use --list-types to see all.{Colors.RESET}")

        result = crack_single_hash(target_hash, hash_type, wordlist, args.verbose,
                                   ext_salt=args.salt, num_threads=args.threads)

        # Handle output
        if args.output:
            results = [result] if result else []
            fmt = detect_output_format(args.output, args.output_format)
            write_output(results, args.output, fmt)

    # ── File mode ──
    elif args.file:
        hash_type_override = args.hash_type
        if hash_type_override:
            matches = [k for k in HASH_DB if k.lower() == hash_type_override.lower()]
            if matches:
                hash_type_override = matches[0]
        results = crack_from_file(args.file, wordlist, hash_type_override, args.verbose,
                                  num_threads=args.threads)

        # Handle output
        if args.output and results:
            fmt = detect_output_format(args.output, args.output_format)
            write_output(results, args.output, fmt)


if __name__ == "__main__":
    main()
