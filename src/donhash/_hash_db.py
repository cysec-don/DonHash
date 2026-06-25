"""Hash type registry — 491 hash types across 30 categories.

Each entry is keyed by a canonical name and stores:
    cat     - category id (1..30)
    desc    - human-readable description
    hex_len - length of the hex-encoded digest (None if variable)
    prefix  - literal prefix that identifies the hash (None if none)
    impl    - implementation status: 'compute' (crackable),
              'crypt' (needs crypt-style salt extraction),
              'salted' (needs external salt),
              'detect' (detection-only, no compute implementation)
"""

from __future__ import annotations

# Implementation status constants
COMPUTE = "compute"  # has a working compute_hash implementation
CRYPT = "crypt"      # needs crypt-style salt extraction
SALTED = "salted"    # needs an external salt supplied by user
DETECT = "detect"    # detection-only, no compute implementation

CATEGORY_NAMES: dict[int, str] = {
    1: "CRC / Checksum",
    2: "Non-Cryptographic",
    3: "MD Family & Variants",
    4: "SHA-1 & Variants",
    5: "SHA-2 Family",
    6: "SHA-3 / Keccak",
    7: "BLAKE Family",
    8: "RIPEMD / Tiger / Whirlpool / Skein / GOST",
    9: "HMAC Variants",
    10: "KDF / yescrypt",
    11: "Unix / Linux Crypt",
    12: "Windows Authentication",
    13: "Database Hashes",
    14: "CMS / Web Applications",
    15: "More CMS / Frameworks",
    16: "Cisco / Network / Firewall",
    17: "Network Protocols",
    18: "MS Office / PDF / Archives",
    19: "Archives & Documents",
    20: "TrueCrypt / VeraCrypt",
    21: "LUKS / DiskCryptor / FDE",
    22: "Apple / macOS / iOS",
    23: "Android / Mobile",
    24: "Cryptocurrency / Blockchain",
    25: "LDAP / Directory Services",
    26: "Password Managers / Vaults",
    27: "Application / Protocol / Other",
    28: "Legacy Variants",
    29: "More Cryptographic Functions",
    30: "Signatures",
}


class HashSpec:
    """Spec for a single hash type."""

    __slots__ = ("cat", "desc", "hex_len", "impl", "name", "prefix")

    def __init__(
        self,
        name: str,
        cat: int,
        desc: str,
        hex_len: int | None = None,
        prefix: str | None = None,
        impl: str = DETECT,
    ) -> None:
        self.name = name
        self.cat = cat
        self.desc = desc
        self.hex_len = hex_len
        self.prefix = prefix
        self.impl = impl

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"HashSpec(name={self.name!r}, cat={self.cat}, "
            f"hex_len={self.hex_len}, prefix={self.prefix!r}, impl={self.impl!r})"
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "cat": self.cat,
            "desc": self.desc,
            "hex_len": self.hex_len,
            "prefix": self.prefix,
            "impl": self.impl,
        }


# ─── Build the registry ──────────────────────────────────────────────────────
# Each tuple: (name, cat, desc, hex_len, prefix, impl)

_REGISTRY: list[tuple] = [
    # ── Category 1: CRC / Checksum ──
    ("CRC-16", 1, "CRC-16 (ARC/BIN)", 4, None, COMPUTE),
    ("CRC-16-CCITT", 1, "CRC-16-CCITT (poly 0x1021, init 0xFFFF)", 4, None, COMPUTE),
    ("CRC-16-IBM", 1, "CRC-16-IBM (reflected)", 4, None, COMPUTE),
    ("CRC-16-DNP", 1, "CRC-16-DNP", 4, None, COMPUTE),
    ("CRC-16-Modbus", 1, "CRC-16-Modbus", 4, None, COMPUTE),
    ("CRC-16-XMODEM", 1, "CRC-16-XMODEM", 4, None, COMPUTE),
    ("CRC-16-USB", 1, "CRC-16-USB", 4, None, COMPUTE),
    ("CRC-24", 1, "CRC-24 (OpenPGP)", 6, None, COMPUTE),
    ("CRC-32", 1, "CRC-32 (zlib/IEEE)", 8, None, COMPUTE),
    ("CRC-32B", 1, "CRC-32B (alternate)", 8, None, COMPUTE),
    ("CRC-32C", 1, "CRC-32C (Castagnoli)", 8, None, COMPUTE),
    ("CRC-32-MPEG-2", 1, "CRC-32-MPEG-2", 8, None, COMPUTE),
    ("CRC-32D", 1, "CRC-32D", 8, None, COMPUTE),
    ("CRC-32Q", 1, "CRC-32Q", 8, None, COMPUTE),
    ("CRC-40-GSM", 1, "CRC-40-GSM", 10, None, DETECT),
    ("CRC-64", 1, "CRC-64 (ECMA-182)", 16, None, COMPUTE),
    ("CRC-64-WE", 1, "CRC-64/WE", 16, None, DETECT),
    ("CRC-64-ISO", 1, "CRC-64/ISO", 16, None, COMPUTE),
    ("CRC-64-Jones", 1, "CRC-64/Jones", 16, None, COMPUTE),
    ("Adler-32", 1, "Adler-32", 8, None, COMPUTE),

    # ── Category 2: Non-Cryptographic ──
    ("Jenkins", 2, "Jenkins one-at-a-time", 8, None, COMPUTE),
    ("MurmurHash32", 2, "MurmurHash3 32-bit", 8, None, DETECT),
    ("MurmurHash64", 2, "MurmurHash3 64-bit", 16, None, DETECT),
    ("MurmurHash3", 2, "MurmurHash3 x86 32-bit", 8, None, DETECT),
    ("FNV-1-32", 2, "FNV-1 32-bit", 8, None, COMPUTE),
    ("FNV-1-64", 2, "FNV-1 64-bit", 16, None, COMPUTE),
    ("FNV-1a-32", 2, "FNV-1a 32-bit", 8, None, COMPUTE),
    ("FNV-1a-64", 2, "FNV-1a 64-bit", 16, None, COMPUTE),
    ("FNV-132", 2, "FNV-1 32-bit (alias)", 8, None, COMPUTE),
    ("FNV-164", 2, "FNV-1 64-bit (alias)", 16, None, COMPUTE),
    ("ELF-32", 2, "ELF-32", 8, None, COMPUTE),
    ("ELF-64", 2, "ELF-64", 16, None, DETECT),
    ("Joaat", 2, "Jenkins one-at-a-time (alias)", 8, None, COMPUTE),
    ("DJB2", 2, "Bernstein DJB2", 8, None, COMPUTE),
    ("SDBM", 2, "SDBM hash", 8, None, COMPUTE),
    ("Zobrist", 2, "Zobrist hashing", None, None, DETECT),
    ("JavaHashCode", 2, "Java String.hashCode()", 8, None, COMPUTE),
    ("CityHash", 2, "Google CityHash64", 16, None, DETECT),
    ("xxHash64", 2, "xxHash 64-bit", 16, None, DETECT),
    ("xxHash3-128", 2, "xxHash3 128-bit", 32, None, DETECT),

    # ── Category 3: MD Family & Variants ──
    ("MD2", 3, "MD2 (RFC 1319, deprecated)", 32, None, DETECT),
    ("MD4", 3, "MD4 (RFC 1320)", 32, None, COMPUTE),
    ("MD5", 3, "MD5 (RFC 1321)", 32, None, COMPUTE),
    ("MD6", 3, "MD6", None, None, DETECT),
    ("Half-MD5", 3, "Half MD5 (16 hex)", 16, None, COMPUTE),
    ("Double-MD5", 3, "MD5(MD5(pass))", 32, None, COMPUTE),
    ("Triple-MD5", 3, "MD5(MD5(MD5(pass))) — explicit form", 32, None, COMPUTE),
    ("md5(md5(md5($pass)))", 3, "MD5(MD5(MD5(pass))) — Hashcat form", 32, None, COMPUTE),
    ("md5(pass.salt)", 3, "MD5(pass.salt)", 32, None, SALTED),
    ("md5(salt.pass)", 3, "MD5(salt.pass)", 32, None, SALTED),
    ("md5(unicode(pass).salt)", 3, "MD5(UTF-16LE(pass).salt)", 32, None, SALTED),
    ("md5(salt.unicode(pass))", 3, "MD5(salt.UTF-16LE(pass))", 32, None, SALTED),
    ("md5(salt.pass.$salt)", 3, "MD5(salt.pass.salt)", 32, None, SALTED),
    ("md5(md5(pass).md5(salt))", 3, "MD5(MD5(pass).MD5(salt))", 32, None, SALTED),
    ("md5(md5(salt).pass)", 3, "MD5(MD5(salt).pass)", 32, None, SALTED),
    ("md5(salt.md5(pass))", 3, "MD5(salt.MD5(pass))", 32, None, SALTED),
    ("md5(pass.md5(salt))", 3, "MD5(pass.MD5(salt))", 32, None, SALTED),
    ("md5(salt.md5(salt.$pass))", 3, "MD5(salt.MD5(salt.pass))", 32, None, SALTED),
    ("md5(salt.md5(pass.$salt))", 3, "MD5(salt.MD5(pass.salt))", 32, None, SALTED),
    ("md5(username.0.pass)", 3, "MD5(username.0.pass)", 32, None, SALTED),
    ("md5(sha1($pass))", 3, "MD5(SHA1(pass))", 32, None, COMPUTE),
    ("md5(strtoupper(md5))", 3, "MD5(upper(MD5(pass)))", 32, None, COMPUTE),
    ("md5(sha1(md5($pass)))", 3, "MD5(SHA1(MD5(pass)))", 32, None, COMPUTE),
    ("MD5(Crypt)", 3, "MD5-crypt ($1$)", None, "$1$", CRYPT),
    ("MD5(APR)", 3, "Apache MD5-crypt ($apr1$)", None, "$apr1$", CRYPT),

    # ── Category 4: SHA-1 & Variants ──
    ("SHA-0", 4, "SHA-0", 40, None, DETECT),
    ("SHA-1", 4, "SHA-1", 40, None, COMPUTE),
    ("Double-SHA1", 4, "SHA1(SHA1(pass))", 40, None, COMPUTE),
    ("Triple-SHA1", 4, "SHA1(SHA1(SHA1(pass))) — explicit form", 40, None, COMPUTE),
    ("sha1(sha1(sha1($pass)))", 4, "SHA1(SHA1(SHA1(pass))) — Hashcat form", 40, None, COMPUTE),
    ("sha1(pass.salt)", 4, "SHA1(pass.salt)", 40, None, SALTED),
    ("sha1(salt.pass)", 4, "SHA1(salt.pass)", 40, None, SALTED),
    ("sha1(unicode(pass).salt)", 4, "SHA1(UTF-16LE(pass).salt)", 40, None, SALTED),
    ("sha1(salt.unicode(pass))", 4, "SHA1(salt.UTF-16LE(pass))", 40, None, SALTED),
    ("sha1(salt.pass.$salt)", 4, "SHA1(salt.pass.salt)", 40, None, SALTED),
    ("sha1(md5($pass))", 4, "SHA1(MD5(pass))", 40, None, COMPUTE),
    ("sha1(sha1(salt.pass.$salt))", 4, "SHA1(SHA1(salt.pass.salt))", 40, None, SALTED),
    ("SHA1-Base64", 4, "SHA-1 (Base64)", None, None, COMPUTE),
    ("SHA-1(Crypt)", 4, "SHA-1-crypt ($sha1$)", None, "$sha1$", CRYPT),
    ("LinkedIn", 4, "LinkedIn unsalted SHA-1", 40, None, COMPUTE),
    ("Netscape-LDAP-SHA", 4, "Netscape LDAP {SHA}", None, "{SHA}", CRYPT),
    ("SSHA1-Base64", 4, "SSHA-1 (Base64)", None, "{SSHA}", CRYPT),
    ("sha1(CX)", 4, "sha1(CX)", 40, None, DETECT),
    ("SHA-1(Oracle)", 4, "Oracle SHA-1", None, None, DETECT),
    ("sha1(sha1(pass).salt)", 4, "SHA1(SHA1(pass).salt)", 40, None, SALTED),

    # ── Category 5: SHA-2 Family ──
    ("SHA-224", 5, "SHA-224", 56, None, COMPUTE),
    ("SHA-256", 5, "SHA-256", 64, None, COMPUTE),
    ("SHA-384", 5, "SHA-384", 96, None, COMPUTE),
    ("SHA-512", 5, "SHA-512", 128, None, COMPUTE),
    ("SHA-512/224", 5, "SHA-512/224", 56, None, COMPUTE),
    ("SHA-512/256", 5, "SHA-512/256", 64, None, COMPUTE),
    ("sha256(pass.salt)", 5, "SHA-256(pass.salt)", 64, None, SALTED),
    ("sha256(salt.pass)", 5, "SHA-256(salt.pass)", 64, None, SALTED),
    ("sha512(pass.salt)", 5, "SHA-512(pass.salt)", 128, None, SALTED),
    ("sha512(salt.pass)", 5, "SHA-512(salt.pass)", 128, None, SALTED),
    ("sha256(unicode(pass).salt)", 5, "SHA-256(UTF-16LE.salt)", 64, None, SALTED),
    ("sha512(unicode(pass).salt)", 5, "SHA-512(UTF-16LE.salt)", 128, None, SALTED),
    ("SHA-256(Crypt)", 5, "SHA-256-crypt ($5$)", None, "$5$", CRYPT),
    ("SHA-512(Crypt)", 5, "SHA-512-crypt ($6$)", None, "$6$", CRYPT),
    ("sha256(salt.unicode(pass))", 5, "SHA-256(salt.UTF-16LE)", 64, None, SALTED),

    # ── Category 6: SHA-3 / Keccak ──
    ("SHA3-224", 6, "SHA3-224 (FIPS 202)", 56, None, COMPUTE),
    ("SHA3-256", 6, "SHA3-256", 64, None, COMPUTE),
    ("SHA3-384", 6, "SHA3-384", 96, None, COMPUTE),
    ("SHA3-512", 6, "SHA3-512", 128, None, COMPUTE),
    ("SHAKE128", 6, "SHAKE128", None, None, COMPUTE),
    ("SHAKE256", 6, "SHAKE256", None, None, COMPUTE),
    ("Keccak-256", 6, "Keccak-256 (pre-FIPS)", 64, None, DETECT),
    ("Keccak-512", 6, "Keccak-512 (pre-FIPS)", 128, None, DETECT),
    ("Raw-Keccak-256", 6, "Raw Keccak-256", 64, None, DETECT),
    ("Raw-Keccak-512", 6, "Raw Keccak-512", 128, None, DETECT),
    ("SHA3-Keccak", 6, "SHA-3 / Keccak (generic)", None, None, DETECT),
    ("Keccak-r40-c160", 6, "Keccak[r=40,c=160]", None, None, DETECT),

    # ── Category 7: BLAKE Family ──
    ("BLAKE-256", 7, "BLAKE-256", 64, None, DETECT),
    ("BLAKE-512", 7, "BLAKE-512", 128, None, DETECT),
    ("BLAKE2b", 7, "BLAKE2b (64-byte digest)", 128, None, COMPUTE),
    ("BLAKE2b-256", 7, "BLAKE2b (32-byte digest)", 64, None, COMPUTE),
    ("BLAKE2b-512", 7, "BLAKE2b (64-byte digest, alias)", 128, None, COMPUTE),
    ("BLAKE2s", 7, "BLAKE2s (32-byte digest)", 64, None, COMPUTE),
    ("BLAKE2s-128", 7, "BLAKE2s (16-byte digest)", 32, None, COMPUTE),
    ("BLAKE2s-256", 7, "BLAKE2s (32-byte, alias)", 64, None, COMPUTE),
    ("BLAKE2bp", 7, "BLAKE2bp (parallel)", 128, None, DETECT),
    ("BLAKE3-256", 7, "BLAKE3 (256-bit)", 64, None, DETECT),
    ("BLAKE3-512", 7, "BLAKE3 (512-bit)", 128, None, DETECT),

    # ── Category 8: RIPEMD/Tiger/Whirlpool/Skein/GOST ──
    ("RIPEMD-128", 8, "RIPEMD-128", 32, None, COMPUTE),
    ("RIPEMD-160", 8, "RIPEMD-160", 40, None, COMPUTE),
    ("RIPEMD-256", 8, "RIPEMD-256", 64, None, COMPUTE),
    ("RIPEMD-320", 8, "RIPEMD-320", 80, None, COMPUTE),
    ("Tiger-128", 8, "Tiger-128", 32, None, DETECT),
    ("Tiger-160", 8, "Tiger-160", 40, None, DETECT),
    ("Tiger-192", 8, "Tiger-192", 48, None, DETECT),
    ("Tiger2", 8, "Tiger2", 48, None, DETECT),
    ("Whirlpool", 8, "Whirlpool", 128, None, COMPUTE),
    ("Whirlpool-T", 8, "Whirlpool-T", 128, None, COMPUTE),
    ("Skein-256", 8, "Skein-256", 64, None, DETECT),
    ("Skein-512", 8, "Skein-512", 128, None, DETECT),
    ("Skein-1024", 8, "Skein-1024", 256, None, DETECT),
    ("Skein-256(512)", 8, "Skein-256(512)", 128, None, DETECT),
    ("Skein-512(256)", 8, "Skein-512(256)", 64, None, DETECT),
    ("Snefru-128", 8, "Snefru-128", 32, None, DETECT),
    ("Snefru-256", 8, "Snefru-256", 64, None, DETECT),
    ("HAVAL-256", 8, "HAVAL-256", 64, None, DETECT),
    ("Streebog-256", 8, "GOST R 34.11-2012 Streebog-256", 64, None, COMPUTE),
    ("Streebog-512", 8, "GOST R 34.11-2012 Streebog-512", 128, None, COMPUTE),
    ("GOST-R-34.11-94", 8, "GOST R 34.11-94", 64, None, DETECT),

    # ── Category 9: HMAC Variants ──
    ("HMAC-MD5(pass)", 9, "HMAC-MD5 (key=pass)", 32, None, SALTED),
    ("HMAC-MD5(salt)", 9, "HMAC-MD5 (key=salt)", 32, None, SALTED),
    ("HMAC-SHA1(pass)", 9, "HMAC-SHA1 (key=pass)", 40, None, SALTED),
    ("HMAC-SHA1(salt)", 9, "HMAC-SHA1 (key=salt)", 40, None, SALTED),
    ("HMAC-SHA256(pass)", 9, "HMAC-SHA256 (key=pass)", 64, None, SALTED),
    ("HMAC-SHA256(salt)", 9, "HMAC-SHA256 (key=salt)", 64, None, SALTED),
    ("HMAC-SHA512(pass)", 9, "HMAC-SHA512 (key=pass)", 128, None, SALTED),
    ("HMAC-SHA512(salt)", 9, "HMAC-SHA512 (key=salt)", 128, None, SALTED),
    ("HMAC-RIPEMD160(pass)", 9, "HMAC-RIPEMD160 (key=pass)", 40, None, SALTED),
    ("HMAC-RIPEMD160(salt)", 9, "HMAC-RIPEMD160 (key=salt)", 40, None, SALTED),
    ("HMAC-Tiger", 9, "HMAC-Tiger", 48, None, DETECT),
    ("HMAC-Whirlpool", 9, "HMAC-Whirlpool", 128, None, DETECT),
    ("HMAC-GOST", 9, "HMAC-GOST", 64, None, DETECT),
    ("HMAC-Streebog-256(pass)", 9, "HMAC-Streebog-256 (key=pass)", 64, None, SALTED),
    ("HMAC-Streebog-256(salt)", 9, "HMAC-Streebog-256 (key=salt)", 64, None, SALTED),
    ("HMAC-Streebog-512(pass)", 9, "HMAC-Streebog-512 (key=pass)", 128, None, SALTED),
    ("HMAC-Streebog-512(salt)", 9, "HMAC-Streebog-512 (key=salt)", 128, None, SALTED),
    ("HMAC-Skein-256", 9, "HMAC-Skein-256", 64, None, DETECT),
    ("HMAC-Skein-512", 9, "HMAC-Skein-512", 128, None, DETECT),
    ("HMAC-SHA3-256", 9, "HMAC-SHA3-256", 64, None, SALTED),

    # ── Category 10: KDF / yescrypt ──
    ("yescrypt", 10, "yescrypt", None, "$y$", DETECT),
    ("yescrypt-v1", 10, "yescrypt v1", None, "$y$1$", DETECT),
    ("yescrypt-v2", 10, "yescrypt v2", None, "$y$2$", DETECT),
    ("gost-yescrypt", 10, "gost-yescrypt", None, "$gy$", DETECT),
    ("scrypt", 10, "scrypt", None, "$scrypt$", DETECT),
    ("scrypt-Colin", 10, "scrypt (Colin Percival $7$)", None, "$7$", DETECT),
    ("scrypt-Litecoin", 10, "scrypt (Litecoin)", None, None, DETECT),
    ("scrypt-Dogecoin", 10, "scrypt (Dogecoin)", None, None, DETECT),
    ("bcrypt", 10, "bcrypt 2a", None, "$2a$", CRYPT),
    ("bcrypt-2b", 10, "bcrypt 2b", None, "$2b$", CRYPT),
    ("bcrypt-2x", 10, "bcrypt 2x", None, "$2x$", CRYPT),
    ("bcrypt-2y", 10, "bcrypt 2y", None, "$2y$", CRYPT),
    ("bcrypt-OpenBSD", 10, "bcrypt-OpenBSD", None, "$2b$", CRYPT),
    ("bcrypt(SHA256)", 10, "bcrypt(SHA-256 pre-hash)", None, "$2b$", CRYPT),
    ("bcrypt(SHA512)", 10, "bcrypt(SHA-512 pre-hash)", None, "$2b$", CRYPT),
    ("PBKDF2-HMAC-MD5", 10, "PBKDF2-HMAC-MD5", None, None, SALTED),
    ("PBKDF2-HMAC-SHA1", 10, "PBKDF2-HMAC-SHA1", None, None, SALTED),
    ("PBKDF2-HMAC-SHA256", 10, "PBKDF2-HMAC-SHA256", None, None, SALTED),
    ("PBKDF2-HMAC-SHA512", 10, "PBKDF2-HMAC-SHA512", None, None, SALTED),
    ("PBKDF2-HMAC-RIPEMD160", 10, "PBKDF2-HMAC-RIPEMD160", None, None, SALTED),
    ("Argon2", 10, "Argon2 (autodetect)", None, "$argon2", CRYPT),
    ("Argon2d", 10, "Argon2d", None, "$argon2d", CRYPT),
    ("Argon2i", 10, "Argon2i", None, "$argon2i", CRYPT),
    ("Argon2id", 10, "Argon2id", None, "$argon2id", CRYPT),
    ("Balloon", 10, "Balloon hashing", None, None, DETECT),

    # ── Category 11: Unix / Linux crypt ──
    ("descrypt", 11, "Traditional DES crypt", None, None, DETECT),
    ("bigcrypt", 11, "bigcrypt", None, None, DETECT),
    ("BSDi-Crypt", 11, "BSDi crypt", None, "_", DETECT),
    ("Crypt16", 11, "Crypt16", None, None, DETECT),
    ("Unix-DES", 11, "Unix DES crypt", None, None, DETECT),
    ("Unix-MD5", 11, "Unix MD5-crypt", None, "$1$", CRYPT),
    ("Unix-Blowfish", 11, "Unix Blowfish-crypt", None, "$2a$", CRYPT),
    ("Unix-SHA256", 11, "Unix SHA-256-crypt", None, "$5$", CRYPT),
    ("Unix-SHA512", 11, "Unix SHA-512-crypt", None, "$6$", CRYPT),
    ("AIX-smd5", 11, "AIX {smd5}", None, "{smd5}", DETECT),
    ("AIX-ssha1", 11, "AIX {ssha1}", None, "{ssha1}", DETECT),
    ("AIX-ssha256", 11, "AIX {ssha256}", None, "{ssha256}", DETECT),
    ("AIX-ssha512", 11, "AIX {ssha512}", None, "{ssha512}", DETECT),
    ("GRUB2-pbkdf2", 11, "GRUB 2 pbkdf2", None, "grub.pbkdf2", DETECT),

    # ── Category 12: Windows Authentication ──
    ("LM", 12, "LANMAN (LM) hash", 32, None, COMPUTE),
    ("NTLM", 12, "NTLM hash", 32, None, COMPUTE),
    ("NT", 12, "NT hash (alias)", 32, None, COMPUTE),
    ("NTLMv1", 12, "NTLMv1 response", None, None, DETECT),
    ("NTLMv2", 12, "NTLMv2 response", None, None, DETECT),
    ("NetNTLMv1", 12, "NetNTLMv1", None, None, DETECT),
    ("NetNTLMv1+ESS", 12, "NetNTLMv1+ESS", None, None, DETECT),
    ("NetNTLMv2", 12, "NetNTLMv2", None, None, DETECT),
    ("DCC", 12, "Domain Cached Credentials v1", 32, None, DETECT),
    ("DCC2", 12, "Domain Cached Credentials v2", None, None, DETECT),
    ("MS-Cache", 12, "MS Cache v1", 32, None, DETECT),
    ("MS-Cache2", 12, "MS Cache v2", 32, None, DETECT),
    ("SAM", 12, "SAM (LM:NT)", None, None, DETECT),
    ("WinPhone8-PIN", 12, "Windows Phone 8+ PIN", None, None, DETECT),
    ("Kerberos-AS-REQ-23", 12, "Kerberos 5 AS-REQ (etype 23)", None, None, DETECT),
    ("Kerberos-TGS-REP-23", 12, "Kerberos 5 TGS-REP (etype 23)", None, None, DETECT),
    ("Kerberos-etype17", 12, "Kerberos 5 etype 17", None, None, DETECT),
    ("Kerberos-etype18", 12, "Kerberos 5 etype 18", None, None, DETECT),

    # ── Category 13: Database Hashes ──
    ("MySQL323", 13, "MySQL 323 (legacy)", 16, None, COMPUTE),
    ("MySQL4.1", 13, "MySQL 4.1+ SHA1(SHA1(pass))", None, None, COMPUTE),  # detection by strict regex in detector.py (no loose '*' prefix)
    ("MySQL5.x", 13, "MySQL 5.x SHA1(SHA1(pass))", 40, None, COMPUTE),
    ("MySQL-CR-SHA1", 13, "MySQL Challenge-Response SHA1", None, None, DETECT),
    ("MSSQL-2000", 13, "MSSQL 2000", None, "0x0100", DETECT),
    ("MSSQL-2005", 13, "MSSQL 2005", None, "0x0100", DETECT),
    ("MSSQL-2008", 13, "MSSQL 2008", None, "0x0100", DETECT),
    ("MSSQL-2012", 13, "MSSQL 2012", None, "0x0200", DETECT),
    ("MSSQL-2014", 13, "MSSQL 2014", None, "0x0200", DETECT),
    ("MSSQL-2016", 13, "MSSQL 2016", None, "0x0200", DETECT),
    ("Oracle-7-10g", 13, "Oracle 7-10g", None, None, DETECT),
    ("Oracle-11g-12c", 13, "Oracle 11g/12c (S: prefix)", None, "S:", DETECT),
    ("Oracle-12c+", 13, "Oracle 12c+", None, None, DETECT),
    ("Oracle-H-Type", 13, "Oracle H: Type", None, None, DETECT),
    ("Oracle-TM-SHA256", 13, "Oracle TM SHA-256", None, None, DETECT),
    ("PostgreSQL-MD5", 13, "PostgreSQL MD5 (md5+MD5(pass+salt))", None, "md5", SALTED),
    ("PostgreSQL-CR-MD5", 13, "PostgreSQL Challenge-Response MD5", None, None, DETECT),
    ("PostgreSQL-SCRAM", 13, "PostgreSQL SCRAM-SHA-256", None, "SCRAM-SHA-256$", DETECT),
    ("Sybase-ASE", 13, "Sybase ASE", None, None, DETECT),
    ("SAP-BCODE", 13, "SAP CODVN B (BCODE)", None, None, DETECT),

    # ── Category 14: CMS / Web Applications ──
    ("SAP-PASSCODE", 14, "SAP CODVN F/G (PASSCODE)", None, None, DETECT),
    ("SAP-ISSHA1", 14, "SAP CODVN H (PWDSALTEDHASH) iSSHA-1", None, None, DETECT),
    ("WordPress-phpass", 14, "WordPress MD5 (phpass $P$)", None, "$P$", CRYPT),
    ("WordPress-2.6.2+", 14, "WordPress >= v2.6.2", None, "$P$", CRYPT),
    ("WordPress-2.6.0", 14, "WordPress v2.6.0/2.6.1", None, "$H$", CRYPT),
    ("Joomla-MD5", 14, "Joomla MD5", 32, None, COMPUTE),
    ("Joomla-old", 14, "Joomla < v2.5.18", None, None, DETECT),
    ("Joomla-new", 14, "Joomla >= v2.5.18", None, "$2y$", CRYPT),
    ("Drupal-5-6", 14, "Drupal 5/6", 32, None, COMPUTE),
    ("Drupal-7", 14, "Drupal 7+ ($S$)", None, "$S$", DETECT),
    ("Drupal-8+", 14, "Drupal 8+", None, None, DETECT),
    ("Drupal-PBKDF2", 14, "Drupal PBKDF2", None, None, DETECT),
    ("phpBB3", 14, "phpBB v3.x ($H$)", None, "$H$", CRYPT),
    ("vBulletin-old", 14, "vBulletin < v3.8.5", None, None, DETECT),
    ("vBulletin-new", 14, "vBulletin >= v3.8.5", None, None, DETECT),
    ("IPBoard", 14, "IP.Board >= v2+", None, None, DETECT),
    ("MyBB", 14, "MyBB >= v1.2+", None, None, DETECT),
    ("SMF", 14, "SMF >= v1.1", None, None, DETECT),
    ("WBB3", 14, "Woltlab Burning Board 3.x", None, None, DETECT),
    ("WBB4", 14, "Woltlab Burning Board 4.x", None, None, DETECT),
    ("PrestaShop", 14, "PrestaShop", None, None, DETECT),
    ("osCommerce", 14, "osCommerce", None, None, DETECT),
    ("xtCommerce", 14, "xt:Commerce", None, None, DETECT),
    ("MediaWiki", 14, "MediaWiki", None, None, DETECT),
    ("Django(MD5)", 14, "Django MD5 (md5$salt$hash)", None, "md5$", CRYPT),
    ("Django(SHA-1)", 14, "Django SHA-1 (sha1$salt$hash)", None, "sha1$", CRYPT),
    ("Django(SHA-256)", 14, "Django SHA-256 (sha256$salt$hash)", None, "sha256$", CRYPT),

    # ── Category 15: More CMS / Frameworks ──
    ("Django(PBKDF2-SHA1)", 15, "Django PBKDF2-SHA1", None, "pbkdf2_sha1$", CRYPT),
    ("Django(PBKDF2-SHA256)", 15, "Django PBKDF2-SHA256", None, "pbkdf2_sha256$", CRYPT),
    ("Django(bcrypt)", 15, "Django bcrypt", None, "bcrypt$", CRYPT),
    ("Django(bcrypt-SHA256)", 15, "Django bcrypt-SHA256", None, "bcrypt_sha256$", CRYPT),
    ("WebEdition", 15, "WebEdition CMS", None, None, DETECT),
    ("Rails-RestfulAuth", 15, "Ruby on Rails Restful Auth", None, None, DETECT),
    ("Rails-Devise", 15, "Ruby on Rails Devise", None, "$2a$", CRYPT),
    ("Rails-Authlogic", 15, "Ruby on Rails Authlogic", None, None, DETECT),
    ("passlib-pbkdf2-sha512", 15, "passlib pbkdf2-sha512", None, "$pbkdf2-sha512$", CRYPT),
    ("passlib-pbkdf2-sha256", 15, "passlib pbkdf2-sha256", None, "$pbkdf2-sha256$", CRYPT),
    ("passlib-pbkdf2-sha1", 15, "passlib pbkdf2-sha1", None, "$pbkdf2$", CRYPT),
    ("passlib-bcrypt", 15, "passlib bcrypt", None, "$2a$", CRYPT),
    ("passlib-scrypt", 15, "passlib scrypt", None, "$scrypt$", CRYPT),
    ("Web2py-pbkdf2", 15, "Web2py pbkdf2-sha512", None, None, DETECT),
    ("PHPass", 15, "PHPass portable hash ($P$)", None, "$P$", CRYPT),

    # ── Category 16: Cisco / Network / Firewall ──
    ("Cisco-PIX", 16, "Cisco PIX MD5", None, None, DETECT),
    ("Cisco-ASA", 16, "Cisco ASA MD5", None, None, DETECT),
    ("Cisco-IOS-MD5", 16, "Cisco-IOS MD5 ($1$)", None, "$1$", CRYPT),
    ("Cisco-IOS-SHA256", 16, "Cisco-IOS SHA-256", None, "$4$", DETECT),
    ("Cisco-Type4", 16, "Cisco Type 4", None, "$4$", DETECT),
    ("Cisco-Type7", 16, "Cisco Type 7", None, None, DETECT),
    ("Cisco-Type8", 16, "Cisco Type 8 (PBKDF2)", None, "$8$", DETECT),
    ("Cisco-Type9", 16, "Cisco Type 9 (scrypt)", None, "$9$", DETECT),
    ("Cisco-VPN-PCF", 16, "Cisco VPN Client PCF", None, None, DETECT),
    ("Cisco-ISE-SHA256", 16, "Cisco-ISE SHA-256", None, None, DETECT),
    ("Juniper-Netscreen", 16, "Juniper Netscreen/SSG", None, None, DETECT),
    ("Fortigate", 16, "Fortigate FortiOS", None, None, DETECT),
    ("WPA-WPA2", 16, "WPA/WPA2 PSK", None, None, DETECT),
    ("WPA-WPA2-PMK", 16, "WPA/WPA2 PMK", 64, None, DETECT),
    ("WPA3", 16, "WPA3 SAE", None, None, DETECT),

    # ── Category 17: Network Protocols ──
    ("IKE-PSK-MD5", 17, "IKE-PSK MD5", None, None, DETECT),
    ("IKE-PSK-SHA1", 17, "IKE-PSK SHA1", None, None, DETECT),
    ("IPMI2-RAKP-SHA1", 17, "IPMI2 RAKP HMAC-SHA1", None, None, DETECT),
    ("IPMI2-RAKP-MD5", 17, "IPMI2 RAKP HMAC-MD5", None, None, DETECT),
    ("SNMPv3-HMAC-MD5-96", 17, "SNMPv3 HMAC-MD5-96", None, None, DETECT),
    ("SNMPv3-HMAC-SHA1-96", 17, "SNMPv3 HMAC-SHA1-96", None, None, DETECT),
    ("SNMPv3-HMAC-SHA256-128", 17, "SNMPv3 HMAC-SHA256-128", None, None, DETECT),
    ("SNMPv3-HMAC-SHA512-384", 17, "SNMPv3 HMAC-SHA512-384", None, None, DETECT),
    ("SCRAM-SHA1", 17, "SCRAM-SHA-1", None, None, DETECT),
    ("SCRAM-SHA256", 17, "SCRAM-SHA-256", None, None, DETECT),

    # ── Category 18: MS Office / PDF / Archives ──
    ("MSOffice-2003-MD5", 18, "MS Office <=2003 (MD5+RC4)", None, None, DETECT),
    ("MSOffice-2003-MD5-C1", 18, "MS Office <=2003 collider #1", None, None, DETECT),
    ("MSOffice-2003-MD5-C2", 18, "MS Office <=2003 collider #2", None, None, DETECT),
    ("MSOffice-2003-SHA1", 18, "MS Office <=2003 (SHA1+RC4)", None, None, DETECT),
    ("MSOffice-2007", 18, "MS Office 2007", None, None, DETECT),
    ("MSOffice-2010", 18, "MS Office 2010", None, None, DETECT),
    ("MSOffice-2013", 18, "MS Office 2013", None, None, DETECT),
    ("MSOffice-2016", 18, "MS Office 2016", None, None, DETECT),
    ("PDF-1.1-1.3", 18, "PDF 1.1-1.3 (Acrobat 2-4)", None, None, DETECT),
    ("PDF-1.4-1.6", 18, "PDF 1.4-1.6 (Acrobat 5-8)", None, None, DETECT),
    ("PDF-1.7-L3", 18, "PDF 1.7 Level 3", None, None, DETECT),
    ("PDF-1.7-L8", 18, "PDF 1.7 Level 8", None, None, DETECT),
    ("PKZIP", 18, "PKZIP", None, None, DETECT),
    ("PKZIP-MasterKey", 18, "PKZIP Master Key", None, None, DETECT),
    ("ZIP-archive", 18, "ZIP archive", None, None, DETECT),

    # ── Category 19: Archives & Documents ──
    ("RAR-archive", 19, "RAR archive", None, None, DETECT),
    ("RAR3-hp", 19, "RAR3-hp", None, None, DETECT),
    ("RAR5", 19, "RAR5", None, None, DETECT),
    ("7-Zip", 19, "7-Zip ($7z$)", None, "$7z$", DETECT),
    ("WinZip", 19, "WinZip", None, None, DETECT),
    ("Outlook-PST", 19, "Microsoft Outlook PST", None, None, DETECT),
    ("MSTSC-RDP", 19, "Microsoft MSTSC RDP file", None, None, DETECT),
    ("PeopleSoft", 19, "PeopleSoft", None, None, DETECT),
    ("Stuffit5", 19, "Stuffit5", None, None, DETECT),
    ("ENCsecurity", 19, "ENCsecurity Datavault", None, None, DETECT),

    # ── Category 20: TrueCrypt / VeraCrypt ──
    ("TC-RIPEMD160-AES", 20, "TrueCrypt RIPEMD160+AES", None, None, DETECT),
    ("TC-RIPEMD160-Serpent", 20, "TrueCrypt RIPEMD160+Serpent", None, None, DETECT),
    ("TC-RIPEMD160-Twofish", 20, "TrueCrypt RIPEMD160+Twofish", None, None, DETECT),
    ("TC-SHA512-AES", 20, "TrueCrypt SHA512+AES", None, None, DETECT),
    ("TC-SHA512-Serpent", 20, "TrueCrypt SHA512+Serpent", None, None, DETECT),
    ("TC-Whirlpool-AES", 20, "TrueCrypt Whirlpool+AES", None, None, DETECT),
    ("TC-Whirlpool-Serpent", 20, "TrueCrypt Whirlpool+Serpent", None, None, DETECT),
    ("TC-Whirlpool-Twofish", 20, "TrueCrypt Whirlpool+Twofish", None, None, DETECT),
    ("VC-RIPEMD160-AES", 20, "VeraCrypt RIPEMD160+AES", None, None, DETECT),
    ("VC-SHA256-AES", 20, "VeraCrypt SHA256+AES", None, None, DETECT),
    ("VC-Whirlpool-AES", 20, "VeraCrypt Whirlpool+AES", None, None, DETECT),
    ("VC-Streebog512-XTS512", 20, "VeraCrypt Streebog-512+XTS 512", None, None, DETECT),
    ("VC-Streebog512-XTS1024", 20, "VeraCrypt Streebog-512+XTS 1024", None, None, DETECT),
    ("VC-Streebog512-XTS1536", 20, "VeraCrypt Streebog-512+XTS 1536", None, None, DETECT),
    ("VC-RIPEMD160-AES-Twofish", 20, "VeraCrypt RIPEMD160+AES-Twofish", None, None, DETECT),
    ("VC-SHA256-Serpent-AES", 20, "VeraCrypt SHA256+Serpent-AES", None, None, DETECT),
    ("VC-SHA256-Serpent-Twofish-AES", 20, "VeraCrypt SHA256+Serpent-Twofish-AES", None, None, DETECT),
    ("VC-Whirlpool-Twofish", 20, "VeraCrypt Whirlpool+Twofish", None, None, DETECT),
    ("VC-Whirlpool-Twofish-Serpent", 20, "VeraCrypt Whirlpool+Twofish-Serpent", None, None, DETECT),
    ("VC-boot-PIM", 20, "VeraCrypt boot-mode + PIM", None, None, DETECT),

    # ── Category 21: LUKS / DiskCryptor / FDE ──
    ("LUKS1-SHA1-AES", 21, "LUKS v1 SHA-1+AES", None, None, DETECT),
    ("LUKS1-SHA256-AES", 21, "LUKS v1 SHA-256+AES", None, None, DETECT),
    ("LUKS1-SHA512-AES", 21, "LUKS v1 SHA-512+AES", None, None, DETECT),
    ("LUKS1-RIPEMD160-AES", 21, "LUKS v1 RIPEMD-160+AES", None, None, DETECT),
    ("LUKS1-SHA1-Serpent", 21, "LUKS v1 SHA-1+Serpent", None, None, DETECT),
    ("LUKS1-SHA1-Twofish", 21, "LUKS v1 SHA-1+Twofish", None, None, DETECT),
    ("LUKS1-SHA256-Serpent", 21, "LUKS v1 SHA-256+Serpent", None, None, DETECT),
    ("LUKS1-SHA256-Twofish", 21, "LUKS v1 SHA-256+Twofish", None, None, DETECT),
    ("LUKS1-SHA512-Serpent", 21, "LUKS v1 SHA-512+Serpent", None, None, DETECT),
    ("LUKS1-SHA512-Twofish", 21, "LUKS v1 SHA-512+Twofish", None, None, DETECT),
    ("LUKS1-RIPEMD160-Serpent", 21, "LUKS v1 RIPEMD-160+Serpent", None, None, DETECT),
    ("LUKS1-RIPEMD160-Twofish", 21, "LUKS v1 RIPEMD-160+Twofish", None, None, DETECT),
    ("LUKS2", 21, "LUKS v2", None, None, DETECT),
    ("DiskCryptor-SHA512-XTS512", 21, "DiskCryptor SHA512+XTS 512", None, None, DETECT),
    ("DiskCryptor-SHA512-XTS1024", 21, "DiskCryptor SHA512+XTS 1024", None, None, DETECT),

    # ── Category 22: Apple / macOS / iOS ──
    ("OSX-10.4", 22, "macOS 10.4 salted SHA-1", 56, None, COMPUTE),
    ("OSX-10.5", 22, "macOS 10.5 salted SHA-1", None, None, DETECT),
    ("OSX-10.6", 22, "macOS 10.6 salted SHA-1", None, None, DETECT),
    ("OSX-10.7-xsha512", 22, "macOS 10.7 xsha512", None, None, DETECT),
    ("OSX-10.8-pbkdf2", 22, "macOS 10.8 pbkdf2-hmac-sha512", None, None, DETECT),
    ("OSX-10.9-pbkdf2", 22, "macOS 10.9 pbkdf2-hmac-sha512", None, None, DETECT),
    ("macOS-10.15+", 22, "macOS 10.15+", None, None, DETECT),
    ("Apple-Keychain", 22, "Apple Keychain", None, None, DETECT),
    ("iTunes-<10.0", 22, "iTunes backup < 10.0", None, None, DETECT),
    ("iTunes-10.0+", 22, "iTunes backup 10.0+", None, None, DETECT),
    ("iOS-Passcode", 22, "iOS Passcode", None, None, DETECT),
    ("iOS7-Backup", 22, "iOS 7+ Backup", None, None, DETECT),
    ("iOS-Keychain", 22, "iOS Keychain", None, None, DETECT),
    ("Apple-FileVault", 22, "Apple FileVault", None, None, DETECT),
    ("Apple-FileVault2", 22, "Apple FileVault 2", None, None, DETECT),

    # ── Category 23: Android / Mobile ──
    ("Samsung-Android-PIN", 23, "Samsung Android Password/PIN", None, None, DETECT),
    ("Android-PIN", 23, "Android PIN", None, None, DETECT),
    ("Android-FDE-4.3", 23, "Android FDE <= 4.3", None, None, DETECT),
    ("Android-FDE-5.0+", 23, "Android FDE 5.0+", None, None, DETECT),
    ("Android-FBE", 23, "Android FBE", None, None, DETECT),
    ("Android-Backup", 23, "Android Backup", None, None, DETECT),
    ("Android-KeyStore", 23, "Android KeyStore", None, None, DETECT),
    ("BlackBerry", 23, "BlackBerry", None, None, DETECT),
    ("BlackBerry-10", 23, "BlackBerry 10", None, None, DETECT),
    ("WinPhone8-PIN-Mobile", 23, "Windows Phone 8+ PIN", None, None, DETECT),

    # ── Category 24: Cryptocurrency / Blockchain ──
    ("Bitcoin-Address", 24, "Bitcoin Address", None, None, DETECT),
    ("Bitcoin-PrivKey", 24, "Bitcoin Private Key", None, None, DETECT),
    ("Bitcoin-Wallet", 24, "Bitcoin Wallet", None, None, DETECT),
    ("Bitcoin-Core-wallet", 24, "Bitcoin Core wallet.dat", None, None, DETECT),
    ("Ethereum-Address", 24, "Ethereum Address", None, None, DETECT),
    ("Ethereum-Wallet", 24, "Ethereum Wallet", None, None, DETECT),
    ("Ethereum-Keystore", 24, "Ethereum Keystore", None, None, DETECT),
    ("Litecoin-Wallet", 24, "Litecoin Wallet", None, None, DETECT),
    ("Dogecoin-Wallet", 24, "Dogecoin Wallet", None, None, DETECT),
    ("Electrum-Wallet", 24, "Electrum Wallet", None, None, DETECT),
    ("Terra-Wallet", 24, "Terra Station Wallet", None, None, DETECT),
    ("Bisq-wallet", 24, "Bisq .wallet (scrypt)", None, None, DETECT),
    ("Monero", 24, "Monero", None, None, DETECT),
    ("Ripple", 24, "Ripple", None, None, DETECT),
    ("Stellar", 24, "Stellar", None, None, DETECT),

    # ── Category 25: LDAP / Directory Services ──
    ("Netscape-LDAP-SHA-2", 25, "Netscape LDAP SHA {SHA}", None, "{SHA}", CRYPT),
    ("Netscape-LDAP-SSHA", 25, "Netscape LDAP SSHA {SSHA}", None, "{SSHA}", CRYPT),
    ("SSHA512-Base64", 25, "SSHA-512 Base64 {SSHA512}", None, "{SSHA512}", CRYPT),
    ("LDAP-SSHA512", 25, "LDAP SSHA-512", None, "{SSHA512}", CRYPT),
    ("OpenLDAP-SSHA", 25, "OpenLDAP {SSHA}", None, "{SSHA}", CRYPT),
    ("OpenLDAP-SSHA256", 25, "OpenLDAP {SSHA256}", None, "{SSHA256}", CRYPT),
    ("OpenLDAP-SSHA512", 25, "OpenLDAP {SSHA512}", None, "{SSHA512}", CRYPT),
    ("AD-NTDS", 25, "Active Directory NTDS.dit", None, None, DETECT),
    ("AD-Kerberos", 25, "Active Directory Kerberos", None, None, DETECT),

    # ── Category 26: Password Managers / Vaults ──
    ("1Password-Agile", 26, "1Password Agile Keychain", None, None, DETECT),
    ("1Password-Cloud", 26, "1Password Cloud Keychain", None, None, DETECT),
    ("LastPass", 26, "LastPass", None, None, DETECT),
    ("LastPass-sniffed", 26, "LastPass sniffed", None, None, DETECT),
    ("KeePass1", 26, "KeePass 1 (AES/Twofish)", None, None, DETECT),
    ("KeePass2", 26, "KeePass 2 (AES)", None, None, DETECT),
    ("Bitwarden", 26, "Bitwarden", None, None, DETECT),
    ("Dashlane", 26, "Dashlane", None, None, DETECT),
    ("NordPass", 26, "NordPass", None, None, DETECT),
    ("RoboForm", 26, "RoboForm", None, None, DETECT),

    # ── Category 27: Application / Protocol / Other ──
    ("Eggdrop", 27, "Eggdrop IRC Bot", None, None, DETECT),
    ("Skype", 27, "Skype", None, None, DETECT),
    ("Lotus-Notes-5", 27, "Lotus Notes/Domino 5", None, None, DETECT),
    ("Lotus-Notes-6", 27, "Lotus Notes/Domino 6", None, None, DETECT),
    ("Lotus-Notes-8", 27, "Lotus Notes/Domino 8", None, None, DETECT),
    ("Siemens-S7", 27, "Siemens-S7", None, None, DETECT),
    ("Dahua", 27, "Dahua", None, None, DETECT),
    ("Dahua-MD5", 27, "Dahua Authentication MD5", None, None, DETECT),
    ("SolarWinds-Orion", 27, "SolarWinds Orion", None, None, DETECT),
    ("SolarWinds-Orion-v2", 27, "SolarWinds Orion v2", None, None, DETECT),
    ("Umbraco-HMAC-SHA1", 27, "Umbraco HMAC-SHA1", None, None, DETECT),
    ("SipHash", 27, "SipHash", None, None, DETECT),
    ("CRAM-MD5", 27, "CRAM-MD5", None, None, DETECT),
    ("S-Key", 27, "S/Key", None, None, DETECT),
    ("OPIE", 27, "OPIE", None, None, DETECT),
    ("OTP", 27, "OTP", None, None, DETECT),
    ("HOTP", 27, "HOTP", None, None, DETECT),
    ("TOTP", 27, "TOTP", None, None, DETECT),
    ("FSHP", 27, "Fairly Secure Hashed Password", None, None, DETECT),

    # ── Category 28: Legacy Variants ──
    ("MD5-CHAP", 28, "MD5(Chap)", None, None, DETECT),
    ("iSCSI-CHAP", 28, "iSCSI CHAP Authentication", None, None, DETECT),
    ("MD5-Crypt-Cisco", 28, "MD5-crypt (Cisco-IOS)", None, "$1$", CRYPT),
    ("FreeBSD-MD5", 28, "FreeBSD MD5-crypt", None, "$1$", CRYPT),
    ("Sun-MD5-Crypt", 28, "Sun MD5-crypt", None, "$md5$", DETECT),
    ("AIX-smd5-2", 28, "AIX {smd5}", None, "{smd5}", DETECT),
    ("MD5(Oracle)", 28, "MD5(Oracle)", None, None, DETECT),
    ("SHA-1(Oracle)-2", 28, "SHA-1(Oracle)", None, None, DETECT),
    ("sha256(salt.unicode)-2", 28, "SHA-256(salt.UTF-16LE(pass))", 64, None, SALTED),
    ("sha512(salt.unicode)-2", 28, "SHA-512(salt.UTF-16LE(pass))", 128, None, SALTED),
    ("Groestl-256", 28, "Groestl-256", 64, None, DETECT),
    ("Groestl-512", 28, "Groestl-512", 128, None, DETECT),
    ("JH-256", 28, "JH-256", 64, None, DETECT),
    ("JH-512", 28, "JH-512", 128, None, DETECT),
    ("ECHO-256", 28, "ECHO-256", 64, None, DETECT),
    ("ECHO-512", 28, "ECHO-512", 128, None, DETECT),
    ("CubeHash-256", 28, "CubeHash-256", 64, None, DETECT),
    ("CubeHash-512", 28, "CubeHash-512", 128, None, DETECT),

    # ── Category 29: More Cryptographic Functions ──
    ("Panama", 29, "Panama", None, None, DETECT),
    ("RadioGatun-32", 29, "RadioGatun[32]", None, None, DETECT),
    ("RadioGatun-64", 29, "RadioGatun[64]", None, None, DETECT),
    ("FSB-160", 29, "FSB-160", 40, None, DETECT),
    ("FSB-256", 29, "FSB-256", 64, None, DETECT),
    ("FSB-384", 29, "FSB-384", 96, None, DETECT),
    ("FSB-512", 29, "FSB-512", 128, None, DETECT),
    ("ECOH", 29, "ECOH", None, None, DETECT),
    ("SWIFFT", 29, "SWIFFT", None, None, DETECT),
    ("Shabal-256", 29, "Shabal-256", 64, None, DETECT),
    ("Shabal-512", 29, "Shabal-512", 128, None, DETECT),
    ("SIMD-256", 29, "SIMD-256", 64, None, DETECT),
    ("SIMD-512", 29, "SIMD-512", 128, None, DETECT),

    # ── Category 30: Signatures ──
    ("HMAC-Skein-1024", 30, "HMAC-Skein-1024", None, None, DETECT),
    ("HMAC-SHA3-224", 30, "HMAC-SHA3-224", None, None, DETECT),
    ("HMAC-SHA3-384", 30, "HMAC-SHA3-384", None, None, DETECT),
    ("HMAC-SHA3-512", 30, "HMAC-SHA3-512", None, None, DETECT),
    ("RSA-MD5", 30, "RSA-MD5 signature", None, None, DETECT),
    ("RSA-SHA1", 30, "RSA-SHA1 signature", None, None, DETECT),
    ("RSA-SHA256", 30, "RSA-SHA256 signature", None, None, DETECT),
    ("DSA-SHA1", 30, "DSA-SHA1 signature", None, None, DETECT),
    ("ECDSA-SHA256", 30, "ECDSA-SHA256 signature", None, None, DETECT),
    ("Ed25519", 30, "Ed25519 signature", None, None, DETECT),
    ("Ed448", 30, "Ed448 signature", None, None, DETECT),
    ("RSA-PSS", 30, "RSA-PSS signature", None, None, DETECT),
    ("RSA-OAEP", 30, "RSA-OAEP", None, None, DETECT),
    ("EdDSA-Ed25519", 30, "EdDSA Ed25519 signature", None, None, DETECT),
]


def _build_db() -> dict[str, HashSpec]:
    db: dict[str, HashSpec] = {}
    for entry in _REGISTRY:
        name, cat, desc, hex_len, prefix, impl = entry
        if name in db:
            raise ValueError(f"Duplicate hash name in registry: {name}")
        db[name] = HashSpec(name, cat, desc, hex_len, prefix, impl)
    return db


HASH_DB: dict[str, HashSpec] = _build_db()


def _build_lookups() -> tuple[dict[int, list[str]], dict[str, list[str]]]:
    length_map: dict[int, list[str]] = {}
    prefix_map: dict[str, list[str]] = {}
    for name, spec in HASH_DB.items():
        if spec.hex_len:
            length_map.setdefault(spec.hex_len, []).append(name)
        if spec.prefix:
            prefix_map.setdefault(spec.prefix, []).append(name)
    # Sort prefix map by descending prefix length so longer prefixes match first
    return length_map, dict(sorted(prefix_map.items(), key=lambda kv: -len(kv[0])))


LENGTH_MAP, PREFIX_MAP = _build_lookups()


def category_counts() -> dict[int, int]:
    counts: dict[int, int] = dict.fromkeys(range(1, 31), 0)
    for spec in HASH_DB.values():
        counts[spec.cat] = counts.get(spec.cat, 0) + 1
    return counts


def implementation_stats() -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in HASH_DB.values():
        counts[spec.impl] = counts.get(spec.impl, 0) + 1
    return counts


def get(name: str) -> HashSpec | None:
    """Case-insensitive lookup by name."""
    if name in HASH_DB:
        return HASH_DB[name]
    lower = name.lower()
    for k, v in HASH_DB.items():
        if k.lower() == lower:
            return v
    return None
