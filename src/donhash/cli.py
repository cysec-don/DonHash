"""Command-line interface for DonHash."""

from __future__ import annotations

import argparse
import os
import sys

from donhash import __version__
from donhash._hash_db import (
    CATEGORY_NAMES,
    COMPUTE,
    CRYPT,
    DETECT,
    HASH_DB,
    SALTED,
    category_counts,
    implementation_stats,
)
from donhash._hash_db import (
    get as get_hash_spec,
)
from donhash.cracker import crack_from_file, crack_single_hash
from donhash.detector import detect_hash_type
from donhash.output import detect_output_format, write_output

# ─── ANSI colors (graceful degradation when not a TTY) ───────────────────────

class _Colors:
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


class _NoColors:
    RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BOLD = DIM = RESET = ""


def _use_colors() -> bool:
    """Return True if stdout is a TTY and color output is desired."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("DONHASH_NO_COLOR"):
        return False
    return sys.stdout.isatty()


Colors = _Colors if _use_colors() else _NoColors


# ─── Banner ──────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the DonHash splash screen."""
    C = Colors
    print()
    print(f"  {C.CYAN}{C.BOLD}+----------------------------------------------------------+{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}|{C.RESET}   {C.RED}{C.BOLD}>>>{C.RESET}  {C.WHITE}{C.BOLD}D  O  N  H  A  S  H{C.RESET}  {C.RED}{C.BOLD}<<<{C.RESET}                        {C.CYAN}{C.BOLD}|{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}|{C.RESET}        {C.DIM}Hash Detector & Cracker{C.RESET}                             {C.CYAN}{C.BOLD}|{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}+----------------------------------------------------------+{C.RESET}")
    print()
    print(f"  {C.CYAN}{C.BOLD}[*]{C.RESET} {C.WHITE}DonHash - Hash Detector & Cracker{C.RESET}  {C.CYAN}{C.BOLD}|{C.RESET}  {C.GREEN}{C.BOLD}Author : CySec Don{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}[*]{C.RESET} {C.WHITE}Detect & crack hashes w/ wordlists{C.RESET} {C.CYAN}{C.BOLD}|{C.RESET}  {C.GREEN}{C.BOLD}Email  : cysecdon@gmail.com{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}[*]{C.RESET} {C.WHITE}{len(HASH_DB)} hash algorithms supported{C.RESET}    {C.CYAN}{C.BOLD}|{C.RESET}  {C.YELLOW}{C.BOLD}Version: v{__version__}{C.RESET}")
    print()
    print(f"  {C.CYAN}{C.BOLD}{'~' * 60}{C.RESET}")
    print(f"   {C.RED}{C.BOLD}>>>{C.RESET} {C.WHITE}DETECT{C.RESET}  {C.CYAN}{C.BOLD}::{C.RESET}  {C.WHITE}CRACK{C.RESET}  {C.CYAN}{C.BOLD}::{C.RESET}  {C.WHITE}REVEAL{C.RESET}  {C.CYAN}{C.BOLD}::{C.RESET}  {C.DIM}v{__version__}{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}{'~' * 60}{C.RESET}")
    print()


# ─── Listing helpers ─────────────────────────────────────────────────────────

def list_categories() -> None:
    """Print all 30 categories with hash counts."""
    C = Colors
    print(f"\n  {C.CYAN}{C.BOLD}30 HASH CATEGORIES{C.RESET}\n")
    counts = category_counts()
    for cat_id in range(1, 31):
        name = CATEGORY_NAMES.get(cat_id, "Unknown")
        print(f"  {C.YELLOW}{cat_id:>2}.{C.RESET} {C.WHITE}{name:<45}{C.RESET} {C.GREEN}({counts[cat_id]} types){C.RESET}")
    total = len(HASH_DB)
    stats = implementation_stats()
    crackable = stats.get(COMPUTE, 0) + stats.get(CRYPT, 0) + stats.get(SALTED, 0)
    print(f"\n  {C.BOLD}{C.CYAN}Total: {total} hash types{C.RESET} "
          f"({C.GREEN}{crackable} crackable{C.RESET}, {C.YELLOW}{stats.get(DETECT, 0)} detection-only{C.RESET})\n")


def list_hash_types(filter_cat: int | None = None) -> None:
    """Print all hash types, optionally filtered by category."""
    C = Colors
    cats = range(1, 31) if filter_cat is None else [filter_cat]
    for cat_id in cats:
        name = CATEGORY_NAMES.get(cat_id, "Unknown")
        types = [(k, v) for k, v in HASH_DB.items() if v.cat == cat_id]
        if not types:
            continue
        print(f"\n  {C.CYAN}{C.BOLD}[{cat_id}] {name}{C.RESET}")
        print(f"  {'-' * 60}")
        for tname, tinfo in types:
            if tinfo.impl == COMPUTE:
                tag = f"{C.GREEN}compute{C.RESET}"
            elif tinfo.impl == CRYPT:
                tag = f"{C.YELLOW}crypt{C.RESET}"
            elif tinfo.impl == SALTED:
                tag = f"{C.YELLOW}salted{C.RESET}"
            else:
                tag = f"{C.DIM}detect-only{C.RESET}"
            print(f"    {tname:<38} {tinfo.desc:<50} [{tag}]")
    print()


def find_rockyou() -> str:
    """Try to locate a rockyou.txt wordlist in common locations."""
    candidates = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/opt/rockyou.txt",
        os.path.expanduser("~/rockyou.txt"),
        "./rockyou.txt",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return "rockyou.txt"


# ─── Argument parser ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="donhash",
        description=f"DonHash v{__version__} — Hash Detector & Cracker "
                    f"— {len(HASH_DB)} hash types, 30 categories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
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
  %(prog)s --detect-only -H 5f4dcc3b5aa765d61d8327deb882cf99

Implementation status:
  [compute]   — full compute support, crackable
  [crypt]     — crackable via crypt-style salt extraction
  [salted]    — crackable, but requires -s/--salt
  [detect-only] — detection only, no compute implementation

Detection-only types will return "unsupported" when cracking is attempted.
Use --list-types to see which types are crackable in this build.
""",
    )

    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("-H", "--hash", dest="target_hash",
                              help="Single hash to crack")
    input_group.add_argument("-f", "--file",
                              help="File with hashes (one per line, optional hash:type syntax)")

    parser.add_argument("-w", "--wordlist", default=None,
                        help="Path to wordlist (default: rockyou.txt if found)")
    parser.add_argument("-t", "--type", dest="hash_type",
                        help="Force a specific hash type (see --list-types)")
    parser.add_argument("-s", "--salt", default="",
                        help="Salt for salted hash types")
    parser.add_argument("-T", "--threads", type=int, default=5, choices=range(1, 101),
                        metavar="1-100",
                        help="Number of threads for cracking (default: 5, max: 100)")
    parser.add_argument("-o", "--output",
                        help="Output file path for results")
    parser.add_argument("--format", dest="output_format", default=None,
                        choices=["txt", "json", "csv", "html", "xml", "md"],
                        help="Output format (default: auto-detect from file extension)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress while cracking")
    parser.add_argument("--detect-only", action="store_true",
                        help="Only detect hash type(s) without cracking")
    parser.add_argument("--list-categories", action="store_true",
                        help="List all 30 categories")
    parser.add_argument("--list-types", action="store_true",
                        help="List all hash types with implementation status")
    parser.add_argument("--category", type=int, default=None,
                        help="Filter --list-types by category number (1-30)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Skip the splash screen (useful for scripting)")
    parser.add_argument("--version", action="version",
                        version=f"donhash {__version__}")

    return parser


# ─── Main entry ──────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    C = Colors

    # Validate --category early (it's only meaningful with --list-types, but
    # rejecting bad values here means we don't silently accept --category 99
    # in combination with other flags).
    if args.category is not None and not (1 <= args.category <= 30):
        print(f"{C.RED}[!] --category must be in range 1-30 (got {args.category}){C.RESET}",
              file=sys.stderr)
        return 2

    if args.list_categories:
        list_categories()
        return 0

    if args.list_types:
        list_hash_types(args.category)
        return 0

    if not args.target_hash and not args.file:
        # If the user gave us cracking-related flags but no -H/-f, treat it as
        # a usage error (exit 2), not a help request (exit 0). We compare
        # against each flag's default value so that running `donhash` with no
        # args at all still prints help and exits 0.
        defaults = {
            "wordlist": None, "hash_type": None, "salt": "",
            "output": None, "output_format": None,
        }
        user_gave_cracking_args = any(
            getattr(args, name) != default for name, default in defaults.items()
        ) or args.verbose or args.detect_only
        if user_gave_cracking_args:
            print(f"{C.RED}[!] -H/--hash or -f/--file is required for cracking.{C.RESET}",
                  file=sys.stderr)
            print(f"{C.YELLOW}[*] See --help for usage.{C.RESET}", file=sys.stderr)
            return 2
        parser.print_help()
        return 0

    if not args.no_banner:
        print_banner()

    # Validate wordlist existence early with an actionable error message.
    wordlist = args.wordlist or find_rockyou()
    if not args.detect_only and not os.path.isfile(wordlist):
        if args.wordlist is None:
            print(f"{C.RED}[!] No wordlist specified and rockyou.txt was not found in any "
                  f"standard location.{C.RESET}", file=sys.stderr)
            print(f"{C.YELLOW}[*] Specify one with -w/--wordlist, e.g.:{C.RESET}", file=sys.stderr)
            print(f"{C.YELLOW}    donhash -H <hash> -w /path/to/wordlist.txt{C.RESET}",
                  file=sys.stderr)
        else:
            print(f"{C.RED}[!] Wordlist not found: {wordlist}{C.RESET}", file=sys.stderr)
        return 2

    # ── Detect-only mode ──
    if args.detect_only:
        if args.target_hash:
            detected = detect_hash_type(args.target_hash)
            if detected:
                print(f"{C.YELLOW}[*] Possible hash types for: {args.target_hash}{C.RESET}\n")
                for idx, (htype, desc, cat) in enumerate(detected, 1):
                    cat_name = CATEGORY_NAMES.get(cat, "Unknown")
                    spec = HASH_DB[htype]
                    impl_label = {
                        COMPUTE: f"{C.GREEN}compute{C.RESET}",
                        CRYPT: f"{C.YELLOW}crypt{C.RESET}",
                        SALTED: f"{C.YELLOW}salted{C.RESET}",
                        DETECT: f"{C.DIM}detect-only{C.RESET}",
                    }[spec.impl]
                    likely = f" {C.GREEN}(most likely){C.RESET}" if idx == 1 else ""
                    print(f"  {C.BOLD}{idx}.{C.RESET} {htype:<35} "
                          f"[{cat_name}] {desc} [{impl_label}]{likely}")
            else:
                print(f"{C.RED}[!] Could not detect hash type.{C.RESET}")
                return 1
        else:
            print(f"{C.RED}[!] --detect-only requires -H/--hash{C.RESET}")
            return 2
        return 0

    # ── Single hash mode ──
    if args.target_hash:
        target_hash = args.target_hash.strip()

        if args.hash_type:
            maybe_spec = get_hash_spec(args.hash_type)
            if maybe_spec is None:
                print(f"{C.RED}[!] Unknown hash type: {args.hash_type}{C.RESET}")
                print(f"{C.YELLOW}[*] Use --list-types to see all supported types{C.RESET}")
                return 2
            hash_type = maybe_spec.name
            print(f"{C.YELLOW}[*] Using forced hash type: {hash_type}{C.RESET}")
        else:
            detected = detect_hash_type(target_hash)
            if not detected:
                print(f"{C.RED}[!] Could not detect hash type for: {target_hash}{C.RESET}")
                print(f"{C.YELLOW}[*] Try specifying the type with -t (e.g., -t md5){C.RESET}")
                print(f"{C.YELLOW}[*] Use --list-types to see all supported types{C.RESET}")
                return 1

            hash_type = detected[0][0]
            if len(detected) == 1:
                cat_name = CATEGORY_NAMES.get(detected[0][2], "")
                print(f"{C.YELLOW}[*] Detected: {hash_type} [{cat_name}]{C.RESET}")
            else:
                print(f"{C.YELLOW}[*] {len(detected)} possible types detected. "
                      f"Using: {hash_type} (most likely){C.RESET}")
                print(f"{C.YELLOW}[*] Override with -t flag. Use --list-types to see all.{C.RESET}")

        result = crack_single_hash(
            target_hash, hash_type, wordlist,
            verbose=args.verbose, ext_salt=args.salt, num_threads=args.threads,
        )

        _print_result(result)

        if args.output:
            results = [result]
            fmt = detect_output_format(args.output, args.output_format)
            write_output(results, args.output, fmt)
            print(f"{C.GREEN}[+] Results written to: {args.output} ({fmt} format){C.RESET}")

        return 0 if result.status == "cracked" else 1

    # ── File mode ──
    if args.file:
        hash_type_override: str | None = None
        if args.hash_type:
            maybe_spec = get_hash_spec(args.hash_type)
            if maybe_spec is None:
                print(f"{C.RED}[!] Unknown hash type: {args.hash_type}{C.RESET}")
                return 2
            hash_type_override = maybe_spec.name

        results = crack_from_file(
            args.file, wordlist, hash_type_override,
            verbose=args.verbose, num_threads=args.threads, salt=args.salt,
        )

        _print_summary(results)

        if args.output and results:
            fmt = detect_output_format(args.output, args.output_format)
            write_output(results, args.output, fmt)
            print(f"{C.GREEN}[+] Results written to: {args.output} ({fmt} format){C.RESET}")

        cracked = sum(1 for r in results if r.status == "cracked")
        # Exit 0 if any hash was cracked; 1 only if nothing was cracked
        return 0 if cracked > 0 else 1

    return 0


def _print_result(result) -> None:
    C = Colors
    if result.status == "cracked":
        print(f"\n{C.GREEN}{C.BOLD}[+] HASH CRACKED!{C.RESET}")
        print(f"{C.GREEN}    Password : {C.BOLD}{result.password}{C.RESET}")
        print(f"{C.GREEN}    Hash Type: {result.type}{C.RESET}")
        print(f"{C.GREEN}    Category : {result.category}{C.RESET}")
        print(f"{C.GREEN}    Attempts : {result.attempts:,}{C.RESET}")
        print(f"{C.GREEN}    Time     : {result.time:.2f}s{C.RESET}")
        print(f"{C.GREEN}    Speed    : {result.speed:,.0f} hash/sec{C.RESET}")
    elif result.status == "unsupported":
        print(f"\n{C.YELLOW}[~] {result.error}{C.RESET}")
    elif result.status == "error":
        print(f"\n{C.RED}[!] {result.error}{C.RESET}")
    else:
        print(f"\n{C.RED}[-] Password not found in wordlist.{C.RESET}")
        if result.attempts:
            print(f"{C.RED}    Attempts: {result.attempts:,} | "
                  f"Time: {result.time:.2f}s | Speed: {result.speed:,.0f} h/s{C.RESET}")


def _print_summary(results) -> None:
    C = Colors
    print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  CRACKING SUMMARY{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}")
    for r in results:
        pw = r.password
        if pw:
            st = f"{C.GREEN}{pw}{C.RESET}"
        elif r.status == "unsupported":
            st = f"{C.YELLOW}unsupported{C.RESET}"
        elif r.status == "error":
            st = f"{C.RED}error{C.RESET}"
        else:
            st = f"{C.RED}Not found{C.RESET}"
        print(f"  {(r.type or 'Unknown'):<28} | {r.hash[:40]:<42} | {st}")
    total = len(results)
    cracked = sum(1 for r in results if r.status == "cracked")
    if total:
        print(f"\n  Cracked: {C.GREEN}{cracked}{C.RESET}/{total} ({cracked/total*100:.0f}%)")


if __name__ == "__main__":
    sys.exit(main())
