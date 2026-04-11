"""
attacks/brute_force.py
======================
EDUCATIONAL USE ONLY — run only against hashes you own or have permission to test.

Demonstrates a brute-force attack: systematically trying every possible combination
of characters up to a given length.

Key insight for students:
  • Even with a modern CPU, 8-char passwords with mixed case + digits = 218 trillion
    combinations.  bcrypt at cost=12 evaluates ~10 hashes/sec, making this
    computationally infeasible.  Against raw MD5, a GPU can do billions/sec.

Usage:
    python attacks/brute_force.py --hash 827ccb0eea8a706c4c34a16891f84e7b \
        --algorithm md5 --max-length 4 --charset digits

    python attacks/brute_force.py --hash ab56b4d92b40713acc5af89985d4b786 \
        --algorithm md5 --max-length 3 --charset lowercase

Charsets:
    digits      0-9
    lowercase   a-z
    uppercase   A-Z
    alpha       a-zA-Z
    alphanum    a-zA-Z0-9
    common      a-zA-Z0-9!@#$%
"""

import hashlib
import itertools
import argparse
import time
import string
from colorama import Fore, init

init(autoreset=True)

ALGORITHMS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
}

CHARSETS = {
    "digits":   string.digits,
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "alpha":    string.ascii_letters,
    "alphanum": string.ascii_letters + string.digits,
    "common":   string.ascii_letters + string.digits + "!@#$%",
}


def search_space_size(charset: str, max_length: int) -> int:
    n = len(charset)
    return sum(n ** l for l in range(1, max_length + 1))


def hash_candidate(candidate: str, algorithm: str) -> str:
    return ALGORITHMS[algorithm](candidate.encode("utf-8")).hexdigest()


def brute_force(target_hash: str, algorithm: str, charset: str, max_length: int,
                progress_interval: int = 500_000):
    """
    Iterate through all combinations. Yields (found: bool, plaintext, attempts, elapsed).
    """
    target_hash = target_hash.strip().lower()
    attempts = 0
    start = time.perf_counter()

    total = search_space_size(charset, max_length)
    print(f"\n{Fore.CYAN}[*] Brute-Force Attack")
    print(f"    Hash      : {target_hash}")
    print(f"    Algorithm : {algorithm}")
    print(f"    Charset   : '{charset}' ({len(charset)} chars)")
    print(f"    Max length: {max_length}")
    print(f"    Search space: {total:,} combinations\n")

    for length in range(1, max_length + 1):
        print(f"[*] Trying length {length} ({len(charset)**length:,} combinations)…")
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1

            if hash_candidate(candidate, algorithm) == target_hash:
                elapsed = time.perf_counter() - start
                rate = attempts / elapsed if elapsed > 0 else float("inf")
                print(f"\n{Fore.GREEN}[+] CRACKED!")
                print(f"    Password : {candidate}")
                print(f"    Attempts : {attempts:,}")
                print(f"    Time     : {elapsed:.3f}s")
                print(f"    Rate     : {rate:,.0f} hashes/sec")
                return candidate, attempts, elapsed

            if attempts % progress_interval == 0:
                elapsed = time.perf_counter() - start
                pct = (attempts / total) * 100
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"    Progress: {pct:5.2f}%  |  {attempts:,} attempts  |  {rate:,.0f} h/s", end="\r")

    elapsed = time.perf_counter() - start
    print(f"\n{Fore.RED}[-] NOT FOUND in {attempts:,} attempts over {elapsed:.3f}s")
    return None, attempts, elapsed


def print_lesson(plaintext, attempts, elapsed, charset, max_length):
    total = search_space_size(charset, max_length)
    rate  = attempts / elapsed if elapsed > 0 else float("inf")

    print(f"\n{Fore.YELLOW}[LESSON — Brute Force Complexity]")
    print(f"  Charset size  : {len(charset)}")
    print(f"  Max length    : {max_length}")
    print(f"  Total combos  : {total:,}")
    print(f"  CPU rate (lab): {rate:,.0f} MD5 hashes/sec  ← single-threaded Python, very slow")
    print()
    print("  Real-world references (GPU/optimized tools):")
    print("    MD5              ~200 billion/sec  (RTX 4090)")
    print("    bcrypt (cost=12) ~       10/sec    (same GPU)")
    print()
    print("  8-char password, alphanum charset = 218 trillion combinations")
    if plaintext:
        print(f"  Your password '{plaintext}' (length {len(plaintext)}) was short — "
              "this is why minimum length policies matter.")
    print("  DEFENSE: enforce length ≥ 12, use bcrypt/Argon2 — makes GPU brute-force infeasible.")


def main():
    parser = argparse.ArgumentParser(
        description="Educational Brute-Force Attack — lab use only."
    )
    parser.add_argument("--hash",       required=True, help="Target hash to crack.")
    parser.add_argument("--algorithm",  default="md5", choices=list(ALGORITHMS.keys()))
    parser.add_argument("--max-length", type=int, default=4,
                        help="Maximum candidate length (keep ≤ 5 for quick demo, default: 4).")
    parser.add_argument("--charset",    default="digits", choices=list(CHARSETS.keys()),
                        help="Character set to use (default: digits).")
    args = parser.parse_args()

    charset_str = CHARSETS[args.charset]
    plaintext, attempts, elapsed = brute_force(
        args.hash, args.algorithm, charset_str, args.max_length
    )
    print_lesson(plaintext, attempts, elapsed, charset_str, args.max_length)


if __name__ == "__main__":
    main()
