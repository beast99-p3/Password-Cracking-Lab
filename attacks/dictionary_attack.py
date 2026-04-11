"""
attacks/dictionary_attack.py
============================
EDUCATIONAL USE ONLY — run only against hashes you own or have permission to test.

Demonstrates a dictionary (wordlist) attack against unsalted hashes.

A dictionary attack hashes each word in a list and compares it to the target.
It works because users tend to pick real words, names, and common phrases.

Usage:
    python attacks/dictionary_attack.py --hashfile setup/hashes.txt \
        --wordlist wordlists/common_passwords.txt --algorithm md5

    python attacks/dictionary_attack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
        --wordlist wordlists/common_passwords.txt --algorithm md5
"""

import hashlib
import argparse
import time
from pathlib import Path
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

ALGORITHMS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
}


def hash_word(word: str, algorithm: str) -> str:
    return ALGORITHMS[algorithm](word.encode("utf-8")).hexdigest()


def load_lines(path: str) -> list[str]:
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]


def crack_single(target_hash: str, wordlist: list[str], algorithm: str) -> tuple[str | None, int]:
    """
    Attempt to crack one hash. Returns (plaintext, attempts) or (None, attempts).
    """
    target_hash = target_hash.strip().lower()
    for i, word in enumerate(wordlist, 1):
        if hash_word(word, algorithm) == target_hash:
            return word, i
    return None, len(wordlist)


def crack_file(hashfile: str, wordlist_path: str, algorithm: str):
    """Crack every hash in a file and print a results table."""
    raw_lines = load_lines(hashfile)
    wordlist  = load_lines(wordlist_path)

    targets = []
    for line in raw_lines:
        parts = line.split(":", 1)
        if len(parts) == 2:
            algo_hint, h = parts
            targets.append((h.strip(), algo_hint.strip()))
        else:
            targets.append((line.strip(), algorithm))

    print(f"\n{Fore.CYAN}[*] Dictionary Attack")
    print(f"    Targets  : {len(targets)} hashes")
    print(f"    Wordlist : {wordlist_path}  ({len(wordlist)} words)")
    print(f"    Algorithm: {algorithm}\n")

    rows = []
    cracked = 0
    start = time.perf_counter()

    for target_hash, declared_algo in targets:
        algo = declared_algo if declared_algo in ALGORITHMS else algorithm
        plaintext, attempts = crack_single(target_hash, wordlist, algo)
        if plaintext:
            cracked += 1
            status = f"{Fore.GREEN}CRACKED"
            rows.append([target_hash[:16] + "…", algo, status, plaintext, attempts])
        else:
            status = f"{Fore.RED}NOT FOUND"
            rows.append([target_hash[:16] + "…", algo, status, "—", attempts])

    elapsed = time.perf_counter() - start

    # Strip color codes for tabulate (colorama only works in terminal cells)
    plain_rows = [
        [r[0], r[1], r[2].replace(Fore.GREEN, "").replace(Fore.RED, ""), r[3], r[4]]
        for r in rows
    ]
    print(tabulate(plain_rows, headers=["Hash", "Algo", "Status", "Plaintext", "Attempts"], tablefmt="grid"))
    print(f"\n[+] Cracked {cracked}/{len(targets)} hashes in {elapsed:.3f}s "
          f"({len(wordlist)/elapsed:,.0f} hashes/sec)")

    # ── Educational analysis ──────────────────────────────────────────────────
    print(f"\n{Fore.YELLOW}[LESSON]")
    print(f"  • {cracked}/{len(targets)} hashes cracked with only {len(wordlist)} words.")
    print("  • Real-world wordlists (rockyou.txt) contain 14 million+ entries.")
    print("  • Unsalted hashes allow pre-computation — the same hash always equals")
    print("    the same password, so results can be looked up instantly in a rainbow table.")
    print("  • DEFENSE: use bcrypt/Argon2 with a unique per-user salt and a high work factor.")


def crack_interactive(target_hash: str, wordlist_path: str, algorithm: str):
    """Crack a single hash provided on the command line."""
    wordlist = load_lines(wordlist_path)
    target_hash = target_hash.strip().lower()

    print(f"\n{Fore.CYAN}[*] Dictionary Attack — single hash")
    print(f"    Hash     : {target_hash}")
    print(f"    Algorithm: {algorithm}")
    print(f"    Wordlist : {wordlist_path}  ({len(wordlist)} words)\n")

    start = time.perf_counter()
    plaintext, attempts = crack_single(target_hash, wordlist, algorithm)
    elapsed = time.perf_counter() - start

    if plaintext:
        print(f"{Fore.GREEN}[+] CRACKED after {attempts} attempts in {elapsed*1000:.2f} ms")
        print(f"    Password: {plaintext}")
    else:
        print(f"{Fore.RED}[-] NOT FOUND in wordlist after {attempts} attempts ({elapsed*1000:.2f} ms)")
        print("    Try a larger wordlist or switch to brute_force.py for short passwords.")


def main():
    parser = argparse.ArgumentParser(
        description="Educational Dictionary Attack — lab use only."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hashfile", help="File containing hashes (output of generate_hashes.py).")
    group.add_argument("--hash",     help="Single hash string to crack.")

    parser.add_argument("--wordlist",   required=True, help="Path to wordlist file.")
    parser.add_argument("--algorithm",  default="md5", choices=list(ALGORITHMS.keys()),
                        help="Hash algorithm (default: md5). Ignored when reading from a file with declared algorithms.")
    args = parser.parse_args()

    if args.hashfile:
        crack_file(args.hashfile, args.wordlist, args.algorithm)
    else:
        crack_interactive(args.hash, args.wordlist, args.algorithm)


if __name__ == "__main__":
    main()
