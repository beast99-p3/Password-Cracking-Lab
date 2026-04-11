"""
defense/password_strength.py
============================
Interactive password strength analyzer.

Evaluates a password against multiple security criteria and gives an overall
score, practical feedback, and entropy estimate.

Usage:
    python defense/password_strength.py
    python defense/password_strength.py --password "MyP@ssw0rd!"
"""

import argparse
import math
import re
import string
import getpass
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

# Path to the common-passwords wordlist (relative to this file's parent)
WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "common_passwords.txt"


def load_common_passwords() -> set[str]:
    if WORDLIST_PATH.exists():
        return {
            line.strip().lower()
            for line in WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    return set()


COMMON_PASSWORDS = load_common_passwords()


# ── Scoring rules ─────────────────────────────────────────────────────────────

def check_length(pw: str) -> tuple[int, str]:
    n = len(pw)
    if n >= 20: return 30, f"{Fore.GREEN}Excellent  (length {n} ≥ 20)"
    if n >= 16: return 25, f"{Fore.GREEN}Very good  (length {n} ≥ 16)"
    if n >= 12: return 20, f"{Fore.YELLOW}Good       (length {n} ≥ 12)"
    if n >=  8: return 10, f"{Fore.YELLOW}Weak       (length {n} ≥ 8 — aim for 12+)"
    return 0,               f"{Fore.RED}Too short  (length {n} — minimum 8)"


def check_lowercase(pw: str) -> tuple[int, str]:
    if any(c in string.ascii_lowercase for c in pw):
        return 10, f"{Fore.GREEN}Has lowercase letters"
    return 0, f"{Fore.RED}No lowercase letters"


def check_uppercase(pw: str) -> tuple[int, str]:
    if any(c in string.ascii_uppercase for c in pw):
        return 10, f"{Fore.GREEN}Has uppercase letters"
    return 0, f"{Fore.RED}No uppercase letters"


def check_digits(pw: str) -> tuple[int, str]:
    if any(c in string.digits for c in pw):
        return 10, f"{Fore.GREEN}Has digits"
    return 0, f"{Fore.RED}No digits"


def check_special(pw: str) -> tuple[int, str]:
    specials = set(string.punctuation)
    count = sum(1 for c in pw if c in specials)
    if count >= 3: return 20, f"{Fore.GREEN}Has {count} special characters (excellent)"
    if count >= 1: return 10, f"{Fore.YELLOW}Has {count} special character(s) — more is better"
    return 0, f"{Fore.RED}No special characters"


def check_no_repeat(pw: str) -> tuple[int, str]:
    """Penalize runs of 3+ identical consecutive characters."""
    if re.search(r"(.)\1{2,}", pw):
        return -10, f"{Fore.RED}Contains repeated characters (e.g. aaa, 111)"
    return 10, f"{Fore.GREEN}No excessive character repetition"


def check_no_sequence(pw: str) -> tuple[int, str]:
    """Penalize obvious keyboard sequences."""
    sequences = ["abcdef", "qwerty", "123456", "654321", "fedcba", "zxcvbn"]
    lower = pw.lower()
    for seq in sequences:
        if seq in lower:
            return -10, f"{Fore.RED}Contains common sequence '{seq}'"
    return 5, f"{Fore.GREEN}No obvious keyboard sequences"


def check_not_common(pw: str) -> tuple[int, str]:
    if pw.lower() in COMMON_PASSWORDS:
        return -30, f"{Fore.RED}This is a VERY common password — it will be cracked instantly"
    return 15, f"{Fore.GREEN}Not in common-passwords wordlist"


# ── Entropy estimate ──────────────────────────────────────────────────────────

def estimate_entropy(pw: str) -> float:
    """Shannon entropy lower bound based on character-set size."""
    pool = 0
    if any(c in string.ascii_lowercase for c in pw): pool += 26
    if any(c in string.ascii_uppercase for c in pw): pool += 26
    if any(c in string.digits           for c in pw): pool += 10
    if any(c in string.punctuation      for c in pw): pool += 32
    if pool == 0: pool = 26
    return len(pw) * math.log2(pool)


# ── Overall score → label ─────────────────────────────────────────────────────

def score_label(score: int) -> str:
    if score >= 90: return f"{Fore.GREEN}VERY STRONG  (excellent — resistant to most attacks)"
    if score >= 70: return f"{Fore.GREEN}STRONG       (good, keep it unique per site)"
    if score >= 50: return f"{Fore.YELLOW}MODERATE     (acceptable, but could be stronger)"
    if score >= 30: return f"{Fore.YELLOW}WEAK         (vulnerable to dictionary attacks)"
    return             f"{Fore.RED}VERY WEAK    (will be cracked quickly)"


# ── Main analyzer ─────────────────────────────────────────────────────────────

def analyze(password: str):
    checks = [
        check_length(password),
        check_lowercase(password),
        check_uppercase(password),
        check_digits(password),
        check_special(password),
        check_no_repeat(password),
        check_no_sequence(password),
        check_not_common(password),
    ]

    total = sum(s for s, _ in checks)
    total = max(0, min(100, total))  # clamp 0–100

    entropy = estimate_entropy(password)

    print(f"\n{'─'*55}")
    print(f"  Password Strength Analysis")
    print(f"{'─'*55}")
    for score, msg in checks:
        sign = "+" if score >= 0 else ""
        print(f"  [{sign}{score:+3d}]  {msg}{Style.RESET_ALL}")
    print(f"{'─'*55}")
    print(f"  Total score : {total}/100  →  {score_label(total)}{Style.RESET_ALL}")
    print(f"  Entropy     : {entropy:.1f} bits  "
          f"({'≥ 60 bits — good' if entropy >= 60 else '< 60 bits — too low'})")
    print(f"{'─'*55}\n")

    print(f"{Fore.YELLOW}[LESSON]")
    print("  Entropy measures the unpredictability of a password.")
    print("  60+ bits: resistant to offline brute force with modern GPUs.")
    print("  True security comes from BOTH entropy AND hashing algorithm:")
    print("  bcrypt/Argon2 are slow by design, making brute force expensive.")
    print("  Even a 'STRONG' password stored as plain MD5 is immediately")
    print("  crackable if the hash database is leaked.")


def main():
    parser = argparse.ArgumentParser(
        description="Interactive password strength analyzer."
    )
    parser.add_argument("--password", help="Password to analyze (omit for secure prompt).")
    args = parser.parse_args()

    if args.password:
        pw = args.password
    else:
        pw = getpass.getpass("Enter password to analyze (input hidden): ")

    if not pw:
        print("[ERROR] No password provided.")
        return

    analyze(pw)


if __name__ == "__main__":
    main()
