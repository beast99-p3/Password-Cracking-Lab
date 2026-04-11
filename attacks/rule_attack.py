"""
attacks/rule_attack.py
======================
EDUCATIONAL USE ONLY

Rule-based attack: applies common mutation rules to each word in a wordlist,
then attempts to crack the target hash.

Rules mimic what real attackers do because users predictably transform passwords:
  "password" → "P@ssw0rd", "password1", "PASSWORD", "drowssap", etc.

Supported rules:
  capitalize        First letter uppercase
  uppercase         ALL CAPS
  lowercase         all lowercase
  reverse           Reverse the word
  leet              a→@ e→3 i→1 o→0 s→$ t→7
  double            Repeat the word twice
  append_digits     Append 0-9, 00-99, 1-9 common years (2018-2024)
  append_symbols    Append !, @, #, $, ?, .
  prepend_digits    Prepend single digits 0-9
  toggle_case       ALtErNaTiNg CaSe
"""

import argparse
import hashlib
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

ALGORITHMS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
}

LEET_MAP = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})
APPEND_DIGITS  = [str(i) for i in range(10)] + [str(i) for i in range(100)] + \
                 [str(y) for y in range(2015, 2026)]
APPEND_SYMBOLS = ["!", "@", "#", "$", "?", ".", "!!", "123", "1234", "12345"]
PREPEND_DIGITS = [str(i) for i in range(10)]


def apply_rules(word: str, rules: list[str]) -> list[str]:
    """Return all unique candidates produced by applying `rules` to `word`."""
    candidates: list[str] = [word]  # always include the original

    if "capitalize" in rules:
        candidates.append(word.capitalize())
    if "uppercase" in rules:
        candidates.append(word.upper())
    if "lowercase" in rules:
        candidates.append(word.lower())
    if "reverse" in rules:
        candidates.append(word[::-1])
    if "leet" in rules:
        leet = word.lower().translate(LEET_MAP)
        candidates.append(leet)
        candidates.append(leet.capitalize())
    if "double" in rules:
        candidates.append(word + word)
    if "toggle_case" in rules:
        toggled = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
        candidates.append(toggled)
    if "append_digits" in rules:
        for d in APPEND_DIGITS:
            candidates.append(word + d)
            candidates.append(word.capitalize() + d)
    if "append_symbols" in rules:
        for sym in APPEND_SYMBOLS:
            candidates.append(word + sym)
            candidates.append(word.capitalize() + sym)
    if "prepend_digits" in rules:
        for d in PREPEND_DIGITS:
            candidates.append(d + word)

    return list(dict.fromkeys(candidates))  # deduplicate while preserving order


def hash_candidate(candidate: str, algorithm: str) -> str:
    return ALGORITHMS[algorithm](candidate.encode("utf-8")).hexdigest()


def rule_attack(
    target_hash: str,
    wordlist_path: str,
    algorithm: str,
    rules: list[str] | None = None,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> Dict[str, Any]:
    """
    Run a rule-based attack.
    Returns dict: {cracked: bool, plaintext, rule_used, attempts, elapsed, rate}
    """
    if rules is None:
        rules = list(ALL_RULES)

    target_hash = target_hash.strip().lower()
    wordlist = [
        line.strip()
        for line in Path(wordlist_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]

    attempts = 0
    start = time.perf_counter()

    for word in wordlist:
        candidates = apply_rules(word, rules)
        for candidate in candidates:
            attempts += 1
            if hash_candidate(candidate, algorithm) == target_hash:
                elapsed = time.perf_counter() - start
                return {
                    "cracked": True,
                    "plaintext": candidate,
                    "original_word": word,
                    "rule_hint": f"'{word}' → '{candidate}'",
                    "attempts": attempts,
                    "elapsed": round(elapsed, 4),
                    "rate": round(attempts / elapsed) if elapsed > 0 else 0,
                }
            if progress_cb and attempts % 10000 == 0:
                progress_cb(attempts)

    elapsed = time.perf_counter() - start
    return {
        "cracked": False,
        "plaintext": None,
        "original_word": None,
        "rule_hint": None,
        "attempts": attempts,
        "elapsed": round(elapsed, 4),
        "rate": round(attempts / elapsed) if elapsed > 0 else 0,
    }


ALL_RULES = [
    "capitalize", "uppercase", "lowercase", "reverse",
    "leet", "double", "append_digits", "append_symbols",
    "prepend_digits", "toggle_case",
]


def main():
    parser = argparse.ArgumentParser(description="Rule-based attack — educational lab only.")
    parser.add_argument("--hash",      required=True)
    parser.add_argument("--wordlist",  required=True)
    parser.add_argument("--algorithm", default="md5", choices=list(ALGORITHMS.keys()))
    parser.add_argument("--rules", nargs="+", choices=ALL_RULES, default=ALL_RULES,
                        help="Mutation rules to apply (default: all).")
    args = parser.parse_args()

    print(f"\n[*] Rule-Based Attack")
    print(f"    Hash     : {args.hash}")
    print(f"    Algorithm: {args.algorithm}")
    print(f"    Rules    : {', '.join(args.rules)}\n")

    result = rule_attack(args.hash, args.wordlist, args.algorithm, args.rules)

    if result["cracked"]:
        print(f"[+] CRACKED: {result['plaintext']}")
        print(f"    Rule applied : {result['rule_hint']}")
        print(f"    Attempts     : {result['attempts']:,}")
        print(f"    Time         : {result['elapsed']}s  ({result['rate']:,} h/s)")
    else:
        print(f"[-] NOT FOUND after {result['attempts']:,} attempts ({result['elapsed']}s)")

    print("\n[LESSON] Rule-based attacks are extremely effective because users follow")
    print("  predictable patterns: capitalise first letter, add a number, swap letters")
    print("  for symbols. A 14+ char passphrase (RandomWords-Together-4ever!) defeats this.")


if __name__ == "__main__":
    main()
