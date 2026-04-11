"""
defense/password_generator.py
==============================
Generates cryptographically strong passwords with configurable options.

Uses Python's `secrets` module (CSPRNG) — never `random`.

Usage:
    python defense/password_generator.py
    python defense/password_generator.py --length 20 --count 5 --no-symbols
    python defense/password_generator.py --passphrase --words 5
"""

import argparse
import math
import secrets
import string

# ── Character pools ───────────────────────────────────────────────────────────
LOWERCASE  = string.ascii_lowercase
UPPERCASE  = string.ascii_uppercase
DIGITS     = string.digits
SYMBOLS    = "!@#$%^&*()-_=+[]{}|;:,.<>?"
AMBIGUOUS  = "0O1lI"  # visually confusing chars (optional exclusion)

# ── Passphrase word list (EFF large wordlist subset — 100 common words) ───────
EFF_WORDS = [
    "abbey", "abbot", "abide", "abode", "abort", "about", "above", "abuse",
    "abyss", "acing", "acorn", "acrid", "acted", "acute", "adage", "adept",
    "adult", "agile", "agree", "ahead", "aided", "aimed", "aired", "algae",
    "alien", "align", "allay", "allot", "allow", "alloy", "aloft", "alone",
    "altar", "amber", "amino", "ample", "angel", "angry", "anime", "ankle",
    "annex", "apart", "apple", "aptly", "arena", "argon", "aroma", "arose",
    "arson", "artsy", "ashen", "asked", "atlas", "atone", "attic", "audio",
    "audit", "augur", "avian", "avoid", "awash", "aware", "awful", "badge",
    "bagel", "banjo", "baron", "basic", "basis", "batch", "bathe", "beach",
    "began", "being", "below", "bench", "berry", "bevel", "birch", "black",
    "blade", "bland", "blaze", "blimp", "blind", "block", "blood", "bloom",
    "blown", "blunt", "blurb", "board", "bonus", "boost", "boxer", "brace",
    "braid", "brake", "brand", "brave", "break", "breed", "brick", "bride",
]


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> tuple[str, float]:
    """
    Generate one strong random password. Returns (password, entropy_bits).
    Guarantees at least one character from each enabled pool.
    """
    pool = LOWERCASE
    required: list[str] = [secrets.choice(LOWERCASE)]

    if use_upper:
        pool += UPPERCASE
        required.append(secrets.choice(UPPERCASE))
    if use_digits:
        pool += DIGITS
        required.append(secrets.choice(DIGITS))
    if use_symbols:
        pool += SYMBOLS
        required.append(secrets.choice(SYMBOLS))

    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS)

    remaining_len = length - len(required)
    if remaining_len < 0:
        remaining_len = 0

    rest = [secrets.choice(pool) for _ in range(remaining_len)]
    combined = required + rest

    # Shuffle securely
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]

    password = "".join(combined)
    entropy  = len(password) * math.log2(len(pool))
    return password, round(entropy, 1)


def generate_passphrase(word_count: int = 5, separator: str = "-") -> tuple[str, float]:
    """
    Generate a diceware-style passphrase from EFF_WORDS.
    Returns (passphrase, entropy_bits).
    """
    words = [secrets.choice(EFF_WORDS) for _ in range(word_count)]
    passphrase = separator.join(words)
    # Entropy: log2(pool_size) * word_count
    entropy = word_count * math.log2(len(EFF_WORDS))
    return passphrase, round(entropy, 1)


def strength_label(entropy: float) -> str:
    if entropy >= 80: return "VERY STRONG"
    if entropy >= 60: return "STRONG"
    if entropy >= 40: return "MODERATE"
    return "WEAK"


def main():
    parser = argparse.ArgumentParser(description="Cryptographically strong password generator.")
    parser.add_argument("--length",     type=int, default=16, help="Password length (default: 16).")
    parser.add_argument("--count",      type=int, default=5,  help="Number of passwords to generate.")
    parser.add_argument("--no-upper",   action="store_true",  help="Exclude uppercase letters.")
    parser.add_argument("--no-digits",  action="store_true",  help="Exclude digits.")
    parser.add_argument("--no-symbols", action="store_true",  help="Exclude symbols.")
    parser.add_argument("--no-ambiguous", action="store_true", help="Exclude ambiguous chars (0Ol1I).")
    parser.add_argument("--passphrase", action="store_true",  help="Generate a passphrase instead.")
    parser.add_argument("--words",      type=int, default=5,  help="Words in passphrase (default: 5).")
    parser.add_argument("--separator",  default="-",           help="Passphrase word separator.")
    args = parser.parse_args()

    print(f"\n{'─'*55}")
    if args.passphrase:
        print(f"  Passphrase Generator  ({args.words} words)")
        print(f"{'─'*55}")
        for i in range(args.count):
            pw, ent = generate_passphrase(args.words, args.separator)
            print(f"  [{i+1}] {pw:<45} ({ent:.0f} bits — {strength_label(ent)})")
    else:
        print(f"  Password Generator  (length={args.length})")
        print(f"{'─'*55}")
        for i in range(args.count):
            pw, ent = generate_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.no_ambiguous,
            )
            print(f"  [{i+1}] {pw:<{args.length + 5}} ({ent:.0f} bits — {strength_label(ent)})")
    print(f"{'─'*55}")
    print("\n[LESSON] These passwords are generated using Python's `secrets` module (CSPRNG).")
    print("  Never use `random` for security-sensitive values — it is NOT cryptographically secure.")
    print("  Passphrases (5+ words) have high entropy AND are easier to remember.\n")


if __name__ == "__main__":
    main()
