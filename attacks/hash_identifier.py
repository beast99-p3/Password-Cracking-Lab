"""
attacks/hash_identifier.py
==========================
EDUCATIONAL USE ONLY

Identifies the probable hash algorithm based on hash length and character set.
Useful as a first step before choosing a cracking strategy.

Usage:
    python attacks/hash_identifier.py <hash_or_file>

Examples:
    python attacks/hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
    python attacks/hash_identifier.py setup/hashes.txt
"""

import sys
import re
from pathlib import Path
from tabulate import tabulate

# Map of (length, charset_pattern) -> algorithm names
HASH_SIGNATURES = [
    (32,  r"^[0-9a-f]{32}$",           ["MD5", "MD4", "LM Hash (half)"]),
    (40,  r"^[0-9a-f]{40}$",           ["SHA-1", "RIPEMD-160 (unlikely)"]),
    (56,  r"^[0-9a-f]{56}$",           ["SHA-224"]),
    (64,  r"^[0-9a-f]{64}$",           ["SHA-256", "BLAKE2s-256"]),
    (96,  r"^[0-9a-f]{96}$",           ["SHA-384"]),
    (128, r"^[0-9a-f]{128}$",          ["SHA-512", "BLAKE2b-512"]),
    (60,  r"^\$2[ayb]\$.{56}$",        ["bcrypt"]),
    (None,r"^\$argon2",                ["Argon2"]),
    (None,r"^\$5\$",                   ["SHA-256 crypt (Unix)"]),
    (None,r"^\$6\$",                   ["SHA-512 crypt (Unix)"]),
    (None,r"^\$1\$",                   ["MD5 crypt (Unix)"]),
    (None,r"^[A-Za-z0-9+/]{24}={0,2}$", ["Base64 (not a hash — encoded data)"]),
]


def identify_hash(h: str) -> list[str]:
    """Return a list of likely algorithm names for a given hash string."""
    h = h.strip()
    candidates = []
    for length, pattern, names in HASH_SIGNATURES:
        if length and len(h) != length:
            continue
        if re.match(pattern, h, re.IGNORECASE):
            candidates.extend(names)
    return candidates if candidates else ["Unknown — no matching signature"]


def process_input(source: str):
    path = Path(source)
    if path.exists():
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        print(f"[*] Analyzing {len(lines)} entries from {path}\n")
        rows = []
        for line in lines:
            # Support "algorithm:hash" format from generate_hashes.py
            parts = line.split(":", 1)
            h = parts[-1].strip()
            declared = parts[0].strip() if len(parts) == 2 else "—"
            guesses = identify_hash(h)
            rows.append([h[:20] + "…" if len(h) > 20 else h, declared, ", ".join(guesses)])
        print(tabulate(rows, headers=["Hash (truncated)", "Declared Algo", "Identified As"], tablefmt="grid"))
    else:
        # Treat as a raw hash string
        guesses = identify_hash(source)
        print(f"\n[*] Input : {source}")
        print(f"[*] Length: {len(source)} chars")
        print(f"[+] Likely algorithm(s): {', '.join(guesses)}")
        print(
            "\n[LESSON] Hash identification is heuristic — length and charset narrow it down, "
            "but you need context (the application source / database schema) to be certain."
        )


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    process_input(sys.argv[1])


if __name__ == "__main__":
    main()
