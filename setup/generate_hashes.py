"""
setup/generate_hashes.py
========================
EDUCATIONAL USE ONLY

Generates intentionally WEAK, UNSALTED hashes from a list of plain-text passwords.
This simulates a poorly implemented password database so you can practice
recognizing and cracking weak storage methods in a controlled lab environment.

Supported algorithms: md5, sha1, sha256
Output: setup/hashes.txt  (format: <algorithm>:<hash>:<optional_hint>)
"""

import argparse
import hashlib
import os
from pathlib import Path
from typing import Dict, List

from tabulate import tabulate

ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}


def hash_password(password: str, algorithm: str) -> str:
    """Return the hex digest of `password` using `algorithm` (no salt — intentionally weak)."""
    h = ALGORITHMS[algorithm](password.encode("utf-8"))
    return h.hexdigest()


def generate_hashes(passwords: list[str], algorithms: list[str]) -> list[Dict[str, str]]:
    """Return a list of records: {plaintext, algorithm, hash}."""
    records = []
    for pwd in passwords:
        for algo in algorithms:
            records.append({
                "plaintext": pwd,
                "algorithm": algo,
                "hash": hash_password(pwd, algo),
            })
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Lab Setup — Generate weak unsalted hashes for cracking practice."
    )
    parser.add_argument(
        "--input",
        default=str(Path(__file__).parent / "sample_passwords.txt"),
        help="Path to plaintext password list (one per line).",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent / "hashes.txt"),
        help="Output file for generated hashes.",
    )
    parser.add_argument(
        "--algorithms",
        nargs="+",
        choices=list(ALGORITHMS.keys()),
        default=["md5", "sha1", "sha256"],
        help="Hash algorithm(s) to use.",
    )
    parser.add_argument(
        "--show-plaintext",
        action="store_true",
        help="Print plaintext alongside hash in the summary table (lab use only).",
    )
    args = parser.parse_args()

    # Read passwords
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        return

    passwords = [
        line.strip()
        for line in input_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print(f"[*] Loaded {len(passwords)} passwords from {input_path}")

    # Generate hashes
    records = generate_hashes(passwords, args.algorithms)

    # Write output — only hashes (no plaintext) so the file simulates a real leak
    output_path = Path(args.output)
    with output_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(f"{r['algorithm']}:{r['hash']}\n")

    print(f"[+] Wrote {len(records)} hashes to {output_path}")

    # Print summary table
    if args.show_plaintext:
        table_data = [[r["plaintext"], r["algorithm"], r["hash"]] for r in records]
        print("\n" + tabulate(table_data, headers=["Plaintext", "Algorithm", "Hash"], tablefmt="grid"))
    else:
        table_data = [[r["algorithm"], r["hash"]] for r in records]
        print("\n" + tabulate(table_data, headers=["Algorithm", "Hash (target)"], tablefmt="grid"))
        print("\n[!] Plaintext NOT shown. Use --show-plaintext only in a fully isolated lab.")

    print(
        "\n[LESSON] Notice how the same password produces the same hash every time "
        "(no salt). This allows precomputed rainbow-table and dictionary attacks."
    )


if __name__ == "__main__":
    main()
