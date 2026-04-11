"""
defense/secure_hashing.py
=========================
Demonstrates the RIGHT way to store and verify passwords:
  • Unique per-user salt
  • Modern adaptive hashing: bcrypt and Argon2
  • Timing-safe comparison

Contrast:
  BAD  → plain MD5/SHA1 (fast, no salt, rainbow-table vulnerable)
  GOOD → bcrypt / Argon2 (slow by design, salted, GPU-resistant)

Usage:
    python defense/secure_hashing.py
"""

import hashlib
import os
import time
from typing import Any, Callable, TypeVar

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from tabulate import tabulate
from colorama import Fore, init

init(autoreset=True)


# ── Insecure approaches (for comparison) ─────────────────────────────────────

def insecure_md5(password: str) -> str:
    """BAD: no salt, fast algorithm."""
    return hashlib.md5(password.encode()).hexdigest()


def slightly_better_sha256_salted(password: str) -> tuple[str, str]:
    """
    STILL BAD: manual salting + SHA-256 is faster than MD5,
    but SHA-256 is NOT designed for passwords — GPUs can compute
    billions per second.
    """
    salt = os.urandom(16).hex()
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, digest


# ── Secure approaches ─────────────────────────────────────────────────────────

def secure_bcrypt_hash(password: str, cost: int = 12) -> bytes:
    """
    GOOD: bcrypt — slow by design, built-in salt, work factor adjustable.
    cost=12 → ~250ms per hash on modern hardware (2024).
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=cost))


def verify_bcrypt(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


def secure_argon2_hash(password: str) -> str:
    """
    BEST CURRENT STANDARD: Argon2id — winner of the Password Hashing Competition.
    Memory-hard (defeats GPU/ASIC attacks), time + memory configurable.
    """
    ph = PasswordHasher(
        time_cost=3,       # number of iterations
        memory_cost=65536, # 64 MB RAM required per hash
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )
    return ph.hash(password)


def verify_argon2(password: str, stored_hash: str) -> bool:
    ph = PasswordHasher()
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


# ── Demo runner ───────────────────────────────────────────────────────────────

T = TypeVar("T")

def time_operation(fn: Callable[..., T], *args: Any) -> tuple[T, float]:
    """Return (result, elapsed_ms)."""
    start = time.perf_counter()
    result = fn(*args)
    elapsed = (time.perf_counter() - start) * 1000
    return result, elapsed


def run_demo(password: str = "MyS3cretPa$$word"):
    print(f"\n{'═'*60}")
    print(f"  Secure Password Hashing Demo")
    print(f"  Test password: '{password}'")
    print(f"{'═'*60}\n")

    # ── 1. Insecure MD5 ───────────────────────────────────────────────────────
    md5_hash, t_md5 = time_operation(insecure_md5, password)
    print(f"{Fore.RED}[BAD]  Unsalted MD5")
    print(f"       Hash   : {md5_hash}")
    print(f"       Time   : {t_md5:.3f} ms")
    print(f"       Problem: No salt — identical for all users with same password.")
    print(f"                GPU cracks 200 billion MD5/sec. This hash lasts milliseconds.\n")

    # ── 2. SHA-256 with manual salt ───────────────────────────────────────────
    (salt, sha256_hash), t_sha = time_operation(slightly_better_sha256_salted, password)
    print(f"{Fore.YELLOW}[MEDIOCRE]  Salted SHA-256 (manual)")
    print(f"       Salt   : {salt}")
    print(f"       Hash   : {sha256_hash}")
    print(f"       Time   : {t_sha:.3f} ms")
    print(f"       Problem: SHA-256 is a general-purpose hash — designed to be FAST.")
    print(f"                A GPU still computes billions/sec even with a salt.\n")

    # ── 3. bcrypt ─────────────────────────────────────────────────────────────
    bcrypt_hash, t_bcrypt = time_operation(secure_bcrypt_hash, password, 12)
    bcrypt_ok, t_bcrypt_v = time_operation(verify_bcrypt, password, bcrypt_hash)
    bcrypt_fail, _        = time_operation(verify_bcrypt, "wrongpassword", bcrypt_hash)

    print(f"{Fore.GREEN}[GOOD]  bcrypt (cost=12)")
    print(f"       Hash   : {bcrypt_hash.decode()}")
    print(f"       Hash time   : {t_bcrypt:.1f} ms  ← intentionally slow")
    print(f"       Verify (ok) : {t_bcrypt_v:.1f} ms  → {bcrypt_ok}")
    print(f"       Verify (bad): {'Pass (wrong password rejected)' if not bcrypt_fail else 'FAIL'}")
    print(f"       Benefit: Built-in salt (see $2b$12$...), work factor adjustable.")
    print(f"                {t_bcrypt:.0f} ms/hash → GPU limited to ~{1000/t_bcrypt:.0f} attempts/sec.\n")

    # ── 4. Argon2id ───────────────────────────────────────────────────────────
    argon2_hash, t_argon = time_operation(secure_argon2_hash, password)
    argon2_ok, t_argon_v = time_operation(verify_argon2, password, argon2_hash)
    argon2_fail, _       = time_operation(verify_argon2, "wrongpassword", argon2_hash)

    print(f"{Fore.GREEN}[BEST]  Argon2id (time=3, memory=64 MB)")
    print(f"       Hash   : {argon2_hash[:60]}…")
    print(f"       Hash time   : {t_argon:.1f} ms  ← intentionally slow + memory-hard")
    print(f"       Verify (ok) : {t_argon_v:.1f} ms  → {argon2_ok}")
    print(f"       Verify (bad): {'Pass (wrong password rejected)' if not argon2_fail else 'FAIL'}")
    print(f"       Benefit: Memory-hard — filling 64 MB RAM per attempt destroys GPU parallelism.\n")

    # ── Comparison table ──────────────────────────────────────────────────────
    rows = [
        ["Unsalted MD5",    f"{t_md5:.2f} ms",    "No",  "No",  "~200 B/sec GPU",   "❌ Terrible"],
        ["Salted SHA-256",  f"{t_sha:.2f} ms",     "Yes", "No",  "~10  B/sec GPU",   "⚠️  Poor"],
        ["bcrypt (12)",     f"{t_bcrypt:.0f} ms",  "Yes", "No",  f"~{1000/t_bcrypt:.0f}/sec GPU", "✅ Good"],
        ["Argon2id",        f"{t_argon:.0f} ms",   "Yes", "Yes", "~few/sec GPU",     "✅ Best"],
    ]
    print(tabulate(
        rows,
        headers=["Algorithm", "Hash Time", "Salted", "Memory-Hard", "GPU Attack Rate", "Verdict"],
        tablefmt="grid"
    ))

    print(f"\n{Fore.YELLOW}[TAKEAWAY]")
    print("  1. NEVER store passwords as plain text or using MD5/SHA1.")
    print("  2. Use bcrypt (cost ≥ 12) or Argon2id for all new systems.")
    print("  3. The salt must be unique per user — never reuse salts.")
    print("  4. Re-hash on login as you increase the work factor over time.")
    print("  5. A 'slow' hash is a feature, not a bug — it defeats brute force.\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Secure hashing demo.")
    parser.add_argument("--password", default="MyS3cretPa$$word",
                        help="Password to hash in the demo.")
    args = parser.parse_args()
    run_demo(args.password)


if __name__ == "__main__":
    main()
