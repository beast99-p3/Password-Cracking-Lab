"""
Tiny rainbow-table demo for unsalted MD5 over a fixed keyspace (educational only).

Uses distinct per-step reduction functions R_i (Oechslin-style) so chains collide
less than Hellman's single-reduction tables. Keyspace is 100 two-digit strings so
the full chain set can be built instantly in the lab.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

CHAIN_LENGTH = 4
KEYSPACE_SIZE = 100


def _md5_hex(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode("utf-8")).hexdigest()


def reduce_digest(step: int, digest_hex: str, size: int = KEYSPACE_SIZE) -> str:
    """Map a hex digest back into the demo keyspace (two-digit strings)."""
    v = int(digest_hex, 16)
    v = (v + step * 0x9E3779B9 + 0x517CC1B727220A95) % size
    return f"{v:02d}"


def chain_trace(start: str, t: int) -> Tuple[str, List[Dict[str, Any]]]:
    """Return (end_plaintext, steps) for a chain of length t hash steps."""
    p = start
    steps: List[Dict[str, Any]] = []
    for step in range(t):
        h = _md5_hex(p)
        steps.append({"plain": p, "hash": h, "step": step})
        if step == t - 1:
            end = reduce_digest(step, h)
            return end, steps
        p = reduce_digest(step, h)
    raise RuntimeError("unreachable")


_FULL_DEMO: Optional[Dict[str, Any]] = None


def full_demo() -> Dict[str, Any]:
    """Single cached build for the web app (100 short chains)."""
    global _FULL_DEMO
    if _FULL_DEMO is None:
        _FULL_DEMO = build_full_demo(CHAIN_LENGTH)
    return _FULL_DEMO


def build_full_demo(t: int = CHAIN_LENGTH) -> Dict[str, Any]:
    """Precompute all chains starting at each key in 00..99-1."""
    table: List[Dict[str, str]] = []
    chains: List[Dict[str, Any]] = []
    for i in range(KEYSPACE_SIZE):
        start = f"{i:02d}"
        end, trace = chain_trace(start, t)
        table.append({"start": start, "end": end})
        chains.append({"start": start, "end": end, "steps": trace})
    return {"chain_length": t, "table": table, "chains": chains}


def lookup_preimage(target_hash: str, table: List[Dict[str, str]], t: int) -> Optional[Dict[str, Any]]:
    """
    Rainbow lookup with verification. Returns dict with plaintext and trace, or None.
    """
    target = target_hash.lower().strip()
    if len(target) != 32 or any(c not in "0123456789abcdef" for c in target):
        return None

    for start_col in range(t - 1, -1, -1):
        cur = target
        last_pw = ""
        for j in range(start_col, t):
            last_pw = reduce_digest(j, cur)
            cur = _md5_hex(last_pw)

        for row in table:
            if row["end"] != last_pw:
                continue
            chain_start = row["start"]
            p = chain_start
            walk: List[Dict[str, str]] = []
            for step in range(t):
                h = _md5_hex(p)
                walk.append({"plain": p, "hash": h})
                if h == target:
                    return {
                        "plaintext": p,
                        "chain_start": chain_start,
                        "matched_end": last_pw,
                        "start_column": start_col,
                        "verify_steps": walk,
                    }
                if step == t - 1:
                    break
                p = reduce_digest(step, h)

    return None


def demo_payload(sample_limit: int = 8) -> Dict[str, Any]:
    data = full_demo()
    chains = data["chains"]
    sample_hashes = []
    for c in chains[:3]:
        if c["steps"]:
            sample_hashes.append({"label": f"from chain starting {c['start']}", "hash": c["steps"][1]["hash"]})

    return {
        "algorithm": "md5",
        "chain_length": CHAIN_LENGTH,
        "keyspace": f"{KEYSPACE_SIZE} passwords (two-digit strings 00–{KEYSPACE_SIZE - 1:02d})",
        "keyspace_size": KEYSPACE_SIZE,
        "chains_total": len(chains),
        "chains_sample": chains[:sample_limit],
        "sample_target_hashes": sample_hashes,
        "lesson": {
            "why": (
                "A rainbow table stores only the start and end of long hash→reduce chains "
                "instead of every password. At lookup time you re-derive the end and collide "
                "against the table, then replay the chain to recover the preimage."
            ),
            "salt": (
                "A unique per-user salt makes each password's hash different even when the "
                "password is the same, so a precomputed table for the unsalted algorithm no "
                "longer matches — this is why real systems store salted slow hashes (bcrypt, Argon2)."
            ),
        },
    }
