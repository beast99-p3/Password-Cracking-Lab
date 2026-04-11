"""
simulations/breach_scenario.py
===============================
EDUCATIONAL USE ONLY

Simulates a realistic corporate database breach.

Scenario:
  "MegaBank XYZ" — a fictional mid-size fintech company — suffers a database
  breach. An attacker exfiltrates the employees table which stores passwords
  as plain MD5 (the most common real-world failure mode found in actual breaches).

  The attack unfolds in waves:
    Wave 1 — Dictionary attack  (seconds)
    Wave 2 — Rule-based attack  (seconds–minutes)
    Wave 3 — Brute force        (minutes–hours for short passwords)

  For each compromised account, the module also resolves downstream blast radius:
  which systems they had access to, what data is now at risk.

This data is entirely fictional and is used solely to illustrate how real
breaches unfold so defenders can build better protections.
"""

import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List

from attacks.rule_attack    import apply_rules, ALL_RULES
from attacks.hash_identifier import identify_hash

# ── Fictional employee database ───────────────────────────────────────────────
# Fields: id, name, role, email, plaintext (kept server-side only for lab),
#         hash_algo, access_level, systems_accessible
FICTIONAL_EMPLOYEES = [
    # (id, name, role, email, plaintext_password, hash_algo, clearance, systems)
    (1,  "Alice Johnson",  "CEO",              "alice@megabank.xyz",   "Sunshine2019",   "md5",    "EXECUTIVE", ["All Systems", "Customer PII", "Financial Records", "HR Database"]),
    (2,  "Bob Martinez",   "DBA",              "bob@megabank.xyz",     "123456",          "md5",    "HIGH",      ["All Databases", "Backups", "Customer PII"]),
    (3,  "Carol Lee",      "Finance Manager",  "carol@megabank.xyz",   "carol123",        "md5",    "HIGH",      ["Financial Records", "Payroll", "Budget Reports"]),
    (4,  "David Chen",     "IT Admin",         "david@megabank.xyz",   "P@ssw0rd",        "md5",    "ADMIN",     ["Active Directory", "VPN", "Firewall", "Email Server"]),
    (5,  "Emma Wilson",    "HR Director",      "emma@megabank.xyz",    "letmein1",        "md5",    "HIGH",      ["HR Database", "Employee PII", "Salary Data"]),
    (6,  "Frank Nguyen",   "Customer Support", "frank@megabank.xyz",   "megabank1",       "md5",    "MEDIUM",    ["CRM System", "Customer Records", "Ticket System"]),
    (7,  "Grace Kim",      "Software Engineer","grace@megabank.xyz",   "qwerty",          "md5",    "MEDIUM",    ["Source Code Repos", "Dev Servers", "CI/CD Pipeline"]),
    (8,  "Henry Patel",    "Security Analyst", "henry@megabank.xyz",   "s3cur1ty!",       "sha1",   "HIGH",      ["SIEM", "Vulnerability Scans", "Incident Reports"]),
    (9,  "Iris Thompson",  "Legal Counsel",    "iris@megabank.xyz",    "LegalEagle2023",  "sha256", "HIGH",      ["Legal Documents", "Contracts", "Regulatory Filings"]),
    (10, "James Brown",    "Marketing",        "james@megabank.xyz",   "password1",       "md5",    "LOW",       ["CMS", "Marketing Emails", "Analytics"]),
    (11, "Karen Davis",    "Accountant",       "karen@megabank.xyz",   "monday",          "md5",    "MEDIUM",    ["Accounting Software", "Invoicing", "Tax Records"]),
    (12, "Leo Garcia",     "DevOps Engineer",  "leo@megabank.xyz",     "deploy#99",       "sha256", "ADMIN",     ["AWS Console", "Kubernetes", "Production Database", "Secrets Manager"]),
    (13, "Maria Santos",   "Data Scientist",   "maria@megabank.xyz",   "sunshine",        "md5",    "MEDIUM",    ["Data Warehouse", "ML Models", "Customer Analytics"]),
    (14, "Nathan Clark",   "CTO",              "nathan@megabank.xyz",  "Tr0ub4dor&3",    "bcrypt", "EXECUTIVE", ["All Systems", "Source Code", "Infrastructure"]),
    (15, "Olivia White",   "CFO",              "olivia@megabank.xyz",  "correct-horse-battery-staple", "argon2", "EXECUTIVE", ["Financial Systems", "Banking APIs", "Board Reports"]),
]

CLEARANCE_RISK = {
    "EXECUTIVE": "CRITICAL — Full organizational access, board-level data",
    "ADMIN":     "CRITICAL — Infrastructure takeover possible",
    "HIGH":      "SEVERE  — Sensitive PII and financial data exposed",
    "MEDIUM":    "HIGH    — Customer data and internal systems at risk",
    "LOW":       "MODERATE — Limited scope, pivot point for further attacks",
}

HASH_FUNCS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
}


def make_hash(plaintext: str, algo: str) -> str:
    if algo == "bcrypt":
        import bcrypt
        return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=4)).decode()
    if algo == "argon2":
        from argon2 import PasswordHasher
        return PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(plaintext)
    return HASH_FUNCS[algo](plaintext.encode()).hexdigest()


def build_database() -> List[Dict[str, Any]]:
    """Return the fictional employee database with hashed passwords."""
    db = []
    for (id_, name, role, email, plaintext, algo, clearance, systems) in FICTIONAL_EMPLOYEES:
        db.append({
            "id":        id_,
            "name":      name,
            "role":      role,
            "email":     email,
            "plaintext": plaintext,         # retained for hash generation and lab verification only
            "algo":      algo,
            "hash":      make_hash(plaintext, algo),
            "clearance": clearance,
            "systems":   systems,
            "cracked":   False,
            "cracked_by": None,
            "crack_time": None,
            "risk":      CLEARANCE_RISK[clearance],
        })
    return db


def run_wave1_dictionary(db: List[Dict[str, Any]], wordlist_path: str) -> List[Dict[str, Any]]:
    """Wave 1: plain dictionary attack against weak hash algos."""
    wordlist = [
        line.strip()
        for line in Path(wordlist_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]
    events = []
    for emp in db:
        if emp["cracked"] or emp["algo"] in ("bcrypt", "argon2"):
            continue
        t0 = time.perf_counter()
        for word in wordlist:
            digest = HASH_FUNCS[emp["algo"]](word.encode()).hexdigest()
            if digest == emp["hash"]:
                elapsed = time.perf_counter() - t0
                emp["cracked"]   = True
                emp["cracked_by"] = "dictionary"
                emp["crack_time"] = round(elapsed * 1000, 1)
                events.append({**emp, "wave": 1, "method": "Dictionary", "elapsed_ms": emp["crack_time"]})
                break
    return events


def run_wave2_rules(db: List[Dict[str, Any]], wordlist_path: str) -> List[Dict[str, Any]]:
    """Wave 2: rule-based mutations against remaining weak-algo accounts."""
    wordlist = [
        line.strip()
        for line in Path(wordlist_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]
    events = []
    for emp in db:
        if emp["cracked"] or emp["algo"] in ("bcrypt", "argon2"):
            continue
        t0 = time.perf_counter()
        for word in wordlist:
            for candidate in apply_rules(word, ALL_RULES):
                if HASH_FUNCS[emp["algo"]](candidate.encode()).hexdigest() == emp["hash"]:
                    elapsed = time.perf_counter() - t0
                    emp["cracked"]    = True
                    emp["cracked_by"] = "rule"
                    emp["crack_time"] = round(elapsed * 1000, 1)
                    events.append({**emp, "wave": 2, "method": "Rule-Based", "elapsed_ms": emp["crack_time"]})
                    break
            if emp["cracked"]:
                break
    return events


def run_wave3_bruteforce(db: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Wave 3: short-password brute force (≤4 chars) on remaining fast-hash accounts.
    Educational note: limited to 4 chars for demo speed; longer passwords would
    take hours–years depending on algorithm and attacker hardware.
    """
    import itertools, string
    charset = string.ascii_lowercase + string.digits
    MAX_LEN = 4   # kept short so the demo completes in seconds
    events  = []
    for emp in db:
        if emp["cracked"] or emp["algo"] in ("bcrypt", "argon2"):
            continue
        t0 = time.perf_counter()
        found = False
        for length in range(1, MAX_LEN + 1):
            for combo in itertools.product(charset, repeat=length):
                candidate = "".join(combo)
                if HASH_FUNCS[emp["algo"]](candidate.encode()).hexdigest() == emp["hash"]:
                    elapsed = time.perf_counter() - t0
                    emp["cracked"]    = True
                    emp["cracked_by"] = "brute_force"
                    emp["crack_time"] = round(elapsed * 1000, 1)
                    events.append({**emp, "wave": 3, "method": "Brute Force", "elapsed_ms": emp["crack_time"]})
                    found = True
                    break
            if found:
                break
    return events


def get_survivor_analysis(db: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return accounts that resisted all attacks and explain why."""
    return [
        {**emp, "reason": "bcrypt/Argon2 with high work factor — computationally infeasible to crack"}
        for emp in db if not emp["cracked"]
    ]
