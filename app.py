"""
app.py  —  Ethical Password Cracking Lab Web Interface
=======================================================
EDUCATIONAL USE ONLY

Run:
    python app.py
Then open: http://localhost:5000
"""

import hashlib
import itertools
import json
import math
import os
import queue
import secrets
import string
import sys
import time
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
    stream_with_context,
)
from flask_cors import CORS

# ── Path setup ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from attacks.rule_attack      import rule_attack, apply_rules, ALL_RULES
from attacks.hash_identifier  import identify_hash
from attacks.rainbow_demo     import CHAIN_LENGTH, demo_payload, full_demo, lookup_preimage
from defense.password_generator import generate_password, generate_passphrase, strength_label
from simulations.breach_scenario import FICTIONAL_EMPLOYEES

app = Flask(__name__)
CORS(app)

# ── In-memory state ───────────────────────────────────────────────────────────
history: List[Dict[str, Any]] = []            # session history
bf_jobs: Dict[str, Dict[str, Any]] = {}       # brute-force job progress

ALGORITHMS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
}

CHARSETS = {
    "digits":    string.digits,
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "alpha":     string.ascii_letters,
    "alphanum":  string.ascii_letters + string.digits,
    "common":    string.ascii_letters + string.digits + "!@#$%",
}


def hash_word(word: str, algorithm: str) -> str:
    return ALGORITHMS[algorithm](word.encode("utf-8")).hexdigest()


def log_history(operation: str, payload: Dict[str, Any]):
    history.insert(0, {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "operation": operation,
        **payload,
    })
    if len(history) > 200:
        history.pop()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    """Browsers request /favicon.ico by default; serve the SVG with an icon MIME type."""
    return send_from_directory(
        BASE_DIR / "static",
        "favicon.svg",
        mimetype="image/svg+xml",
    )


# ─── Setup ────────────────────────────────────────────────────────────────────

@app.route("/api/generate-hashes", methods=["POST"])
def api_generate_hashes():
    data = request.get_json(force=True)
    passwords  = [p.strip() for p in data.get("passwords", "").splitlines() if p.strip()]
    algorithms = data.get("algorithms", ["md5", "sha1", "sha256"])

    if not passwords:
        return jsonify({"error": "No passwords provided."}), 400

    records = []
    for pwd in passwords:
        for algo in algorithms:
            records.append({
                "algorithm": algo,
                "hash": hash_word(pwd, algo),
                "plaintext": pwd,          # only shown in lab context
            })

    # Save to file
    out_path = BASE_DIR / "setup" / "hashes.txt"
    out_path.parent.mkdir(exist_ok=True)
    with out_path.open("w") as f:
        for r in records:
            f.write(f"{r['algorithm']}:{r['hash']}\n")

    log_history("Generate Hashes", {
        "details": f"{len(passwords)} passwords × {len(algorithms)} algorithms = {len(records)} hashes",
        "status": "done",
    })
    return jsonify({"records": records, "saved_to": "setup/hashes.txt"})


# ─── Hash Identifier ──────────────────────────────────────────────────────────

@app.route("/api/identify-hash", methods=["POST"])
def api_identify_hash():
    data = request.get_json(force=True)
    hashes = [h.strip() for h in data.get("hashes", "").splitlines() if h.strip()]
    if not hashes:
        return jsonify({"error": "No hashes provided."}), 400

    results = []
    for h in hashes:
        parts = h.split(":", 1)
        raw = parts[-1].strip()
        declared = parts[0].strip() if len(parts) == 2 and len(parts[0]) < 10 else "—"
        guesses = identify_hash(raw)
        results.append({"hash": raw, "declared": declared, "identified": guesses})

    log_history("Hash Identifier", {"details": f"Analyzed {len(results)} hashes", "status": "done"})
    return jsonify({"results": results})


# ─── Dictionary Attack ────────────────────────────────────────────────────────

@app.route("/api/dictionary-attack", methods=["POST"])
def api_dictionary_attack():
    data       = request.get_json(force=True)
    raw_hashes = [h.strip() for h in data.get("hashes", "").splitlines() if h.strip()]
    wordlist_name = data.get("wordlist", "common_passwords.txt")
    algorithm  = data.get("algorithm", "md5")

    if algorithm not in ALGORITHMS:
        return jsonify({"error": "Unknown algorithm."}), 400

    wl_path = BASE_DIR / "wordlists" / wordlist_name
    if not wl_path.exists():
        return jsonify({"error": f"Wordlist not found: {wordlist_name}"}), 400

    wordlist = [
        line.strip()
        for line in wl_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]

    results = []
    cracked = 0
    start = time.perf_counter()

    for line in raw_hashes:
        parts = line.split(":", 1)
        target = parts[-1].strip().lower()
        algo   = parts[0].strip() if len(parts) == 2 and parts[0].strip() in ALGORITHMS else algorithm

        plaintext = None
        attempts  = 0
        for word in wordlist:
            attempts += 1
            if hash_word(word, algo) == target:
                plaintext = word
                cracked += 1
                break

        results.append({
            "hash":      target[:16] + "…" if len(target) > 16 else target,
            "full_hash": target,
            "algorithm": algo,
            "cracked":   plaintext is not None,
            "plaintext": plaintext or "—",
            "attempts":  attempts,
        })

    elapsed = time.perf_counter() - start
    rate    = len(wordlist) * len(raw_hashes) / elapsed if elapsed > 0 else 0

    log_history("Dictionary Attack", {
        "details": f"{cracked}/{len(raw_hashes)} cracked from {wordlist_name}",
        "status": "cracked" if cracked > 0 else "not_found",
    })
    return jsonify({
        "results":  results,
        "cracked":  cracked,
        "total":    len(raw_hashes),
        "elapsed":  round(elapsed, 3),
        "rate":     round(rate),
        "wordlist_size": len(wordlist),
    })


# ─── Rule-Based Attack ────────────────────────────────────────────────────────

@app.route("/api/rule-attack", methods=["POST"])
def api_rule_attack():
    data      = request.get_json(force=True)
    target    = data.get("hash", "").strip().lower()
    algorithm = data.get("algorithm", "md5")
    rules     = data.get("rules", ALL_RULES)
    wordlist_name = data.get("wordlist", "common_passwords.txt")

    if not target:
        return jsonify({"error": "No hash provided."}), 400

    wl_path = BASE_DIR / "wordlists" / wordlist_name
    if not wl_path.exists():
        return jsonify({"error": "Wordlist not found."}), 400

    result = rule_attack(target, str(wl_path), algorithm, rules)

    log_history("Rule-Based Attack", {
        "details": f"{'CRACKED: ' + result['plaintext'] if result['cracked'] else 'Not found'} "
                   f"({result['attempts']:,} attempts, {len(rules)} rules)",
        "status": "cracked" if result["cracked"] else "not_found",
    })
    return jsonify(result)


# ─── Rainbow table (educational micro-demo) ─────────────────────────────────

@app.route("/api/rainbow/demo", methods=["GET"])
def api_rainbow_demo():
    return jsonify(demo_payload())


@app.route("/api/rainbow/lookup", methods=["POST"])
def api_rainbow_lookup():
    data = request.get_json(force=True)
    target = data.get("hash", "").strip().lower()
    if not target:
        return jsonify({"error": "No hash provided."}), 400

    fd = full_demo()
    result = lookup_preimage(target, fd["table"], CHAIN_LENGTH)
    if result:
        log_history("Rainbow Table Demo", {
            "details": f"preimage={result['plaintext']} (chain {result['chain_start']}→{result['matched_end']})",
            "status": "cracked",
        })
        return jsonify({"found": True, **result})

    log_history("Rainbow Table Demo", {
        "details": "lookup miss (outside keyspace or no chain match)",
        "status": "not_found",
    })
    return jsonify({
        "found": False,
        "message": "No preimage in this demo. Tables only cover unsalted MD5 of two-digit passwords 00–99.",
    })


# ─── Brute Force (SSE streaming) ──────────────────────────────────────────────

def _brute_force_worker(job_id: str, target: str, algorithm: str,
                         charset: str, max_length: int):
    """Run in a background thread; push updates into bf_jobs[job_id]."""
    job      = bf_jobs[job_id]
    total    = sum(len(charset) ** l for l in range(1, max_length + 1))
    attempts = 0
    start    = time.perf_counter()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            if job.get("cancel"):
                job["status"] = "cancelled"
                return

            candidate = "".join(combo)
            attempts += 1
            digest = ALGORITHMS[algorithm](candidate.encode()).hexdigest()

            if digest == target:
                elapsed = time.perf_counter() - start
                job.update({
                    "status":    "cracked",
                    "plaintext": candidate,
                    "attempts":  attempts,
                    "elapsed":   round(elapsed, 4),
                    "rate":      round(attempts / elapsed) if elapsed > 0 else 0,
                    "progress":  100,
                })
                return

            if attempts % 5000 == 0:
                elapsed = time.perf_counter() - start
                job.update({
                    "status":   "running",
                    "attempts": attempts,
                    "progress": round((attempts / total) * 100, 1),
                    "rate":     round(attempts / elapsed) if elapsed > 0 else 0,
                    "elapsed":  round(elapsed, 2),
                })

    elapsed = time.perf_counter() - start
    job.update({
        "status":    "not_found",
        "attempts":  attempts,
        "elapsed":   round(elapsed, 4),
        "rate":      round(attempts / elapsed) if elapsed > 0 else 0,
        "progress":  100,
    })


@app.route("/api/brute-force/start", methods=["POST"])
def api_brute_force_start():
    data      = request.get_json(force=True)
    target    = data.get("hash", "").strip().lower()
    algorithm = data.get("algorithm", "md5")
    charset   = CHARSETS.get(data.get("charset", "digits"), string.digits)
    max_len   = min(int(data.get("max_length", 4)), 6)  # cap at 6 for demo safety

    if not target:
        return jsonify({"error": "No hash provided."}), 400
    if algorithm not in ALGORITHMS:
        return jsonify({"error": "Unknown algorithm."}), 400

    total = sum(len(charset) ** l for l in range(1, max_len + 1))
    job_id = str(uuid.uuid4())
    bf_jobs[job_id] = {
        "status": "running", "progress": 0, "attempts": 0,
        "plaintext": None, "elapsed": 0, "rate": 0,
        "target": target, "algorithm": algorithm,
        "charset_name": data.get("charset", "digits"),
        "max_length": max_len, "total": total,
    }

    t = threading.Thread(target=_brute_force_worker,
                         args=(job_id, target, algorithm, charset, max_len),
                         daemon=True)
    t.start()

    log_history("Brute Force", {
        "details": f"hash={target[:12]}… algo={algorithm} charset={data.get('charset')} max_len={max_len}",
        "status": "started",
    })
    return jsonify({"job_id": job_id, "total": total})


@app.route("/api/brute-force/status/<job_id>")
def api_brute_force_status(job_id):
    job = bf_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404

    # Update history when done
    if job["status"] in ("cracked", "not_found", "cancelled") and job.get("_logged") is None:
        job["_logged"] = True
        # Update the history entry
        for h in history:
            if h["operation"] == "Brute Force" and job["target"][:12] in h.get("details", ""):
                h["status"] = job["status"]
                if job["status"] == "cracked":
                    h["details"] += f" → '{job['plaintext']}'"
                break

    return jsonify(job)


@app.route("/api/brute-force/cancel/<job_id>", methods=["POST"])
def api_brute_force_cancel(job_id):
    if job_id in bf_jobs:
        bf_jobs[job_id]["cancel"] = True
        return jsonify({"ok": True})
    return jsonify({"error": "Job not found."}), 404


# ─── Password Strength ────────────────────────────────────────────────────────

from defense.password_strength import (
    check_length, check_lowercase, check_uppercase, check_digits,
    check_special, check_no_repeat, check_no_sequence, check_not_common,
    estimate_entropy, score_label, COMMON_PASSWORDS,
)
import re as _re

def _strip_color(s: str) -> str:
    return _re.sub(r"\x1b\[[0-9;]*m", "", s)


@app.route("/api/strength-check", methods=["POST"])
def api_strength_check():
    data     = request.get_json(force=True)
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password."}), 400

    checks_raw = [
        check_length(password),
        check_lowercase(password),
        check_uppercase(password),
        check_digits(password),
        check_special(password),
        check_no_repeat(password),
        check_no_sequence(password),
        check_not_common(password),
    ]
    checks = [{"score": s, "msg": _strip_color(m)} for s, m in checks_raw]
    total  = max(0, min(100, sum(c["score"] for c in checks)))
    entropy = estimate_entropy(password)
    label   = _strip_color(score_label(total))

    log_history("Strength Check", {
        "details": f"score={total}/100, entropy={entropy:.0f} bits — {label}",
        "status": "done",
    })
    return jsonify({
        "checks":  checks,
        "total":   total,
        "entropy": round(entropy, 1),
        "label":   label,
    })


# ─── Secure Hashing Demo ──────────────────────────────────────────────────────

@app.route("/api/secure-hash", methods=["POST"])
def api_secure_hash():
    import bcrypt
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    data     = request.get_json(force=True)
    password = data.get("password", "MyS3cretPa$$word")

    results = []

    # MD5 (bad)
    t0 = time.perf_counter()
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    t_md5 = (time.perf_counter() - t0) * 1000
    results.append({
        "algorithm": "Unsalted MD5", "hash": md5_hash,
        "time_ms": round(t_md5, 3), "salted": False, "memory_hard": False,
        "verdict": "Terrible", "gpu_rate": "~200 B/sec",
    })

    # SHA-256 salted (mediocre)
    t0 = time.perf_counter()
    salt_hex = os.urandom(16).hex()
    sha256_hash = hashlib.sha256((salt_hex + password).encode()).hexdigest()
    t_sha = (time.perf_counter() - t0) * 1000
    results.append({
        "algorithm": "Salted SHA-256", "hash": sha256_hash,
        "time_ms": round(t_sha, 3), "salted": True, "memory_hard": False,
        "verdict": "Poor", "gpu_rate": "~10 B/sec",
    })

    # bcrypt
    t0 = time.perf_counter()
    bc_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    t_bcrypt = (time.perf_counter() - t0) * 1000
    results.append({
        "algorithm": "bcrypt (cost=12)", "hash": bc_hash,
        "time_ms": round(t_bcrypt, 1), "salted": True, "memory_hard": False,
        "verdict": "Good", "gpu_rate": f"~{round(1000/t_bcrypt)}/sec",
    })

    # Argon2id
    t0 = time.perf_counter()
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
    a2_hash = ph.hash(password)
    t_argon = (time.perf_counter() - t0) * 1000
    results.append({
        "algorithm": "Argon2id", "hash": a2_hash,
        "time_ms": round(t_argon, 1), "salted": True, "memory_hard": True,
        "verdict": "Best", "gpu_rate": "~few/sec",
    })

    log_history("Secure Hash Demo", {"details": "Compared MD5 / SHA-256 / bcrypt / Argon2id", "status": "done"})
    return jsonify({"results": results})


# ─── Password Generator ───────────────────────────────────────────────────────

@app.route("/api/generate-password", methods=["POST"])
def api_generate_password():
    data   = request.get_json(force=True)
    mode   = data.get("mode", "password")  # "password" | "passphrase"
    count  = min(int(data.get("count", 5)), 20)

    if mode == "passphrase":
        words = int(data.get("words", 5))
        sep   = data.get("separator", "-")
        results = []
        for _ in range(count):
            pw, ent = generate_passphrase(words, sep)
            results.append({"password": pw, "entropy": ent, "strength": strength_label(ent)})
    else:
        length   = min(int(data.get("length", 16)), 64)
        results  = []
        for _ in range(count):
            pw, ent = generate_password(
                length=length,
                use_upper=data.get("use_upper", True),
                use_digits=data.get("use_digits", True),
                use_symbols=data.get("use_symbols", True),
                exclude_ambiguous=data.get("exclude_ambiguous", False),
            )
            results.append({"password": pw, "entropy": ent, "strength": strength_label(ent)})

    log_history("Password Generator", {"details": f"Generated {count} {mode}(s)", "status": "done"})
    return jsonify({"results": results})


# ─── Breach Simulation ───────────────────────────────────────────────────────

@app.route("/api/breach/database")
def api_breach_database():
    """Return the fictional employee database (hashes only, no plaintext)."""
    from simulations.breach_scenario import build_database
    db = build_database()
    public = []
    for emp in db:
        public.append({
            "id":        emp["id"],
            "name":      emp["name"],
            "role":      emp["role"],
            "email":     emp["email"],
            "hash_algo": emp["algo"],
            "hash":      emp["hash"],
            "clearance": emp["clearance"],
            "systems":   emp["systems"],
            "risk":      emp["risk"],
        })
    return jsonify({"employees": public, "total": len(public)})


@app.route("/api/breach/simulate", methods=["POST"])
def api_breach_simulate():
    """
    Run the full breach simulation (all 3 waves).
    Returns per-wave events and a final survivor analysis.
    """
    from simulations.breach_scenario import (
        build_database, run_wave1_dictionary,
        run_wave2_rules, run_wave3_bruteforce,
        get_survivor_analysis,
    )

    wl_path = str(BASE_DIR / "wordlists" / "common_passwords.txt")
    db      = build_database()

    t_total = time.perf_counter()
    w1_raw = run_wave1_dictionary(db, wl_path)
    w2_raw = run_wave2_rules(db, wl_path)
    w3_raw = run_wave3_bruteforce(db)
    survivors_raw = get_survivor_analysis(db)
    total_elapsed = round((time.perf_counter() - t_total) * 1000, 1)

    # All cracked accounts (need plaintext for blast-radius display)
    cracked_all = {e["id"]: e for e in w1_raw + w2_raw + w3_raw}

    def emp_public(e, include_plaintext=False):
        out = {
            "id": e["id"], "name": e["name"], "role": e["role"],
            "email": e["email"], "hash_algo": e["algo"],
            "clearance": e["clearance"], "systems": e["systems"],
            "risk": e["risk"], "crack_time_ms": e.get("crack_time"),
            "cracked_by": e.get("cracked_by"),
        }
        if include_plaintext:
            out["plaintext"] = e["plaintext"]
        return out

    def wave_events(raw_cracked, all_db, wave_num):
        """Build timeline events for one wave: cracked + survived accounts."""
        cracked_ids = {e["id"] for e in raw_cracked}
        events = []
        # Participated: accounts that were NOT already cracked in prior waves
        # and are eligible (not bcrypt/argon2 for waves 1-3)
        for emp in all_db:
            if emp["algo"] in ("bcrypt", "argon2"):
                events.append({"status": "skipped", "name": emp["name"],
                                "message": f"({emp['algo']} — computationally infeasible, skipped)"})
            elif emp["id"] in cracked_ids:
                ev = next(e for e in raw_cracked if e["id"] == emp["id"])
                events.append({"status": "cracked", "name": emp["name"],
                                "message": f"→ <code>{ev['plaintext']}</code> cracked in {ev.get('crack_time',0):.1f}ms ({emp['role']})"})
            else:
                # Only show "survived this wave" for fast-hash accounts still alive at this point
                # (already cracked by prior wave → skip; already bcrypt → skipped above)
                if not emp["cracked"]:
                    events.append({"status": "survived", "name": emp["name"],
                                   "message": f"password not in {'wordlist' if wave_num<=1 else 'rule mutations' if wave_num==2 else 'brute-force range'}"})
        return events

    events = {
        "wave1": wave_events(w1_raw, db, 1),
        "wave2": wave_events(w2_raw, db, 2),
        "wave3": wave_events(w3_raw, db, 3),
    }

    cracked_count = len(cracked_all)
    result = {
        "events":           events,
        "survivors":        [emp_public(s) for s in survivors_raw],
        "cracked_employees": [emp_public(e, include_plaintext=True) for e in cracked_all.values()],
        "total_cracked":    cracked_count,
        "total_survived":   len(survivors_raw),
        "total_elapsed_ms": total_elapsed,
    }

    log_history("Breach Simulation", {
        "details": f"MegaBank XYZ — {cracked_count}/15 accounts cracked in {total_elapsed}ms",
        "status": "cracked" if cracked_count > 0 else "done",
    })
    return jsonify(result)


# ─── Credential Stuffing ──────────────────────────────────────────────────────

# Fictional services — the same employee may have registered with same password
FICTIONAL_SERVICES = [
    {"name": "LinkedIn Clone",   "icon": "fa-linkedin",         "domain": "linkedout.com",    "type": "Social"},
    {"name": "WebMail Plus",     "icon": "fa-envelope",         "domain": "webmailplus.io",   "type": "Email"},
    {"name": "CloudDrive",       "icon": "fa-cloud",            "domain": "clouddrive.net",   "type": "Storage"},
    {"name": "ShopZone",         "icon": "fa-cart-shopping",    "domain": "shopzone.shop",    "type": "E-commerce"},
    {"name": "HealthPortal",     "icon": "fa-heart-pulse",      "domain": "myhealthportal.org","type": "Healthcare"},
    {"name": "BankEasy",         "icon": "fa-building-columns", "domain": "bankeasy.com",     "type": "Finance"},
    {"name": "HRConnect",        "icon": "fa-users",            "domain": "hrconnect.biz",    "type": "HR"},
    {"name": "DevHub",           "icon": "fa-code-branch",      "domain": "devhub.io",        "type": "Development"},
]

# Simulate password reuse: some employees reused the same or similar passwords
# (realistic — studies show 65%+ reuse passwords across services)
REUSE_PROFILES = {
    1:  ["Sunshine2019", "Sunshine19", "sunshine2019", "Sunshine2019!"],  # Alice reused variants
    2:  ["123456", "123456", "123456", "123456"],                          # Bob uses same everywhere
    3:  ["carol123", "carol123!", "Carol123", "carol123"],
    4:  ["P@ssw0rd", "Password1", "P@ssw0rd!", "P@ssword"],
    5:  ["letmein1", "letmein1!", "Letmein1", "letmein1"],
    6:  ["megabank1", "frank2024", "megabank1", "frank_ng"],
    7:  ["qwerty", "qwerty!", "Qwerty123", "qwerty"],
    8:  ["s3cur1ty!", "Security1!", "s3cur1ty!", "secur!ty"],               # Security analyst — still reused
    9:  ["LegalEagle2023", "Legal2023", "LegalEagle!", "legal2024"],
    10: ["password1", "password1", "Password1!", "password1"],
    11: ["monday", "Monday1", "monday!", "monday"],
    12: ["deploy#99", "deploy99", "Deploy#99", "deploy99!"],
    13: ["sunshine", "sunshine1", "Sunshine!", "sunshine"],
    14: ["Tr0ub4dor&3", "Tr0ub4dor3", "Troublemaker!", "troubadour"],      # CTO — varied
    15: ["correct-horse-battery-staple", "correcthorse", "Battery$taple", "horse-battery"],  # CFO
}


@app.route("/api/credential-stuffing", methods=["POST"])
def api_credential_stuffing():
    """
    Simulate credential stuffing: take cracked credentials from breach
    and try them on fictional external services.
    Accepts: { cracked_employees: [{id, name, role, clearance, systems, plaintext}] }
    Returns: { services: [str], results: {emp_id: {service_name: bool}}, total_hits: int }
    """
    data             = request.get_json(force=True)
    cracked_employees = data.get("cracked_employees", [])

    service_names = [s["name"] for s in FICTIONAL_SERVICES]
    results = {}
    total_hits = 0

    for emp in cracked_employees:
        emp_id   = int(emp.get("id", 0))
        plaintext = emp.get("plaintext", "")
        reused_pws = REUSE_PROFILES.get(emp_id, [plaintext] * len(FICTIONAL_SERVICES))
        svc_map = {}
        for i, svc in enumerate(FICTIONAL_SERVICES):
            reused_pw = reused_pws[i] if i < len(reused_pws) else plaintext
            # Credential stuffing succeeds if the reused password matches (case-insensitive variant counts)
            hit = (reused_pw == plaintext) or (reused_pw.lower() == plaintext.lower())
            svc_map[svc["name"]] = hit
            if hit:
                total_hits += 1
        results[str(emp_id)] = svc_map

    log_history("Credential Stuffing", {
        "details": f"{len(cracked_employees)} credentials stuffed against {len(FICTIONAL_SERVICES)} services → {total_hits} hits",
        "status": "cracked" if total_hits > 0 else "not_found",
    })
    return jsonify({
        "services": service_names,
        "results":  results,
        "total_hits": total_hits,
    })


# ─── Time-to-Crack Calculator ─────────────────────────────────────────────────

# GPU/setup benchmarks (hashes per second) — real-world 2024/2025 data
ATTACKER_PROFILES = {
    "laptop_cpu": {
        "label":       "Laptop (CPU)",
        "description": "Single consumer laptop, single-threaded Python equivalent",
        "icon":        "fa-laptop",
        "speed": {"md5":    200_000_000,   "sha1": 100_000_000,
                  "sha256":  50_000_000,   "bcrypt_12":        10,
                  "argon2":   3},
    },
    "gaming_gpu": {
        "label":       "Gaming GPU (RTX 4080)",
        "description": "High-end consumer graphics card with hashcat/John",
        "icon":        "fa-microchip",
        "speed": {"md5": 60_000_000_000,  "sha1": 22_000_000_000,
                  "sha256": 10_000_000_000, "bcrypt_12":    200,
                  "argon2":  20},
    },
    "gpu_cluster": {
        "label":       "GPU Cluster (8× RTX 4090)",
        "description": "Dedicated cracking rig — attainable by organized crime",
        "icon":        "fa-server",
        "speed": {"md5": 500_000_000_000, "sha1": 180_000_000_000,
                  "sha256": 80_000_000_000, "bcrypt_12":  1_600,
                  "argon2": 160},
    },
    "nation_state": {
        "label":       "Nation-State / Cloud Farm",
        "description": "Massive compute resources (ASIC/thousands of GPUs)",
        "icon":        "fa-globe",
        "speed": {"md5": 10_000_000_000_000, "sha1": 3_600_000_000_000,
                  "sha256": 1_600_000_000_000, "bcrypt_12": 40_000,
                  "argon2":  4_000},
    },
}

CHARSET_SIZES = {
    "digits":    10,
    "lowercase": 26,
    "uppercase": 26,
    "alpha":     52,
    "alphanum":  62,
    "full":      95,
}


def format_time(seconds: float) -> str:
    if seconds < 0.001:    return f"{seconds*1000:.4f} ms"
    if seconds < 1:        return f"{seconds*1000:.1f} ms"
    if seconds < 60:       return f"{seconds:.1f} seconds"
    if seconds < 3600:     return f"{seconds/60:.1f} minutes"
    if seconds < 86400:    return f"{seconds/3600:.1f} hours"
    if seconds < 31536000: return f"{seconds/86400:.1f} days"
    years = seconds / 31536000
    if years < 1000:       return f"{years:.1f} years"
    if years < 1e6:        return f"{years/1000:.1f} thousand years"
    if years < 1e9:        return f"{years/1e6:.1f} million years"
    return "Effectively forever"


@app.route("/api/crack-time", methods=["POST"])
def api_crack_time():
    """Calculate theoretical time-to-crack for given password properties."""
    data         = request.get_json(force=True)
    password_len = int(data.get("length", 8))
    charset      = data.get("charset", "alphanum")
    # Accept both 'algo' (frontend key) and 'algorithm' (legacy key)
    algo         = data.get("algo", data.get("algorithm", "md5"))

    charset_size = CHARSET_SIZES.get(charset, 62)
    total_combos = charset_size ** password_len

    algo_key = "bcrypt_12" if "bcrypt" in algo else ("argon2" if "argon2" in algo else algo)

    def _feasibility(avg_sec):
        if avg_sec < 60:          return "trivial"
        if avg_sec < 3_600:       return "easy"
        if avg_sec < 86_400 * 7:  return "moderate"
        if avg_sec < 86_400 * 365: return "hard"
        return "infeasible"

    profiles = []
    for profile_id, profile in ATTACKER_PROFILES.items():
        hps = profile["speed"].get(algo_key, profile["speed"].get("md5", 1))
        avg_seconds   = max((total_combos / 2) / hps, 1e-9)
        worst_seconds = max(total_combos / hps, 1e-9)
        # Human-readable hps label
        if hps >= 1_000_000_000_000:
            hps_label = f"{hps/1e12:.1f}T"
        elif hps >= 1_000_000_000:
            hps_label = f"{hps/1e9:.1f}B"
        elif hps >= 1_000_000:
            hps_label = f"{hps/1e6:.1f}M"
        elif hps >= 1_000:
            hps_label = f"{hps/1e3:.1f}K"
        else:
            hps_label = str(int(hps))
        profiles.append({
            "id":          profile_id,
            "name":        profile["label"],
            "description": profile["description"],
            "hps_label":   hps_label,
            "avg_time":    format_time(avg_seconds),
            "worst_time":  format_time(worst_seconds),
            "avg_seconds": avg_seconds,
            "feasibility": _feasibility(avg_seconds),
        })

    log_history("Crack-Time Calculator", {
        "details": f"len={password_len}, charset={charset} ({charset_size} chars), algo={algo} → {total_combos:,.0f} combos",
        "status": "done",
    })
    return jsonify({
        "total_combinations": total_combos,
        "charset_size":       charset_size,
        "length":             password_len,
        "algo":               algo,
        "profiles":           profiles,
    })


# ─── Wordlist listing ─────────────────────────────────────────────────────────

@app.route("/api/wordlists")
def api_wordlists():
    wl_dir = BASE_DIR / "wordlists"
    files  = [f.name for f in wl_dir.glob("*.txt")] if wl_dir.exists() else []
    return jsonify({"wordlists": files})


# ─── History ──────────────────────────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    return jsonify({"history": history})


@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    history.clear()
    return jsonify({"ok": True})


@app.route("/api/history/export")
def api_history_export():
    import csv, io
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "timestamp", "operation", "details", "status"])
    writer.writeheader()
    for row in history:
        writer.writerow({k: row.get(k, "") for k in writer.fieldnames})
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=lab_history.csv"},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  Ethical Password Cracking Lab — Web Interface")
    print("  EDUCATIONAL USE ONLY")
    print("═" * 55)
    print("  Open your browser:  http://localhost:5000")
    print("═" * 55 + "\n")
    app.run(debug=True, threaded=True, port=5000)
