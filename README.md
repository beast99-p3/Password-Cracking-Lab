# Ethical Password Cracking Lab

> **DISCLAIMER — EDUCATIONAL USE ONLY**
> This lab is designed strictly for cybersecurity education and ethical research.
> You must only run these tools against hashes and systems you **own** or have **explicit written permission** to test.
> Unauthorized use is illegal under laws such as the CFAA (US) and equivalent statutes worldwide.

---

## Overview

This lab teaches you how weak passwords can be compromised so you can build better defenses.
It covers:

| Module | What you learn |
|---|---|
| **Setup** | How password hashes are generated and stored |
| **Dictionary Attack** | Cracking hashes using a wordlist |
| **Brute Force Attack** | Exhaustive character-space search |
| **Hash Identifier** | Detecting hash algorithm from format |
| **Defense** | Password strength analysis & secure hashing |

---

## Prerequisites

- Python 3.8+
- Install dependencies:

```bash
pip install -r requirements.txt
```

### Quickstart (Windows + virtualenv)

```bash
# 1) Create and activate a virtual environment
python -m venv .venv

# PowerShell
.venv\\Scripts\\Activate

# Git Bash / WSL
source .venv/Scripts/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run the web lab
python app.py
```

If your editor shows unresolved imports for `flask` or `flask_cors`, make sure it
is using the same `.venv` environment where you installed the requirements.

---

## Web Interface (Recommended)

Start the interactive browser-based UI:

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

### Features in the Web UI

| Tab | Description |
|---|---|
| **Setup & Hash Gen** | Generate unsalted hash targets from weak passwords |
| **Hash Identifier** | Detect algorithm from hash format/length |
| **Dictionary Attack** | Crack hashes using a wordlist |
| **Rule-Based Attack** | Mutate wordlist entries (leet, append digits, capitalize…) |
| **Brute Force** | Live progress bar attack with real-time stats |
| **Strength Checker** | Entropy analysis + policy scoring with visual gauge |
| **Secure Hashing** | Side-by-side MD5 vs bcrypt vs Argon2id with speed chart |
| **Password Generator** | CSPRNG-based password & passphrase generator |
| **History** | Session log with CSV export |

---

## CLI Walkthrough

### Step 1 — Generate hashes to crack
```bash
python setup/generate_hashes.py
```
This produces `setup/hashes.txt` — a file of unsalted MD5 / SHA1 / SHA256 hashes of weak passwords.
*This simulates a leaked database dump.*

### Step 2 — Identify hash types
```bash
python attacks/hash_identifier.py setup/hashes.txt
```

### Step 3 — Run a dictionary attack
```bash
python attacks/dictionary_attack.py --hashfile setup/hashes.txt --wordlist wordlists/common_passwords.txt --algorithm md5
```

### Step 4 — Rule-based attack (NEW)
```bash
python attacks/rule_attack.py --hash <HASH> --wordlist wordlists/common_passwords.txt --algorithm md5
```

### Step 5 — Run a brute-force attack (small keyspace demo)
```bash
python attacks/brute_force.py --hash <PASTE_HASH> --algorithm md5 --max-length 4 --charset digits
```

### Step 6 — Check password strength (defense)
```bash
python defense/password_strength.py
```

### Step 7 — Generate strong passwords (NEW)
```bash
python defense/password_generator.py --length 20 --count 5
python defense/password_generator.py --passphrase --words 5
```

### Step 8 — See secure hashing in action
```bash
python defense/secure_hashing.py
```

---

## Key Lessons

1. **Unsalted MD5/SHA1 are broken** — any common password cracks in milliseconds.
2. **Dictionary attacks win** — >80 % of real-world user passwords appear in known wordlists.
3. **Brute force is expensive** — even 6-character lowercase takes millions of iterations.
4. **Defense**: use `bcrypt` / `Argon2` with per-user salts and a high work factor.

---

## Directory Structure

```
Password Cracking Lab/
├── README.md
├── requirements.txt
├── app.py                          # Flask web interface (NEW)
├── setup/
│   ├── generate_hashes.py          # Create lab hash targets
│   └── sample_passwords.txt        # Plaintext weak passwords used in setup
├── attacks/
│   ├── dictionary_attack.py        # Wordlist-based cracking
│   ├── brute_force.py              # Exhaustive search cracking
│   ├── hash_identifier.py          # Detect hash algorithm
│   └── rule_attack.py              # Rule-based mutations (NEW)
├── wordlists/
│   └── common_passwords.txt        # ~100 common weak passwords
├── defense/
│   ├── password_strength.py        # Interactive strength analyzer
│   ├── secure_hashing.py           # bcrypt / Argon2 demo
│   └── password_generator.py       # CSPRNG password generator (NEW)
├── templates/
│   └── index.html                  # Web UI single-page app (NEW)
└── static/
    ├── css/style.css               # Dark cybersecurity theme (NEW)
    └── js/app.js                   # Frontend JavaScript (NEW)
```
