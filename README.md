# Offline Desktop Password Vault

A zero-knowledge, 100% offline desktop password manager built with Python, Tkinter/TTK, SQLite, and industry-standard cryptography (`cryptography` library).

---

## Overview

Password Vault provides secure local password management without cloud dependencies, telemetries, or remote accounts. All sensitive secrets (passwords, usernames, and notes) are encrypted on disk using AES-256 (Fernet) with keys derived via Scrypt.

### Features
- **Zero-Knowledge Architecture:** Cryptographic keys exist only in volatile RAM while the vault is unlocked and are wiped on lock or exit.
- **100% Offline:** No network requests, telemetry, or third-party cloud servers.
- **Strong Key Derivation:** Scrypt (RFC 7914 compliant) with salt generation from cryptographically secure entropy (`secrets`).
- **Rate-Limited Unlock:** Exponential backoff delays enforce protection against local brute-force guessing.
- **Password Generator:** Cryptographically secure generator with configurable length (8–64), character pools, and look-alike exclusion (`0`, `O`, `o`, `1`, `l`, `I`).
- **Strength Evaluation:** Real-time entropy calculation in bits with penalty deductions for dictionary words, repetitions, and sequential patterns.
- **Auto-Lock & Memory Safety:** Inactivity timer monitors keyboard/mouse events and minimizes exposure; clipboard auto-clears after a configurable timeout.
- **Encrypted Backups (.vbak):** Portable encrypted archives using separate backup passphrases.
- **Browser CSV Import:** Seamlessly migrate existing passwords from Google Chrome and Mozilla Firefox.
- **Database Safety:** SQLite with `PRAGMA foreign_keys=ON` and `PRAGMA secure_delete=ON`. Master password changes re-encrypt records atomically in a single transaction with automatic rollback on failure.

---

## Installation & Running

### Requirements
- Python 3.11 or higher
- Windows, macOS, or Linux

### Quick Setup

1. **Clone or navigate to the project directory:**
   ```bash
   cd C:\Users\Nikhil\Downloads\passwordVault
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python main.py
   ```

---

## How Encryption Works (In Plain Language)

1. **Master Password & Scrypt Key Derivation:**
   When you create or unlock your vault, your master password is never stored directly. Instead, it is combined with a random 16-byte salt and processed through the **Scrypt** memory-hard key derivation function ($N=32768, r=8, p=1$). This derivation takes substantial CPU and RAM, making hardware-accelerated dictionary attacks and brute-force cracking computationally impractical.

2. **Symmetric Encryption (Fernet / AES-256):**
   The derived 32-byte key is formatted for **Fernet** encryption. Fernet provides authenticated symmetric encryption using:
   - **AES-128/256 in CBC mode** for confidentiality.
   - **HMAC-SHA256** for message integrity and authenticity verification.
   - A unique 128-bit Initialization Vector (IV) generated fresh for every encrypted field, ensuring that identical passwords produce completely different ciphertext tokens.

3. **Decryption on Demand:**
   Plaintext metadata (site names, URLs, categories, and timestamps) are kept unencrypted in SQLite for instantaneous search and categorization. Sensitive values (passwords, usernames, and notes) remain encrypted blobs on disk and are only decrypted into memory when requested.

4. **Zero-Knowledge Token Verification:**
   To verify that your master password is correct without storing a hash, the vault encrypts a known fixed token (`b"VAULT_VERIFICATION_TOKEN_V1"`) at setup. On unlock, if your derived key successfully decrypts this token, access is granted.

---

## Threat Model

### Protected Against
- **Stolen Database File:** If your database (`vault.db`) or backup (`.vbak`) file is copied or leaked, an attacker cannot read any password, username, or note without the master password.
- **Offline Brute-Force Attacks:** Scrypt's high memory and CPU cost drastically slows down password recovery attempts.
- **Ciphertext Tampering:** Any bit modifications or corruptions in ciphertext are detected immediately by Fernet's HMAC authentication tag, preventing forgery.
- **Casual Screen & Shoulder Surfing:** Password fields are masked by default and require explicit actions to view or copy.
- **Clipboard Snooping:** Copied passwords are automatically expunged from the system clipboard after 15 seconds (configurable).

### Out of Scope / Known Limitations
- **Compromised Host Machine:** If an attacker has administrative access, active malware, keyloggers, or memory dumpers running on your machine while the vault is unlocked, they can capture keystrokes or inspect RAM.
- **Physical Device Seizure While Unlocked:** An attacker with physical access to an unlocked, unminimized desktop can view exposed secrets before the auto-lock timer elapses.
- **Unencrypted CSV Exports:** Exporting to plain CSV removes all cryptographic protections and is strictly guarded behind dual confirmation warnings.

---

## Running the Test Suite

The test suite uses `pytest` with fast Scrypt parameters ($N=4096$) for rapid execution and isolates all database files inside temporary directories:

```bash
pytest tests/ -v
```

To run a fast concise test run:
```bash
pytest tests/ -q --tb=short
```

---

## Standalone Executable Build (Optional PyInstaller)

To bundle Password Vault into a single standalone executable without requiring Python installed on the target machine:

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Build the single-file executable:
   ```bash
   pyinstaller --onefile --windowed --name "PasswordVault" main.py
   ```

3. The generated executable will be placed in the `dist/` directory:
   - Windows: `dist/PasswordVault.exe`
   - Linux / macOS: `dist/PasswordVault`
