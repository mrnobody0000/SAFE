#!/usr/bin/env python3
# ==============================================================
#  KAPTANOVI SAFE — FINAL PATCHED VERSION — NOV 17 2025
# ==============================================================

import os, json, getpass, time
from nacl import secret, utils
from nacl.exceptions import CryptoError

VAULT_FILENAME = "vault.kap"

# ---- CONSTANTS / HEADERS ----
MAGIC = b"KAPTV1\x00\x00"  # 8-byte magic header
SALT_LEN = 16

# ---- SCRYPT KDF PARAMETERS ----
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

# --------------------------------------------------------------
# Helper utilities
# --------------------------------------------------------------

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def hexb(b: bytes):
    return b.hex()

# --------------------------------------------------------------
# KDF — SCRYPT
# --------------------------------------------------------------
import hashlib

def derive_master_key(password: str, salt: bytes):
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32
    )

# --------------------------------------------------------------
# AEAD XChaCha20-Poly1305 (PyNaCl SecretBox)
# --------------------------------------------------------------

def aead_encrypt(key: bytes, plaintext: bytes) -> bytes:
    box = secret.SecretBox(key)
    return box.encrypt(plaintext)  # returns nonce+ciphertext+tag

def aead_decrypt(key: bytes, blob: bytes) -> bytes:
    box = secret.SecretBox(key)
    return box.decrypt(blob)

# --------------------------------------------------------------
# FILE IO — Robust Single-File Format
# [MAGIC][SALT][CIPHERTEXT]
# --------------------------------------------------------------

def write_vault_singlefile(filename: str, key: bytes, plaintext: bytes, salt: bytes):
    ct = aead_encrypt(key, plaintext)
    with open(filename, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(ct)
        try:
            os.fsync(f.fileno())
        except:
            pass

def read_vault_singlefile(filename: str):
    with open(filename, "rb") as f:
        header = f.read(len(MAGIC))
        if header != MAGIC:
            raise ValueError("Bad or corrupted vault header.")

        salt = f.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            raise ValueError("Vault missing salt / truncated.")

        blob = f.read()
        if not blob:
            raise ValueError("Vault missing ciphertext.")

    return salt, blob

# --------------------------------------------------------------
# CREATE VAULT
# --------------------------------------------------------------

def create_vault():
    pw = getpass.getpass("Create master password: ")
    conf = getpass.getpass("Confirm: ")
    if pw != conf:
        print("Passwords do not match.")
        return False

    salt = os.urandom(SALT_LEN)
    key = derive_master_key(pw, salt)

    meta = {
        "version": 1,
        "created_at": now_iso(),
        "kdf": "scrypt",
        "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
    }

    vault = {
        "meta": meta,
        "entries": []
    }

    plaintext = json.dumps(vault, indent=2).encode()
    write_vault_singlefile(VAULT_FILENAME, key, plaintext, salt)

    # cleanup
    pw = None
    key = None

    print(f"Vault created → {VAULT_FILENAME}")
    return True

# --------------------------------------------------------------
# LOAD VAULT (UNLOCK)
# --------------------------------------------------------------

def load_vault():
    if not os.path.exists(VAULT_FILENAME):
        print("No vault found.")
        return None, None, None

    pw = getpass.getpass("Master password: ")

    try:
        salt, blob = read_vault_singlefile(VAULT_FILENAME)
    except Exception as e:
        print("Error:", e)
        return None, None, None

    key = derive_master_key(pw, salt)

    try:
        plain = aead_decrypt(key, blob)
        data = json.loads(plain.decode())
        return data, key, salt
    except CryptoError:
        print("Wrong password")
        return None, None, None

# --------------------------------------------------------------
# SAVE VAULT
# --------------------------------------------------------------

def save_vault(vault_data: dict, key: bytes, salt: bytes):
    plaintext = json.dumps(vault_data, indent=2).encode()
    write_vault_singlefile(VAULT_FILENAME, key, plaintext, salt)

# --------------------------------------------------------------
# PASSWORD TOOLS
# --------------------------------------------------------------

import string, secrets

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def simple_strength(password: str):
    score = 0
    if len(password) >= 12: score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_=+" for c in password): score += 1
    return score

# --------------------------------------------------------------
# MAIN APP MENU
# --------------------------------------------------------------

def main_menu():
    print("\n=== KAPTANOVI SAFE ===")
    print("1 = Unlock Vault")
    print("2 = Create New Vault")
    print("3 = Quit")
    return input("> ").strip()

def entry_menu():
    print("\n=== ENTRIES ===")
    print("1 = List")
    print("2 = Add Entry")
    print("3 = Generate Password")
    print("4 = Save & Lock")
    return input("> ").strip()

# --------------------------------------------------------------
# ENTRY FUNCTIONS
# --------------------------------------------------------------

def list_entries(v):
    print("\nVault Entries:")
    for i, e in enumerate(v["entries"]):
        print(f"{i+1}. {e['name']} ({e['username']})")

def add_entry(v):
    name = input("Name: ")
    user = input("Username: ")
    pw = getpass.getpass("Password: ")

    v["entries"].append({
        "name": name,
        "username": user,
        "password": pw,
        "created": now_iso()
    })
    print("Entry added.")

# --------------------------------------------------------------
# MAIN LOOP
# --------------------------------------------------------------

def main():
    print("KAPTANOVI iSH — FINAL VERIFIED BUILD — NOV 17 2025")

    while True:
        c = main_menu()

        if c == "1":
            data, key, salt = load_vault()
            if key is None:
                continue
            print("Vault unlocked.")

            # entry loop
            while True:
                a = entry_menu()

                if a == "1":
                    list_entries(data)

                elif a == "2":
                    add_entry(data)

                elif a == "3":
                    pw = generate_password()
                    print("Generated:", pw)
                    print("Strength score:", simple_strength(pw))

                elif a == "4":
                    save_vault(data, key, salt)
                    print("Saved. Locked.")
                    break

        elif c == "2":
            if os.path.exists(VAULT_FILENAME):
                ov = input("Overwrite existing vault? yes/NO: ").lower()
                if ov != "yes":
                    continue
            create_vault()

        elif c == "3":
            print("Goodbye.")
            return

        else:
            print("Invalid.")

# --------------------------------------------------------------
if __name__ == "__main__":
    main()
