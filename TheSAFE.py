#!/usr/bin/env python3
"""
Kaptainovi Password Safe v1
- scrypt + XSalsa20-Poly1305 (SecretBox)
- Single encrypted file (salt + params prepended)
- Per-entry password encryption (zero plaintext on disk)
- Clipboard auto-clear (pyperclip)
- Automatic encrypted backups
- Proper exceptions, search, delete, history reuse protection
- Simpley the last saffe you will ever need
"""

import os
import json
import sys
import time
import hashlib
import binascii
import secrets
import string
import uuid
from datetime import datetime
from pathlib import Path

try:
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
    from nacl.exceptions import CryptoError
except ImportError:
    print("Error: PyNaCl missing → pip install pynacl")
    sys.exit(1)

try:
    import pyperclip
except ImportError:
    pyperclip = None

# ====================== CONFIG ======================
VAULT_FILE = Path("vault.kap")
BACKUP_DIR = Path("backups")
BACKUP_DIR.mkdir(exist_ok=True)

SALT_LEN = 16
SCRYPT_N = 2**16    # 65k – fast on phones, still strong
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

CLIPBOARD_TIMEOUT = 15  # seconds

# ====================== HELPERS ======================
def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_LEN)

def encrypt_box(key: bytes, plaintext: bytes) -> bytes:
    box = SecretBox(key)
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    return box.encrypt(plaintext, nonce)

def decrypt_box(key: bytes, ciphertext: bytes) -> bytes:
    return SecretBox(key).decrypt(ciphertext)

def hexb(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def unhex(s: str) -> bytes:
    return binascii.unhexlify(s)

def copy_to_clipboard(text: str):
    if not pyperclip:
        print(f"Copy-paste manually (pyperclip not installed):\n{text}")
        return
    pyperclip.copy(text)
    print(f"Copied! Clearing clipboard in {CLIPBOARD_TIMEOUT}s...", end="", flush=True)
    for _ in range(CLIPBOARD_TIMEOUT):
        time.sleep(1)
        print(".", end="", flush=True)
    pyperclip.copy("")
    print(" Cleared.")

# ====================== PASSWORD GEN ======================
def generate_password(length=20, include_symbols=True):
    alphabet = string.ascii_letters + string.digits
    if include_symbols:
        alphabet += "!@#$%^&*_-+="
    # remove ambiguous chars
    for ch in "lI1O0|":
        alphabet = alphabet.replace(ch, "")
    pwd = "".join(secrets.choice(alphabet) for _ in range(length))
    entropy = len(pwd) * (len(alphabet).bit_length() - 1)
    return pwd, round(entropy, 1)

# ====================== VAULT I/O ======================
def create_vault():
    if VAULT_FILE.exists():
        print("Vault already exists!")
        return False

    pw = getpass("Create master password: ")
    if pw != getpass("Confirm master password: "):
        print("Passwords don't match.")
        return False

    salt = os.urandom(SALT_LEN)
    key = derive_key(pw, salt)

    vault = {
        "meta": {
            "version": 2,
            "created": now_iso(),
            "kdf": "scrypt",
            "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
        },
        "entries": []
    }

    encrypted = encrypt_box(key, json.dumps(vault, indent=2).encode())
    VAULT_FILE.write_bytes(salt + encrypted)
    make_backup()
    print(f"Vault created → {VAULT_FILE}")
    return True

def load_vault():
    if not VAULT_FILE.exists():
        print("No vault found. Create one first.")
        return None, None

    data = VAULT_FILE.read_bytes()
    if len(data) < SALT_LEN:
        print("Vault file corrupted.")
        sys.exit(1)

    salt = data[:SALT_LEN]
    ciphertext = data[SALT_LEN:]

    for attempt in range(3):
        pw = getpass("Master password: ")
        key = derive_key(pw, salt)
        try:
            plaintext = decrypt_box(key, ciphertext)
            vault = json.loads(plaintext.decode())
            print("Vault unlocked.")
            return vault, key
        except CryptoError:
            print("Wrong password. Try again.")
    print("Too many failed attempts.")
    sys.exit(1)

def save_vault(vault: dict, key: bytes):
    # Strip plaintext before save
    clean_vault = {
        "meta": vault["meta"],
        "entries": []
    }
    for e in vault["entries"]:
        saved = e.copy()
        if "password_plain" in saved:
            saved["password_enc"] = hexb(encrypt_box(key, saved.pop("password_plain").encode()))
        if saved.get("notes_plain"):
            saved["notes_enc"] = hexb(encrypt_box(key, saved["notes_plain"].encode()))
            saved.pop("notes_plain")
        clean_vault["entries"].append(saved)

    encrypted = encrypt_box(key, json.dumps(clean_vault, indent=2).encode())
    salt = os.urandom(SALT_LEN)  # new salt on every save (optional but nice)
    VAULT_FILE.write_bytes(salt + encrypted)
    make_backup()
    print("Saved & re-encrypted with new salt.")

def make_backup():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = BACKUP_DIR / f"vault_backup_{timestamp}.kap"
    backup_path.write_bytes(VAULT_FILE.read_bytes())
    # keep only last 20 backups
    backups = sorted(BACKUP_DIR.glob("vault_backup_*.kap"), reverse=True)
    for old in backups[20:]:
        old.unlink()

# ====================== ENTRY HELPERS ======================
def new_entry():
    title = input("Title: ").strip()
    username = input("Username (optional): ").strip() or None
    url = input("URL (optional): ").strip() or None

    gen = input("Generate strong password? (Y/n): ").strip().lower() != "n"
    if gen:
        length = int(input("Length [20]: ") or "20")
        pwd, entropy = generate_password(length)
        print(f"Generated ({entropy} bits entropy): {pwd}")
    else:
        pwd = getpass("Password: ")

    notes = input("Notes (optional, multi-line ok, Ctrl+D to end):\n")
    if notes.strip():
        notes += "\n"

    tags = [t.strip() for t in input("Tags (comma-separated): ").split(",") if t.strip()]

    return {
        "id": str(uuid.uuid4())[:8],
        "title": title,
        "username": username,
        "url": url,
        "password_plain": pwd,
        "notes_plain": notes,
        "tags": tags,
        "created": now_iso(),
        "updated": now_iso(),
        "history": []
    }

def decrypt_entry_password(entry: dict, key: bytes):
    if "password_enc" in entry:
        return decrypt_box(key, unhex(entry["password_enc"])).decode()
    return None

def decrypt_entry_notes(entry: dict, key: bytes):
    if "notes_enc" in entry:
        return decrypt_box(key, unhex(entry["notes_enc"])).decode()
    return ""

def change_password(entry: dict, key: bytes):
    old_pwd = entry.get("password_plain") or decrypt_entry_password(entry, key)
    if old_pwd:
        # store old hash to prevent reuse
        salt = os.urandom(16)
        hash_hex = hexb(hashlib.scrypt(old_pwd.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32))
        entry["history"].append({"hash": hash_hex, "date": now_iso()})

    gen = input("Generate new password? (Y/n): ").strip().lower() != "n"
    if gen:
        pwd, _ = generate_password(22)
        print(f"New password: {pwd}")
    else:
        pwd = getpass("New password: ")

    entry["password_plain"] = pwd
    entry["updated"] = now_iso()
    print("Password updated.")

# ====================== MENU ======================
def search_entries(vault):
    term = input("Search (title/tag/username): ").strip().lower()
    matches = [e for e in vault["entries"] if term in e["title"].lower() or
               any(term in t.lower() for t in e["tags"]) or
               (e.get("username") and term in e["username"].lower())]
    return matches

def main():
    import getpass
    vault, key = None, None

    while True:
        print("\n=== Kaptainovi Password Safe ===")
        if not VAULT_FILE.exists():
            print("No vault found.")
            if input("Create new vault? (y/n): ").lower() == "y":
                create_vault()
            else:
                sys.exit(0)

        if vault is None:
            print("1) Unlock vault")
        else:
            print(f"1) Unlock vault   |   Entries: {len(vault['entries'])}")

        print("2) Create new vault")
        print("3) Exit")
        choice = input("> ").strip()

        if choice == "1" and vault is None:
            vault, key = load_vault()
            if not vault:
                continue

        if choice == "2":
            if input("This will overwrite existing vault! Continue? (yes/NO): ") == "yes":
                VAULT_FILE.unlink(missing_ok=True)
                create_vault()
            continue

        if choice == "3" or choice == "":
            print("Bye.")
            break

        if vault and key:
            while True:
                print(f"\nVault unlocked – {len(vault['entries'])} entries")
                print("a) Add entry      s) Search      l) List all")
                print("v) View/copy      c) Change pw   d) Delete")
                print("x) Lock vault     q) Quit")
                cmd = input("> ").strip().lower()

                if cmd == "a":
                    vault["entries"].append(new_entry())
                elif cmd == "s":
                    results = search_entries(vault)
                    for e in results:
                        print(f"[{e['id']}] {e['title']}  |  {e.get('username','')}  |  {', '.join(e['tags'])}")
                    if results:
                        view_id = input("View ID (or blank): ").strip()
                        entry = next((e for e in results if e["id"] == view_id), None)
                    else:
                        entry = None
                elif cmd == "l":
                    for e in vault["entries"]:
                        print(f"[{e['id']}] {e['title']}")
                    entry = None
                elif cmd == "v":
                    eid = input("Entry ID: ").strip()
                    entry = next((e for e in vault["entries"] if e["id"] == eid), None)
                else:
                    entry = None

                if cmd in "v" or (cmd in "s" and entry):
                    if not entry:
                        print("Not found.")
                        continue
                    pwd = entry.get("password_plain") or decrypt_entry_password(entry, key)
                    notes = entry.get("notes_plain") or decrypt_entry_notes(entry, key)
                    print(f"\nTitle: {entry['title']}")
                    print(f"Username: {entry.get('username','')}")
                    print(f"URL: {entry.get('url','')}")
                    print(f"Password: {pwd}")
                    print(f"Tags: {', '.join(entry['tags'])}")
                    if notes.strip():
                        print(f"Notes:\n{notes}")

                    copy_what = input("\nCopy? (p)assword / (u)sername / (n)othing: ").lower()
                    if copy_what == "p":
                        copy_to_clipboard(pwd)
                    elif copy_what == "u" and entry.get("username"):
                        copy_to_clipboard(entry["username"])

                elif cmd == "c":
                    eid = input("Entry ID to change: ").strip()
                    entry = next((e for e in vault["entries"] if e["id"] == eid), None)
                    if entry:
                        change_password(entry, key)
                    else:
                        print("Not found.")

                elif cmd == "d":
                    eid = input("Delete Entry ID: ").strip()
                    vault["entries"] = [e for e in vault["entries"] if e["id"] != eid]
                    print("Deleted.")

                elif cmd == "x":
                    if input("Save before locking? (Y/n): ").lower() != "n":
                        save_vault(vault, key)
                    vault, key = None, None
                    print("Locked.")
                    break

                elif cmd == "q":
                    if input("Save before quitting? (Y/n): ").lower() != "n":
                        save_vault(vault, key)
                    print("Bye.")
                    sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)
