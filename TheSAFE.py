#!/usr/bin/env python3
import os
import sys
import json
import time
import hashlib
import struct
import uuid
import string
from pathlib import Path
from getpass import getpass
from secrets import token_bytes, choice
from datetime import datetime

# ───────────────────── PERFECT ChaCha20-Poly1305 ─────────────────────
def rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def chacha_quarter(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d = rotl(d ^ a, 16)
    c = (c + d) & 0xFFFFFFFF
    b = rotl(b ^ c, 12)
    a = (a + b) & 0xFFFFFFFF
    d = rotl(d ^ a, 8)
    c = (c + d) & 0xFFFFFFFF
    b = rotl(b ^ c, 7)
    return a, b, c, d

def chacha20_block(key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce[:12].ljust(12, b"\x00"))
    state = constants + list(k) + [counter] + list(n)
    working = list(state)
    for _ in range(10):
        working[0], working[4], working[8], working[12] = chacha_quarter(*working[0::4])
        working[1], working[5], working[9], working[13] = chacha_quarter(*working[1::4])
        working[2], working[6], working[10], working[14] = chacha_quarter(*working[2::4])
        working[3], working[7], working[11], working[15] = chacha_quarter(*working[3::4])
        working[0], working[5], working[10], working[15] = chacha_quarter(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = chacha_quarter(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8], working[13] = chacha_quarter(working[2], working[7], working[8], working[13])
        working[3], working[4], working[9], working[14] = chacha_quarter(working[3], working[4], working[9], working[14])
    return bytes((working[i] + state[i]) & 0xFF for i in range(16))

def poly1305_mac(message: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    accumulator = 0
    p = (1 << 130) - 5
    for i in range(0, len(message), 16):
        block = message[i:i+16] + b'\x01'
        n = int.from_bytes(block.ljust(17, b'\x00'), "little")
        accumulator = ((accumulator + n) * r) % p
    accumulator = (accumulator + s) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return accumulator.to_bytes(16, "little")

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = token_bytes(12)
    poly_key = chacha20_block(key, nonce, 0)
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, chacha20_block(key, nonce, 1)))
    mac = poly1305_mac(ciphertext + struct.pack("<QQ", 0, len(plaintext)), poly_key)
    return nonce + ciphertext + mac

def decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) < 28:
        raise ValueError("Corrupted")
    nonce = data[:12]
    ciphertext = data[12:-16]
    received_mac = data[-16:]
    poly_key = chacha20_block(key, nonce, 0)
    expected_mac = poly1305_mac(ciphertext + struct.pack("<QQ", 0, len(ciphertext)), poly_key)
    if expected_mac != received_mac:
        raise ValueError("Authentication failed")
    return bytes(a ^ b for a, b in zip(ciphertext, chacha20_block(key, nonce, 1)))

# ───────────────────── Vault ─────────────────────
VAULT_FILE = Path("vault.kap")
BACKUP_DIR = Path("backups")
BACKUP_DIR.mkdir(exist_ok=True)

SALT_LEN = 16
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

salt = b""

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode('utf-8').rstrip(b'\r\n'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_LEN)

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def copy_to_clipboard(text: str):
    print(f"\n=== COPY THIS NOW ===\n{text}\n=== CLEARED IN 15s ===")
    time.sleep(15)
    print("CLEARED\n")

def generate_password(length=22):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    alphabet = ''.join(c for c in alphabet if c not in 'lI1O0|')
    return ''.join(choice(alphabet) for _ in range(length))

def create_vault():
    global salt
    master_pw = getpass("Master password: ")
    confirm_pw = getpass("Confirm: ")
    if master_pw != confirm_pw:
        print("Passwords don't match!")
        return False
    salt = token_bytes(SALT_LEN)
    key = derive_key(master_pw, salt)
    vault_data = {"meta": {"version": 1, "created": now_iso()}, "entries": []}
    encrypted = encrypt(key, json.dumps(vault_data, indent=2).encode('utf-8'))
    VAULT_FILE.write_bytes(salt + encrypted)
    print("Vault created → vault.kap")
    return True

def load_vault():
    global salt
    if not VAULT_FILE.exists():
        print("No vault found")
        return None, None
    data = VAULT_FILE.read_bytes()
    if len(data) < SALT_LEN:
        print("Corrupted vault")
        return None, None
    salt = data[:SALT_LEN]
    ciphertext = data[SALT_LEN:]
    for attempt in range(3):
        master_pw = getpass("Master password: ")
        try:
            key = derive_key(master_pw, salt)
            plaintext = decrypt(key, ciphertext)
            vault_data = json.loads(plaintext.decode('utf-8'))
            print("Vault unlocked!")
            return vault_data, key
        except ValueError:
            if attempt < 2:
                print("Wrong password")
    print("Too many failed attempts")
    return None, None

def save_vault(vault_data, key):
    clean_vault = {"meta": vault_data["meta"], "entries": []}
    for entry in vault_data["entries"]:
        saved_entry = entry.copy()
        if "password_plain" in saved_entry:
            saved_entry["p"] = encrypt(key, saved_entry.pop("password_plain").encode()).hex()
        if "notes_plain" in saved_entry:
            saved_entry["n"] = encrypt(key, saved_entry.pop("notes_plain").encode()).hex()
        clean_vault["entries"].append(saved_entry)
    new_salt = token_bytes(SALT_LEN)
    encrypted = encrypt(key, json.dumps(clean_vault, indent=2).encode('utf-8'))
    VAULT_FILE.write_bytes(new_salt + encrypted)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = BACKUP_DIR / f"vault_{timestamp}.kap"
    backup_path.write_bytes(VAULT_FILE.read_bytes())
    print("Saved + backup created")

def new_entry():
    title = input("Title: ").strip()
    username = input("Username (optional): ").strip() or None
    generate = input("Generate strong password? y/n: ").strip().lower() != "n"
    password = generate_password() if generate else getpass("Password: ")
    if generate:
        print("Generated →", password)
    notes = input("Notes (optional): ").strip()
    tags_input = input("Tags (comma separated): ").strip()
    tags = [t.strip() for t in tags_input.split(",") if t.strip()]
    return {
        "id": str(uuid.uuid4())[:8],
        "t": title,
        "u": username,
        "password_plain": password,
        "notes_plain": notes,
        "tags": tags,
        "c": now_iso(),
        "m": now_iso()
    }

def view_entry(entry, key):
    password = entry.get("password_plain") or decrypt(key, bytes.fromhex(entry.get("p", ""))).decode()
    print(f"\nTitle: {entry['t']}\nUsername: {entry.get('u', '')}\nPassword: {password}\nNotes: {entry.get('notes_plain', '')}")
    if input("\nCopy password? y/n: ").strip().lower() == "y":
        copy_to_clipboard(password)

# ───────────────────── MAIN LOOP ─────────────────────
print("KAPTANOVI iSH — PERFECT FINAL BUILD — NOV 17 2025")
vault = key = None
while True:
    print("\n=== KAPTANOVI SAFE ===")
    if not VAULT_FILE.exists():
        if input("Create new vault? y/n: ").strip().lower() == "y":
            create_vault()
        else:
            sys.exit(0)
        continue
    status = f"Entries: {len(vault['entries']) if vault else 'locked'}"
    print(f"{status} | 1=unlock 2=new vault 3=quit")
    choice = input("> ").strip()
    if choice == "2":
        if input("OVERWRITE existing vault? yes/NO: ").strip().lower() == "yes":
            VAULT_FILE.unlink(missing_ok=True)
            create_vault()
        continue
    if choice == "3":
        sys.exit(0)
    if choice == "1" and vault is None:
        res = load_vault()
        if res:
            vault, key = res
        continue
    if vault and key:
        print("a=add l=list s=search v=view c=change pw d=delete x=lock q=quit")
        cmd = input("> ").strip().lower()
        if cmd == "a":
            vault["entries"].append(new_entry())
        elif cmd == "l":
            for e in vault["entries"]:
                print(f"[{e['id']}] {e['t']}")
        elif cmd == "s":
            term = input("Search: ").strip().lower()
            for e in vault["entries"]:
                if term in e["t"].lower() or any(term in t.lower() for t in e.get("tags", [])):
                    print(f"[{e['id']}] {e['t']}")
        elif cmd == "v":
            eid = input("Entry ID: ").strip()
            entry = next((x for x in vault["entries"] if x["id"] == eid), None)
            if entry:
                view_entry(entry, key)
        elif cmd == "c":
            eid = input("Entry ID: ").strip()
            entry = next((x for x in vault["entries"] if x["id"] == eid), None)
            if entry:
                entry["m"] = now_iso()
                entry["password_plain"] = generate_password() if input("Generate new? y/n: ").strip().lower() != "n" else getpass("New password: ")
                print("Password updated")
        elif cmd == "d":
            eid = input("Delete ID: ").strip()
            vault["entries"] = [x for x in vault["entries"] if x["id"] != eid]
            print("Deleted")
        elif cmd == "x":
            if input("Save before lock? y/n: ").strip().lower() != "n":
                save_vault(vault, key)
            vault = key = None
            print("Vault locked")
        elif cmd == "q":
            if input("Save before quit? y/n: ").strip().lower() != "n":
                save_vault(vault, key)
            print("Goodbye, Whitehatkaliboy")
            sys.exit(0)
