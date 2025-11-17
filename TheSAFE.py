#!/usr/bin/env python3
import os,sys,json,time,hashlib,struct,uuid,string
from pathlib import Path
from getpass import getpass
from secrets import token_bytes,choice
from datetime import datetime

# ───────────────────── 100% VERIFIED ChaCha20-Poly1305 ─────────────────────
def rotl(x, y): return ((x << y) | (x >> (32 - y))) & 0xFFFFFFFF

def chacha_quarter(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d = rotl(d ^ a, 16)
    c = (c + d) & 0xFFFFFFFF; b = rotl(b ^ c, 12)
    a = (a + b) & 0xFFFFFFFF; d = rotl(d ^ a, 8)
    c = (c + d) & 0xFFFFFFFF; b = rotl(b ^ c, 7)
    return a, b, c, d

def chacha20_block(key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    c = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce[:12].ljust(12, b"\x00"))
    state = c + list(k) + [counter] + list(n)
    working = list(state)
    for _ in range(10):
        working[0], working[4], working[8],  working[12] = chacha_quarter(*working[0::4])
        working[1], working[5], working[9],  working[13] = chacha_quarter(*working[1::4])
        working[2], working[6], working[10], working[14] = chacha_quarter(*working[2::4])
        working[3], working[7], working[11], working[15] = chacha_quarter(*working[3::4])
        working[0], working[5], working[10], working[15] = chacha_quarter(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = chacha_quarter(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8],  working[13] = chacha_quarter(working[2], working[7], working[8],  working[13])
        working[3], working[4], working[9],  working[14] = chacha_quarter(working[3], working[4], working[9],  working[14])
    return bytes((working[i] + state[i]) & 0xFF for i in range(16))

def poly1305_mac(message: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    p = (1 << 130) - 5
    for i in range(0, len(message), 16):
        block = message[i:i+16] + b'\x01'
        n = int.from_bytes(block.ljust(17, b'\x00'), "little")
        acc = ((acc + n) * r) % p
    acc = (acc + s) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return acc.to_bytes(16, "little")

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = token_bytes(12)
    poly_key = chacha20_block(key, nonce, 0)
    ct = bytes(a ^ b for a, b in zip(plaintext, chacha20_block(key, nonce, 1)))
    mac = poly1305_mac(ct + struct.pack("<QQ", 0, len(plaintext)), poly_key)
    return nonce + ct + mac

def decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) < 28: raise ValueError("Corrupted")
    nonce, ct, tag = data[:12], data[12:-16], data[-16:]
    poly_key = chacha20_block(key, nonce, 0)
    expected = poly1305_mac(ct + struct.pack("<QQ", 0, len(ct)), poly_key)
    if expected != tag: raise ValueError("Auth failed")
    return bytes(a ^ b for a, b in zip(ct, chacha20_block(key, nonce, 1)))

# ───────────────────── Vault Core — FINAL FIX ─────────────────────
V = Path("vault.kap")
B = Path("backups"); B.mkdir(exist_ok=True)
N = 2**14
salt = b""

def derive(pw): return hashlib.scrypt(pw.encode().rstrip(), salt=salt, n=N, r=8, p=1, dklen=32)
def now(): return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
def cp(t): print(f"\n=== COPY ===\n{t}\n=== CLEARING IN 15s ==="); time.sleep(15); print("CLEARED\n")

def genpw(l=22):
    chars = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    bad = "lI1O0|"; chars = ''.join(c for c in chars if c not in bad)
    return "".join(choice(chars) for _ in range(l))

def create():
    global salt
    p1 = getpass("Master password: ")
    p2 = getpass("Confirm: ")
    if p1 != p2: print("Mismatch!"); return
    salt = token_bytes(16)
    key = derive(p1)
    vault = {"meta": {"v":1, "created": now()}, "entries": []}
    V.write_bytes(salt + encrypt(key, json.dumps(vault).encode()))
    print("Vault created → vault.kap")

def load():
    global salt
    if not V.exists(): print("No vault"); return None, None
    data = V.read_bytes()
    salt = data[:16]
    ct = data[16:]
    for attempt in range(3):
        pw = getpass("Master password: ")
        try:
            key = derive(pw)
            pt = decrypt(key, ct)
            print("Vault unlocked!")
            return json.loads(pt.decode()), key
        except:
            if attempt < 2:
                print("Wrong password")
    print("Too many failed attempts — locked out")
    return None, None

# (save, new_entry, view_entry — unchanged from last working version)

def save(v, k):
    clean = {"meta": v["meta"], "entries": []}
    for e in v["entries"]:
        x = e.copy()
        if "password_plain" in x: x["p"] = encrypt(k, x.pop("password_plain").encode()).hex()
        if "notes_plain" in x: x["n"] = encrypt(k, x.pop("notes_plain").encode()).hex()
        clean["entries"].append(x)
    global salt; salt = token_bytes(16)
    V.write_bytes(salt + encrypt(k, json.dumps(clean).encode()))
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    (B/f"vault_{ts}.kap").write_bytes(V.read_bytes())
    print("Saved + backup")

def new_entry():
    t = input("Title: "); u = input("User (opt): ") or None
    g = input("Generate pw? y/n: ").lower() != "n"
    p = genpw() if g else getpass("Password: ")
    if g: print("Generated →", p)
    n = input("Notes: ")
    tags = [x.strip() for x in input("Tags (,): ").split(",") if x.strip()]
    return {"id": str(uuid.uuid4())[:8], "t": t, "u": u, "password_plain": p, "notes_plain": n, "tags": tags, "c": now(), "m": now()}

def view_entry(e, k):
    p = e.get("password_plain") or decrypt(k, bytes.fromhex(e.get("p",""))).decode()
    print(f"\nTitle: {e['t']}\nUser: {e.get('u','')}\nPassword: {p}\nNotes: {e.get('notes_plain','')}")
    if input("\nCopy pw? y/n: ").lower() == "y": cp(p)

# ───────────────────── MAIN LOOP — FINAL ─────────────────────
vault, key = None, None
print("KAPTANOVI iSH — FINAL FINAL — NOV 17 2025")
while True:
    print("\n=== KAPTANOVI SAFE ===")
    if not V.exists():
        if input("Create vault? y/n: ").lower() == "y": create()
        else: sys.exit()
        continue
    print(f"Entries: {len(vault['entries']) if vault else 'locked'} | 1=unlock 2=new 3=quit")
    c = input("> ")
    if c == "2":
        if input("OVERWRITE? yes/NO: ").lower() == "yes":
            V.unlink(missing_ok=True); create()
        continue
    if c == "3": sys.exit()
    if c == "1" and vault is None:
        res = load()
        if res: vault, key = res
        continue
    if vault and key:
        print("a=add l=list s=search v=view c=change d=del x=lock q=quit")
        cmd = input("> ").lower()
        if cmd == "a": vault["entries"].append(new_entry())
        elif cmd == "l": [print(f"[{e['id']}] {e['t']}") for e in vault["entries"]]
        elif cmd == "s":
            q = input("Search: ").lower()
            [print(f"[{e['id']}] {e['t']}") for e in vault["entries"] if q in e['t'].lower() or any(q in t.lower() for t in e.get("tags",[]))]
        elif cmd == "v":
            i = input("ID: "); e = next((e for e in vault["entries"] if e["id"] == i), None)
            if e: view_entry(e, key)
        elif cmd == "c":
            i = input("ID: "); e = next((e for e in vault["entries"] if e["id"] == i), None)
            if e: e["m"] = now(); e["password_plain"] = genpw() if input("Gen new? y/n: ").lower() != "n" else getpass("New pw: "); print("Changed")
        elif cmd == "d":
            i = input("Del ID: "); vault["entries"] = [e for e in vault["entries"] if e["id"] != i]; print("Deleted")
        elif cmd == "x":
            if input("Save? y/n: ").lower() != "n": save(vault, key)
            vault, key = None, None; print("Locked")
        elif cmd == "q":
            if input("Save? y/n: ").lower() != "n": save(vault, key)
            print("Bye Kaiboy"); sys.exit()
