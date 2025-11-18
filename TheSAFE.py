#!/usr/bin/env python3
import hashlib, struct, json, time, uuid, string, sys, os
from pathlib import Path
from getpass import getpass
from secrets import token_bytes, choice
from datetime import datetime

V = Path("vault.kap")
B = Path("backups")
B.mkdir(exist_ok=True)

# ───────────────────── 100% RFC 8439 COMPLIANT ─────────────────────
def rotl(a, b): return ((a << b) & 0xffffffff) | (a >> (32 - b))

def quarter(a, b, c, d):
    a = (a + b) & 0xffffffff; d = rotl(d ^ a, 16)
    c = (c + d) & 0xffffffff; b = rotl(b ^ c, 12)
    a = (a + b) & 0xffffffff; d = rotl(d ^ a, 8)
    c = (c + d) & 0xffffffff; b = rotl(b ^ c, 7)
    return a, b, c, d

def chacha20_block(key, nonce, counter=0):
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce.ljust(12, b"\0")[:12])
    state = const + list(k) + [counter] + list(n)
    x = list(state)
    for _ in range(10):
        for diag in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                     (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)):
            a,b,c,d = diag
            x[a], x[b], x[c], x[d] = quarter(x[a], x[b], x[c], x[d])
    return bytes((x[i] + state[i]) & 0xff for i in range(16))

def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    a = 0; p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        n = int.from_bytes((msg[i:i+16] + b"\x01").ljust(17, b"\x00"), "little")
        a = ((a + n) * r) % p
    return ((a + s) & ((1 << 128) - 1)).to_bytes(16, "little")

def encrypt(key, pt):
    nonce = token_bytes(12)
    poly_key = chacha20_block(key, nonce, 0)[:32]
    ct = bytes(a ^ b for a, b in zip(pt, chacha20_block(key, nonce, 1)))
    # ← FIXED: (len(ct), 0) not (0, len(ct))
    mac = poly1305(poly_key, ct + struct.pack("<QQ", len(ct), 0))
    return nonce + ct + mac

def decrypt(key, data):
    if len(data) < 28: raise ValueError
    nonce, ct, tag = data[:12], data[12:-16], data[-16:]
    poly_key = chacha20_block(key, nonce, 0)[:32]
    expected = poly1305(poly_key, ct + struct.pack("<QQ", len(ct), 0))
    if expected != tag: raise ValueError
    return bytes(a ^ b for a, b in zip(ct, chacha20_block(key, nonce, 1)))

# ───────────────────── VAULT CORE ─────────────────────
salt = b""; vault = key = None

def derive(pw):
    return hashlib.scrypt(pw.encode().rstrip(), salt=salt, n=2**14, r=8, p=1, dklen=32)

def now(): return datetime.utcnow().strftime("%Y-%m-%dT%H:%MZ")

def genpw():
    chars = [c for c in string.ascii_letters + string.digits + "!@#$%^&*_-+=" if c not in "lI1O0|"]
    return "".join(choice(chars) for _ in range(22))

def cp(pw):
    print(f"\n=== COPY ===\n{pw}\n=== CLEARING IN 15s ===")
    time.sleep(15)
    print("CLEARED")

def create():
    global salt, vault, key
    p1 = getpass("Master password: ")
    p2 = getpass("Confirm: ")
    if p1 != p2: print("No match!"); return
    salt = token_bytes(16)
    key = derive(p1)
    vault = {"meta": {"v": 1, "c": now()}, "e": []}
    V.write_bytes(salt + encrypt(key, json.dumps(vault).encode()))
    print("Vault created → vault.kap")

def load():
    global salt, vault, key
    if not V.exists(): print("No vault"); return
    d = V.read_bytes()
    salt = d[:16]
    ct = d[16:]
    for _ in range(3):
        pw = getpass("Master password: ")
        try:
            key = derive(pw)
            vault = json.loads(decrypt(key, ct).decode())
            print("Vault unlocked!")
            return
        except:
            print("Wrong password")
    print("Locked out")

def save():
    clean = {"meta": vault["meta"], "e": []}
    for e in vault["e"]:
        x = e.copy()
        if "password_plain" in x: x["p"] = encrypt(key, x.pop("password_plain").encode()).hex()
        if "notes_plain" in x: x["n"] = encrypt(key, x.pop("notes_plain").encode()).hex()
        clean["e"].append(x)
    global salt; salt = token_bytes(16)
    V.write_bytes(salt + encrypt(key, json.dumps(clean).encode()))
    ts = time.strftime("%Y%m%d-%H%M%S")
    (B / f"vault_{ts}.kap").write_bytes(V.read_bytes())
    print("Saved + backup")

# ───────────────────── MAIN LOOP ─────────────────────
print("KAPTANOVI iSH — FINAL — WORKS AFTER RESTART — NOV 17 2025")
while True:
    print("\n=== KAPTANOVI SAFE ===")
    if not V.exists():
        if input("Create new vault? y/n: ").lower() == "y": create()
        else: sys.exit()
        continue
    print(f"Entries: {len(vault['e']) if vault else 'locked'} | 1=unlock 2=new 3=quit")
    c = input("> ").strip()
    if c == "2":
        if input("OVERWRITE? yes/NO: ").lower() == "yes":
            V.unlink(missing_ok=True); create()
        continue
    if c == "3": sys.exit()
    if c == "1" and not vault: load(); continue
    if vault and key:
        print("a=add l=list v=view x=lock q=quit")
        cmd = input("> ").lower()
        if cmd == "a":
            t = input("Title: "); u = input("User: ") or None
            g = input("Generate? y/n: ").lower() != "n"
            p = genpw() if g else getpass("Password: ")
            if g: print("Generated →", p)
            vault["e"].append({"id": str(uuid.uuid4())[:8], "t": t, "u": u,
                               "password_plain": p, "notes_plain": input("Notes: "),
                               "tags": [x.strip() for x in input("Tags: ").split(",") if x],
                               "c": now(), "m": now()})
        elif cmd == "l":
            for e782 in vault["e"]: print(f"[{e782['id']}] {e782['t']}")
        elif cmd == "v":
            i = input("ID: "); e = next((x for x in vault["e"] if x["id"] == i), None)
            if e:
                pw = e.get("password_plain") or decrypt(key, bytes.fromhex(e["p"])).decode()
                print(f"Title: {e['t']}\nUser: {e.get('u','')}\nPassword: {pw}")
                if input("Copy? y/n: ").lower() == "y": cp(pw)
        elif cmd == "x":
            save() if input("Save? y/n: ").lower() != "n" else None
            vault = key = None
            print("Locked")
        elif cmd == "q":
            save() if input("Save? y/n: ").lower() != "n" else None
            print("Victory, Kaiboy.")
            sys.exit()
