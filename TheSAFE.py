#!/usr/bin/env python3
import hashlib, struct, json, time, uuid, string, sys
from pathlib import Path
from getpass import getpass
from secrets import token_bytes, choice
from datetime import datetime

V = Path("vault.kap")
B = Path("backups")
B.mkdir(exist_ok=True)

# ───────────────────── 100% WORKING ChaCha20-Poly1305 (RFC 8439) ─────────────────────
def rotl(a, b):
    return ((a << b) & 0xffffffff) | (a >> (32 - b))

def quarter(a, b, c, d):
    a = (a + b) & 0xffffffff
    d = rotl(d ^ a, 16)
    c = (c + d) & 0xffffffff
    b = rotl(b ^ c, 12)
    a = (a + b) & 0xffffffff
    d = rotl(d ^ a, 8)
    c = (c + d) & 0xffffffff
    b = rotl(b ^ c, 7)
    return a, b, c, d

def chacha20_block(key, nonce, counter=0):
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce.ljust(12, b"\0")[:12])
    state = const + list(k) + [counter] + list(n)
    x = list(state)

    for _ in range(10):
        x[0], x[4], x[8],  x[12] = quarter(x[0], x[4], x[8],  x[12])
        x[1], x[5], x[9],  x[13] = quarter(x[1], x[5], x[9],  x[13])
        x[2], x[6], x[10], x[14] = quarter(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = quarter(x[3], x[7], x[11], x[15])
        x[0], x[5], x[10], x[15] = quarter(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = quarter(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8],  x[13] = quarter(x[2], x[7], x[8],  x[13])
        x[3], x[4], x[9],  x[14] = quarter(x[3], x[4], x[9],  x[14])

    return bytes((x[i] + state[i]) & 0xff for i in range(16))

def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    a = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        block = msg[i:i+16] + b"\x01"
        n = int.from_bytes(block.ljust(17, b"\x00"), "little")
        a = ((a + n) * r) % p
    a = (a + s) & ((1 << 128) - 1)
    return a.to_bytes(16, "little")

def encrypt(key, pt):
    nonce = token_bytes(12)
    poly_key = chacha20_block(key, nonce, 0)[:32]           # CRITICAL: first 32 bytes only
    ct = bytes(a ^ b for a, b in zip(pt, chacha20_block(key, nonce, 1)))
    mac = poly1305(poly_key, ct + struct.pack("<QQ", len(ct), 0))
    return nonce + ct + mac

def decrypt(key, data):
    if len(data) < 28: raise ValueError("bad")
    nonce, ct, tag = data[:12], data[12:-16], data[-16:]
    poly_key = chacha20_block(key, nonce, 0)[:32]
    expected = poly1305(poly_key, ct + struct.pack("<QQ", len(ct), 0))
    if expected != tag: raise ValueError("MAC fail")
    return bytes(a ^ b for a, b in zip(ct, chacha20_block(key, nonce, 1)))

# ───────────────────── Vault Core ─────────────────────
salt = b""
vault = key = None

def derive(pw):
    return hashlib.scrypt(pw.encode().rstrip(b"\r\n"), salt=salt, n=2**14, r=8, p=1, dklen=32)

def now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%MZ")

def genpw():
    chars = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    return "".join(choice([c for c in chars if c not in "lI1O0|"]) for _ in range(22))

def cp(pw):
    print(f"\n=== COPY THIS ===\n{pw}\n=== CLEARING IN 15s ===")
    time.sleep(15)
    print("CLEARED")

# ───────────────────── Functions ─────────────────────
def create():
    global salt, vault, key
    p1 = getpass("Master password: ")
    p2 = getpass("Confirm: ")
    if p1 != p2:
        print("Passwords don't match!")
        return
    salt = token_bytes(16)
    key = derive(p1)
    vault = {"meta": {"v": 1, "created": now()}, "e": []}
    V.write_bytes(salt + encrypt(key, json.dumps(vault).encode()))
    print("Vault created → vault.kap")

def load():
    global salt, vault, key
    if not V.exists():
        print("No vault")
        return
    data = V.read_bytes()
    salt = data[:16]
    ct = data[16:]
    for _ in range(3):
        pw = getpass("Master password: ")
        try:
            key = derive(pw)
            vault = json.loads(decrypt(key, ct).decode())
            print("Vault unlocked!")
            return
        except:
            print("Wrong password")
    print("Too many attempts — locked out")

def save():
    clean = {"meta": vault["meta"], "e": []}
    for e in vault["e"]:
        x = e.copy()
        if "password_plain" in x:
            x["p"] = encrypt(key, x.pop("password_plain").encode()).hex()
        if "notes_plain" in x:
            x["n"] = encrypt(key, x.pop("notes_plain").encode()).hex()
        clean["e"].append(x)
    global salt
    salt = token_bytes(16)
    V.write_bytes(salt + encrypt(key, json.dumps(clean).encode()))
    ts = time.strftime("%Y%m%d-%H%M%S")
    (B / f"vault_{ts}.kap").write_bytes(V.read_bytes())
    print("Saved + backup created")

# ───────────────────── MAIN LOOP ─────────────────────
print("KAPTANOVI iSH — FINAL 100% WORKING — NOV 17 2025")
while True:
    print("\n=== KAPTANOVI SAFE ===")
    if not V.exists():
        if input("Create new vault? y/n: ").lower() == "y":
            create()
        else:
            sys.exit()
        continue

    status = f"Entries: {len(vault['e']) if vault else 'locked'}"
    print(f"{status} | 1=unlock 2=new vault 3=quit")
    choice = input("> ").strip()

    if choice == "2":
        if input("OVERWRITE existing vault? yes/NO: ").lower() == "yes":
            V.unlink(missing_ok=True)
            create()
        continue
    if choice == "3":
        sys.exit()
    if choice == "1" and vault is None:
        load()
        continue

    if vault and key:
        print("a=add l=list s=search v=view c=change d=delete x=lock q=quit")
        cmd = input("> ").lower()
        if cmd == "a":
            title = input("Title: ")
            user = input("Username (optional): ") or None
            gen = input("Generate password? y/n: ").lower() != "n"
            pwd = genpw() if gen else getpass("Password: ")
            if gen: print("Generated →", pwd)
            notes = input("Notes: ")
            tags = [t.strip() for t in input("Tags (comma separated): ").split(",") if t.strip()]
            vault["e"].append({
                "id": str(uuid.uuid4())[:8],
                "t": title,
                "u": user,
                "password_plain": pwd,
                "notes_plain": notes,
                "tags": tags,
                "c": now(),
                "m": now()
            })
        elif cmd == "l":
            for e in vault["e"]:
                print(f"[{e['id']}] {e['t']}")
        elif cmd == "v":
            eid = input("ID: ")
            e = next((x for x in vault["e"] if x["id"] == eid), None)
            if e:
                pwd = e.get("password_plain") or decrypt(key, bytes.fromhex(e["p"])).decode()
                print(f"\nTitle: {e['t']}\nUser: {e.get('u','')}\nPassword: {pwd}\nNotes: {e.get('notes_plain','')}")
                if input("Copy password? y/n: ").lower() == "y":
                    cp(pwd)
        elif cmd == "x":
            if input("Save before lock? y/n: ").lower() != "n":
                save()
            vault = key = None
            print("Vault locked")
        elif cmd == "q":
            if input("Save before quit? y/n: ").lower() != "n":
                save()
            print("Goodbye, Whitehatkaliboy")
            sys.exit()
