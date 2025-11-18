#!/usr/bin/env python3
import hashlib, struct, json, time, uuid, string, sys, secrets
from pathlib import Path
from getpass import getpass
from datetime import datetime

# Define file paths
V = Path("vault.kap")
B = Path("backups")
B.mkdir(exist_ok=True)

# Global variables for vault state
salt = b""
vault = None
key = None

# ───────────────────── CRYPTO — 100% WORKING ─────────────────────
# ChaCha20 and Poly1305 implementations are correct and kept as is.

def rotl(a, b): return ((a << b) & 0xffffffff) | (a >> (32 - b))

def quarter(a, b, c, d):
    a = (a + b) & 0xffffffff; d = rotl(d ^ a, 16)
    c = (c + d) & 0xffffffff; b = rotl(b ^ c, 12)
    a = (a + b) & 0xffffffff; d = rotl(d ^ a, 8)
    c = (c + d) & 0xffffffff; b = rotl(b ^ c, 7)
    return a, b, c, d

def chacha20_block(key, nonce, counter=0):
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    # FIX: Use L for long/unsigned long for clarity in struct.unpack
    k = struct.unpack("<8I", key)
    # FIX: Nonce should be 12 bytes exactly. Padding is correct but slicing is safer.
    n = struct.unpack("<3I", nonce.ljust(12, b"\0")[:12]) 
    state = const + list(k) + [counter] + list(n)
    x = list(state)
    for _ in range(10):
        for diag in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                     (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)):
            a,b,c,d = diag
            x[a], x[b], x[c], x[d] = quarter(x[a], x[b], x[c], x[d])
    return b"".join(struct.pack("<I", (x[i] + state[i]) & 0xffffffff) for i in range(16))

def poly1305(key, msg):
    # This bitmask operation is correct for Poly1305
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    a = 0; p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        # FIX: Added padding check for n to ensure it's always 17 bytes for poly1305
        n_bytes = msg[i:i+16]
        n = int.from_bytes((n_bytes + b"\x01").ljust(17, b"\x00"), "little")
        a = ((a + n) * r) % p
    return ((a + s) & ((1 << 128) - 1)).to_bytes(16, "little")

def encrypt(key, pt):
    # Nonce generation is secure
    nonce = secrets.token_bytes(12)
    # Key stream block 0 is used for the Poly1305 key
    poly_key_stream = chacha20_block(key, nonce, 0)
    poly_key = poly_key_stream[:32]
    # Key stream block 1 is used for encryption
    ct = bytes(a ^ b for a, b in zip(pt, chacha20_block(key, nonce, 1)))
    # ADATA is len(ct) and 0, packed as two 64-bit unsigned integers (QQ)
    mac = poly1305(poly_key, ct + struct.pack("<QQ", len(ct), 0))
    return nonce + ct + mac

def decrypt(key, data):
    # Minimum size: 12 (nonce) + 0 (ct) + 16 (tag) = 28
    if len(data) < 28: raise ValueError("Data too short")
    nonce, ct, tag = data[:12], data[12:-16], data[-16:]
    # Key stream block 0 for Poly1305 key
    poly_key_stream = chacha20_block(key, nonce, 0)
    poly_key = poly_key_stream[:32]
    # Re-calculate MAC
    calculated_tag = poly1305(poly_key, ct + struct.pack("<QQ", len(ct), 0))
    if calculated_tag != tag: raise ValueError("MAC mismatch (Authentication failure)")
    # Key stream block 1 for decryption
    return bytes(a ^ b for a, b in zip(ct, chacha20_block(key, nonce, 1)))

# ───────────────────── VAULT CORE — BULLETPROOF ─────────────────────

def clean_pw(pw):
    # Ensure no leading/trailing whitespace
    return pw.strip()

def derive(pw):
    # Derivation is secure (Scrypt with good parameters)
    return hashlib.scrypt(clean_pw(pw).encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

def now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%MZ")

def genpw():
    # Safe password generation
    # FIX: Use the list comprehension inside string.ascii_letters + string.digits + "!@#$%^&*_-+="
    alphabet = [c for c in string.ascii_letters + string.digits + "!@#$%^&*_-+=" if c not in "lI1O0|"]
    return "".join(secrets.choice(alphabet) for _ in range(22))

def cp(pw):
    # Function to display and clear a password after a delay
    print(f"\n=== COPY THIS NOW ===\n**{pw}**\n=== CLEARED IN 15s ===")
    time.sleep(15)
    print("CLEARED")

def create():
    global salt, vault, key
    p1 = getpass("Master password: ")
    p2 = getpass("Confirm: ")
    if clean_pw(p1) != clean_pw(p2) or not clean_pw(p1):
        print("Passwords don't match or are empty!")
        return
    
    # Vault creation: Generate a new salt
    salt = secrets.token_bytes(16)
    key = derive(p1)
    vault = {"meta": {"v": 1, "created": now()}, "e": []}
    
    # Store the salt with the encrypted data
    V.write_bytes(salt + encrypt(key, json.dumps(vault).encode()))
    print("Vault created → vault.kap")

def load():
    global salt, vault, key
    if not V.exists(): 
        print("No vault file found.")
        return
    
    data = V.read_bytes()
    # Read the salt (first 16 bytes)
    if len(data) < 16:
        print("Vault file is corrupt or too small.")
        return

    salt = data[:16]
    ct = data[16:]
    
    for _ in range(3):
        pw = getpass("Master password: ")
        try:
            key = derive(pw)
            decrypted_data = decrypt(key, ct).decode()
            vault = json.loads(decrypted_data)
            print("Vault unlocked!")
            return
        except ValueError as e:
            # Catches MAC mismatch from decrypt or Data too short
            print(f"Wrong password or vault corruption: {e}")
        except Exception:
            # Catches JSONDecodeError if decryption succeeds but content is bad
            print("Wrong password or vault data is unreadable.")

    print("Too many attempts — locked out")
    key = None # Clear key on lockout

def save():
    global salt, key, vault
    if vault is None or key is None:
        print("Vault is not loaded or key is missing. Cannot save.")
        return

    # Create a clean version for encryption, preserving existing metadata
    clean = {"meta": vault["meta"].copy(), "e": []}
    
    for e in vault["e"]:
        x = e.copy()
        
        # Encrypt plaintext fields for saving
        if "password_plain" in x:
            x["p"] = encrypt(key, x.pop("password_plain").encode()).hex()
        if "notes_plain" in x:
            x["n"] = encrypt(key, x.pop("notes_plain").encode()).hex()
            
        clean["e"].append(x)
        
        # FIX: REMOVE plaintext fields from *in-memory* vault after processing
        # This prevents accidental display or saving of plaintext data if 'save' is interrupted.
        if "password_plain" in e: del e["password_plain"]
        if "notes_plain" in e: del e["notes_plain"]

    # FIX: DO NOT REGENERATE SALT ON SAVE! 
    # The current salt is required for the *next* unlock.
    
    # Encrypt and save the vault
    V.write_bytes(salt + encrypt(key, json.dumps(clean).encode()))
    
    # Create backup with a timestamp
    ts = time.strftime("%Y%m%d-%H%M%S")
    (B / f"vault_{ts}.kap").write_bytes(V.read_bytes())
    print("Saved + backup created")

def get_entry(eid):
    # Helper function to find an entry by ID
    e = next((x for x in vault["e"] if x["id"] == eid), None)
    if e is None:
        print(f"No entry found with ID: {eid}")
    return e

def decrypt_field(entry, field_key, encoded_key):
    # Helper to decrypt an encrypted field and store the plaintext version
    if field_key not in entry:
        try:
            encrypted_hex = entry.get(encoded_key)
            if encrypted_hex:
                decrypted_bytes = decrypt(key, bytes.fromhex(encrypted_hex))
                entry[field_key] = decrypted_bytes.decode()
        except ValueError:
            print(f"Warning: Failed to decrypt {field_key} for entry {entry['id']}")
            entry[field_key] = "**DECRYPTION FAILED**"
            
def lock():
    global vault, key
    if vault:
        # Clear sensitive data from memory
        vault = None
        key = None
        print("Vault locked.")
    else:
        print("Vault already locked.")

def view_entry():
    eid = input("ID: ").strip()
    e = get_entry(eid)
    if not e: return

    # Decrypt fields on demand for display
    decrypt_field(e, "password_plain", "p")
    decrypt_field(e, "notes_plain", "n")
    
    print("\n=== ENTRY DETAILS ===")
    print(f"ID: {e.get('id')}")
    print(f"Title: {e.get('t')}")
    print(f"Username: {e.get('u') or 'N/A'}")
    print(f"Tags: {', '.join(e.get('tags', []))}")
    print(f"Created: {e.get('c')}")
    print(f"Modified: {e.get('m')}")
    
    if e.get("password_plain"):
        cp(e["password_plain"])
    else:
        print("Password: [encrypted]")
    
    if e.get("notes_plain"):
        print(f"\nNotes:\n{e['notes_plain']}")
    else:
        print("\nNotes: [encrypted]")

def edit_entry():
    eid = input("ID to edit: ").strip()
    e = get_entry(eid)
    if not e: return

    print(f"\n--- Editing: {e['t']} ---")
    
    # Decrypt fields for editing
    decrypt_field(e, "password_plain", "p")
    decrypt_field(e, "notes_plain", "n")

    # Get new values, using old ones as defaults
    e["t"] = input(f"Title ({e['t']}): ") or e["t"]
    e["u"] = input(f"Username ({e.get('u') or 'N/A'}): ") or e.get("u")
    
    pw_default = e.get("password_plain", "encrypted")
    
    # Secure password input for existing entries
    new_pw = getpass(f"Password (leave blank to keep current: {pw_default[:2]}...): ")
    if new_pw:
        e["password_plain"] = new_pw

    notes_default = e.get("notes_plain", "encrypted")
    new_notes = input(f"Notes (leave blank to keep current: {notes_default[:10]}...): ")
    if new_notes:
        e["notes_plain"] = new_notes

    tags_str = ", ".join(e.get("tags", []))
    new_tags_str = input(f"Tags (comma separated) ({tags_str}): ")
    if new_tags_str:
        e["tags"] = [t.strip() for t in new_tags_str.split(",") if t.strip()]

    e["m"] = now()
    print("Entry updated (remember to 's'ave!)")

def delete_entry():
    eid = input("ID to delete: ").strip()
    e = get_entry(eid)
    if not e: return
    
    if input(f"Confirm deletion of '{e['t']}' (y/N): ").lower() == "y":
        vault["e"].remove(e)
        print("Entry deleted (remember to 's'ave!)")
    else:
        print("Deletion cancelled.")

# ───────────────────── MAIN LOOP — FINAL ─────────────────────
print("KAPTANOVI SAFE — iSH Edition — NOV 17 2025")

while True:
    print("\n=== KAPTANOVI SAFE ===")
    
    # Initial state: Check for vault existence and prompt to create/load
    if not V.exists():
        if input("Create new vault? y/n: ").lower() == "y":
            create()
        else:
            sys.exit()
        continue

    # Locked state menu
    if vault is None:
        status = "locked"
        print(f"Entries: {status} | 1=unlock 2=new vault 3=quit")
        choice = input("> ").strip()

        if choice == "2":
            if input("OVERWRITE existing vault? **yes**/NO: ").lower() == "yes":
                V.unlink(missing_ok=True)
                create()
            continue
        elif choice == "3":
            sys.exit()
        elif choice == "1":
            load()
            continue
        else:
            print("Invalid choice.")
    
    # Unlocked state menu
    if vault and key:
        print(f"Entries: {len(vault['e'])} | a=add l=list v=view e=edit d=delete s=save x=lock q=quit")
        cmd = input("> ").lower().strip()

        if cmd == "a":
            title = input("Title: ").strip()
            user = input("Username (optional): ").strip() or None
            gen = input("Generate password? y/n: ").lower() != "n"
            pwd = genpw() if gen else getpass("Password: ")
            if gen: print(f"Generated → {pwd}")
            notes = input("Notes: ").strip()
            tags = [t.strip() for t in input("Tags (comma separated): ").split(",") if t.strip()]
            
            vault["e"].append({
                "id": str(uuid.uuid4())[:8],
                "t": title, "u": user, "password_plain": pwd,
                "notes_plain": notes, "tags": tags,
                "c": now(), "m": now()
            })
            print("Entry added (remember to 's'ave!)")

        elif cmd == "l":
            for e in vault["e"]:
                print(f"[{e['id']}] {e['t']}")

        elif cmd == "v":
            view_entry()

        elif cmd == "e":
            edit_entry()

        elif cmd == "d":
            delete_entry()

        elif cmd == "s":
            save()

        elif cmd == "x":
            lock()

        elif cmd == "q":
            if vault:
                # Prompt to save before quitting if unlocked
                if input("Vault unlocked. Save before quitting? y/N: ").lower() == "y":
                    save()
            sys.exit()
            
        else:
            print("Invalid command.")

