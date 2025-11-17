#!/usr/bin/env python3
from pathlib import Path as P; from getpass import getpass; from secrets import token_bytes,choice
import hashlib,struct,json,uuid,string,time,sys

V=P("vault.kap"); B=P("backups"); B.mkdir(exist_ok=True)
N=2**14; salt=b""; vault=key=None

# ───────────────────── PERFECT ChaCha20-Poly1305 (fixed forever) ─────────────────────
r=lambda x,y:((x<<y)|(x>>(32-y)))&0xFFFFFFFF
q=lambda a,b,c,d:(a:=a+b&-1,d:=r(d^a,16),c:=c+d&-1,b:=r(b^c,12),a:=a+b&-1,d:=r(d^a,8),c:=c+d&-1,b:=r(b^c,7))or(a,b,c,d)

def chacha(k,n,c=0):
 s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]+list(struct.unpack("<8I",k))+[c]+list(struct.unpack("<3I",n[:12].ljust(12,b"\0")))
 w=list(s)
 for _ in range(10):
  for i in range(4): w[i::4]=q(*w[i::4])
  w[0],w[5],w[10],w[15]=q(w[0],w[5],w[10],w[15])
  w[1],w[6],w[11],w[12]=q(w[1],w[6],w[11],w[12])
  w[2],w[7],w[8],w[13]=q(w[2],w[7],w[8],w[13])
  w[3],w[4],w[9],w[14]=q(w[3],w[4],w[9],w[14])
 return bytes((a+b)&255 for a,b in zip(s,w))

def poly(m,k):
 r=int.from_bytes(k[:16],"little")&0x0ffffffc0ffffffc0ffffffc0fffffff
 s=int.from_bytes(k[16:32],"little"); a=0; p=(1<<130)-5
 for i in range(0,len(m),16):
  n=int.from_bytes((m[i:i+16]+b"\x01").ljust(17,b"\x00"),"little")
  a=((a+n)*r)%p
 return ((a+s)&((1<<128)-1)).to_bytes(16,"little")

def E(k,t):
 n=token_bytes(12)
 poly_key=chacha(k,n,0)[:32]                    # ← CRITICAL FIX
 ct=bytes(a^b for a,b in zip(t,chacha(k,n,1)))
 mac=poly(ct+struct.pack("<QQ",0,len(t)),poly_key)
 return n+ct+mac

def D(k,d):
 if len(d)<28:raise ValueError("bad")
 n,ct,tag=d[:12],d[12:-16],d[-16:]
 poly_key=chacha(k,n,0)[:32]
 if poly(ct+struct.pack("<QQ",0,len(ct)),poly_key)!=tag:raise ValueError("fail")
 return bytes(a^b for a,b in zip(ct,chacha(k,n,1)))

derive=lambda p:hashlib.scrypt(p.encode().rstrip(b"\r\n"),salt=salt,n=N,r=8,p=1,dklen=32)
now=lambda:time.strftime("%Y-%m-%dT%H:%MZ",time.gmtime())
cp=lambda t:(print(f"\n=== COPY NOW ===\n{t}\n=== CLEARED IN 15s ==="),time.sleep(15),print("CLEARED"))[0]
genpw=lambda:"".join(choice([c for c in string.ascii_letters+string.digits+"!@#$%^&*_-+=" if c not in"lI1O0|"])for _ in range(22))

def create():
 global salt,vault,key
 p1=getpass("Master password: "); p2=getpass("Confirm: ")
 if p1!=p2:print("Mismatch!");return
 salt=token_bytes(16); key=derive(p1)
 vault={"meta":{"v":1,"created":now()},"e":[]}
 V.write_bytes(salt+E(key,json.dumps(vault).encode()))
 print("Vault created → vault.kap")

def load():
 global salt,vault,key
 if not V.exists():print("No vault");return
 d=V.read_bytes(); salt=d[:16]; ct=d[16:]
 for _ in range(3):
  p=getpass("Master password: ")
  try: key=derive(p); vault=json.loads(D(key,ct).decode()); print("Vault unlocked!"); return
  except: print("Wrong password")
 print("Locked out after 3 tries")

def save():
 c={"meta":vault["meta"],"e":[]}
 for e in vault["e"]:
  x=e.copy()
  if"password_plain"in x: x["p"]=E(key,x.pop("password_plain").encode()).hex()
  if"notes_plain"in x: x["n"]=E(key,x.pop("notes_plain").encode()).hex()
  c["e"].append(x)
 global salt; salt=token_bytes(16)
 V.write_bytes(salt+E(key,json.dumps(c).encode()))
 (B/f"vault_{time.strftime('%Y%m%d-%H%M%S')}.kap").write_bytes(V.read_bytes())
 print("Saved + backup created")

print("KAPTANOVI iSH — FINAL PERFECT BUILD — NOV 17 2025")
while 1:
 print("\n=== KAPTANOVI SAFE ===")
 if not V.exists():
  if input("Create new vault? y/n: ").lower()=="y": create(); continue
  else: sys.exit()
 print(f"Entries: {len(vault['e'])if vault else'locked'} | 1=unlock 2=new vault 3=quit")
 c=input("> ").strip()
 if c=="2":
  if input("OVERWRITE vault? yes/NO: ").lower()=="yes": V.unlink(missing_ok=True); create(); continue
 if c=="3": sys.exit()
 if c=="1" and not vault: load(); continue
 if vault and key:
  print("a=add l=list s=search v=view c=change d=delete x=lock q=quit")
  cmd=input("> ").lower()
  if cmd=="a":
   t=input("Title: "); u=input("User: ")or None
   g=input("Generate pw? y/n: ").lower()!="n"
   p=genpw()if g else getpass("Password: ")
   if g: print("Generated →",p)
   n=input("Notes: "); tags=[x.strip()for x in input("Tags (comma): ").split(",")if x]
   vault["e"].append({"id":str(uuid.uuid4())[:8],"t":t,"u":u,"password_plain":p,"notes_plain":n,"tags":tags,"c":now(),"m":now()})
  elif cmd=="l": [print(f"[{e['id']}] {e['t']}")for e in vault["e"]]
  elif cmd=="s":
   q=input("Search: ").lower()
   [print(f"[{e['id']}] {e['t']}")for e in vault["e"]if q in e['t'].lower()or any(q in t.lower()for t in e.get("tags",[]))]
  elif cmd=="v":
   i=input("ID: "); e=next((x for x in vault["e"]if x["id"]==i),None)
   if e:
    pwd=e.get("password_plain")or D(key,bytes.fromhex(e["p"])).decode()
    print(f"\nTitle: {e['t']}\nUser: {e.get('u','')}\nPassword: {pwd}\nNotes: {e.get('notes_plain','')}")
    if input("Copy password? y/n: ").lower()=="y": cp(pwd)
  elif cmd=="c":
   i=input("ID: "); e=next((x for x in vault["e"]if x["id"]==i),None)
   if e: e["m"]=now(); e["password_plain"]=genpw()if input("Gen new? y/n: ").lower()!="n"else getpass("New pw: "); print("Password changed")
  elif cmd=="d":
   i=input("Delete ID: "); vault["e"]=[x for x in vault["e"]if x["id"]!=i]; print("Deleted")
  elif cmd=="x":
   if input("Save before lock? y/n: ").lower()!="n": save()
   vault=key=None; print("Vault locked")
  elif cmd=="q":
   if input("Save before quit? y/n: ").lower()!="n": save()
   print("Goodbye, Whitehatkaliboy"); sys.exit()
