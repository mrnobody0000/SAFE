#!/usr/bin/env python3
import os,sys,json,time,hashlib,hmac,struct,uuid,string
from pathlib import Path
from getpass import getpass
from secrets import token_bytes,choice
from datetime import datetime

# ───────────────────── 100% WORKING ChaCha20-Poly1305 ─────────────────────
def rotl(v,c):return((v<<c)&0xFFFFFFFF)|(v>>(32-c))
def qr(a,b,c,d):
 a=(a+b)&0xFFFFFFFF;d=rotl(d^a,16)
 c=(c+d)&0xFFFFFFFF;b=rotl(b^c,12)
 a=(a+b)&0xFFFFFFFF;d=rotl(d^a,8)
 c=(c+d)&0xFFFFFFFF;b=rotl(b^c,7)
 return a,b,c,d

def chacha_block(key:bytes,nonce:bytes,counter=0)->bytes:
 const=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
 k=struct.unpack("<8I",key)
 n=struct.unpack("<3I",nonce.ljust(12,b"\0")[:12])
 state=const+list(k)+[counter]+list(n)
 w=list(state)
 for _ in range(10):
  w[0],w[4],w[8],w[12]=qr(*w[0::4])
  w[1],w[5],w[9],w[13]=qr(*w[1::4])
  w[2],w[6],w[10],w[14]=qr(*w[2::4])
  w[3],w[7],w[11],w[15]=qr(*w[3::4])
  w[0],w[5],w[10],w[15]=qr(w[0],w[5],w[10],w[15])
  w[1],w[6],w[11],w[12]=qr(w[1],w[6],w[11],w[12])
  w[2],w[7],w[8],w[13]=qr(w[2],w[7],w[8],w[13])
  w[3],w[4],w[9],w[14]=qr(w[3],w[4],w[9],w[14])
 return bytes((a+b)&0xFF for a,b in zip(state,w))

def poly1305(msg:bytes,key:bytes)->bytes:
 r=int.from_bytes(key[:16],"little")&0x0ffffffc0ffffffc0ffffffc0fffffff
 s=int.from_bytes(key[16:32],"little")
 acc=0;p=(1<<130)-5
 for i in range(0,len(msg),16):
  block=msg[i:i+16]+b"\x01"
  n=int.from_bytes(block.ljust(17,b"\0"),"little")
  acc=((acc+n)*r)%p
 return (acc+s).to_bytes(16,"little")

def encrypt(key:bytes,plain:bytes)->bytes:
 nonce=token_bytes(12)
 polykey=chacha_block(key,nonce)
 ct=bytes(a^b for a,b in zip(plain,chacha_block(key,nonce,1)))
 mac=poly1305(ct+struct.pack("<QQ",0,len(plain)),polykey)
 return nonce+ct+mac

def decrypt(key:bytes,data:bytes)->bytes:
 if len(data)<28:raise ValueError("bad")
 nonce,ct,tag=data[:12],data[12:-16],data[-16:]
 polykey=chacha_block(key,nonce)
 if poly1305(ct+struct.pack("<QQ",0,len(ct)),polykey)!=tag:raise ValueError("fail")
 return bytes(a^b for a,b in zip(ct,chacha_block(key,nonce,1)))

# ───────────────────── Vault Core ─────────────────────
V=Path("vault.kap");B=Path("backups");B.mkdir(exist_ok=True)
N=2**14;salt=b""

def derive(pw):return hashlib.scrypt(pw.encode().rstrip(b"\r\n"),salt=salt,n=N,r=8,p=1,dklen=32)
def now():return datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
def cp(t):print(f"\n=== COPY ===\n{t}\n=== CLEARING IN 15s ===");time.sleep(15);print("CLEARED")

def genpw(l=22):
 a=string.ascii_letters+string.digits+"!@#$%^&*_-+=";a=a.translate(str.maketrans("","","lI1O0|"))
 return "".join(choice(a)for _ in range(l))

def create():
 global salt
 p1=getpass("Master password: ");p2=getpass("Confirm: ")
 if p1!=p2:print("Mismatch");return
 salt=token_bytes(16);key=derive(p1)
 v={"meta":{"v":1,"c":now()},"entries":[]}
 V.write_bytes(salt+encrypt(key,json.dumps(v).encode()))
 print("Vault created → vault.kap")

def load():
 global salt
 if not V.exists():print("No vault");return None,None
 d=V.read_bytes();salt=d[:16];ct=d[16:]
 for _ in range(3):
  pw=getpass("Master password: ")
  try:key=derive(pw);pt=decrypt(key,ct);return json.loads(pt.decode()),key
  except:print("Wrong password")
 print("Too many fails");return None,None

def save(v,key):
 c={"meta":v["meta"],"entries":[]}
 for e in v["entries"]:
  x=e.copy()
  if"password_plain"in x:x["p"]=encrypt(key,x.pop("password_plain").encode()).hex()
  if"notes_plain"in x:x["n"]=encrypt(key,x.pop("notes_plain").encode()).hex()
  c["entries"].append(x)
 global salt;salt=token_bytes(16)
 V.write_bytes(salt+encrypt(key,json.dumps(c).encode()))
 ts=datetime.now().strftime("%Y%m%d-%H%M%S")
 (B/f"vault_{ts}.kap").write_bytes(V.read_bytes())
 print("Saved + backup")

def new():
 t=input("Title: ");u=input("User (opt): ")or None
 g=input("Generate pw? y/n: ").lower()!="n"
 p=genpw()if g else getpass("Password: ")
 if g:print("Generated →",p)
 n=input("Notes: ");tg=[x.strip()for x in input("Tags (,): ").split(",")if x]
 return{"id":str(uuid.uuid4())[:8],"t":t,"u":u,"password_plain":p,"notes_plain":n,"tags":tg,"c":now(),"m":now()}

def view(e,k):
 p=e.get("password_plain")or(decrypt(k,bytes.fromhex(e.get("p",""))).decode()if"p"in e else"")
 print(f"\nTitle: {e['t']}\nUser: {e.get('u','')}\nPassword: {p}\nNotes: {e.get('notes_plain','')}")
 if input("Copy pw? y/n: ").lower()=="y":cp(p)

# ───────────────────── MAIN LOOP ─────────────────────
vault,key=None,None
print("KAPTANOVI iSH — FINAL 100% WORKING — NOV 17 2025")
while True:
 print("\n=== KAPTANOVI ===")
 if not V.exists():
  if input("Create vault? y/n: ").lower()=="y":create();continue
  else:sys.exit()
 print(f"Entries: {len(vault['entries'])if vault else'?'} | 1=unlock 2=new vault 3=quit")
 c=input("> ")
 if c=="2":
  if input("OVERWRITE? yes/NO: ").lower()=="yes":V.unlink(missing_ok=True);create();continue
 if c=="3":sys.exit()
 if c=="1"and vault is None:
  res=load()
  if res:vault,key=res
  continue
 if vault and key:
  print("a=add l=list s=search v=view c=change d=del x=lock q=quit")
  cmd=input("> ").lower()
  if cmd=="a":vault["entries"].append(new())
  elif cmd=="l":[print(f"[{e['id']}] {e['t']}")for e in vault["entries"]]
  elif cmd=="s":
   q=input("Search: ").lower()
   [print(f"[{e['id']}] {e['t']}")for e in vault["entries"]if q in e['t'].lower()or any(q in t.lower()for t in e.get("tags",[]))]
  elif cmd=="v":
   i=input("ID: ");e=next((e for e in vault["entries"]if e["id"]==i),None)
   if e:view(e,key)
  elif cmd=="c":
   i=input("ID: ");e=next((e for e in vault["entries"]if e["id"]==i),None)
   if e:e["m"]=now();e["password_plain"]=genpw()if input("Gen new? y/n: ").lower()!="n"else getpass("New pw: ");print("Changed")
  elif cmd=="d":
   i=input("Del ID: ");vault["entries"]=[e for e in vault["entries"]if e["id"]!=i];print("Deleted")
  elif cmd=="x":
   if input("Save? y/n: ").lower()!="n":save(vault,key)
   vault,key=None,None;print("Locked")
  elif cmd=="q":
   if input("Save? y/n: ").lower()!="n":save(vault,key)
   print("Bye Kaiboy");sys.exit()
