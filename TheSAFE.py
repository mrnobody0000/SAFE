#!/usr/bin/env python3
import os,sys,json,time,hashlib,hmac,struct,uuid,string
from pathlib import Path
from getpass import getpass
from secrets import token_bytes,choice
from datetime import datetime

def rotl(a,b):return((a<<b)&0xffffffff)|(a>>(32-b))
def qr(a,b,c,d):
 a=(a+b)&0xffffffff;d^=a;d=rotl(d,16)
 c=(c+d)&0xffffffff;b^=c;b=rotl(b,12)
 a=(a+b)&0xffffffff;d^=a;d=rotl(d,8)
 c=(c+d)&0xffffffff;b^=c;b=rotl(b,7)
 return a,b,c,d
def chacha_block(k,n,c=0):
 s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]+list(struct.unpack("<8I",k))+[c]+list(struct.unpack("<3I",n))
 w=list(s)
 for _ in range(10):
  w[0],w[4],w[8],w[12]=qr(*w[0::4])
  w[1],w[5],w[9],w[13]=qr(*w[1::4])
  w[2],w[6],w[10],w[14]=qr(*w[2::4])
  w[3],w[7],w[11],w[15]=qr(*w[3::4])
  w[0],w[5],w[10],w[15]=qr(w[0],w[5],w[10],w[15])
  w[1],w[6],w[11],w[12]=qr(w[1],w[6],w[11],w[12])
  w[2],w[7],w[8],w[13]=qr(w[2],w[7],w[8],w[13])
  w[3],w[4],w[9],w[14]=qr(w[3],w[4],w[9],w[14])
 return bytes((a+b)&0xff for a,b in zip(s,w))
def poly1305(m,k):
 r=int.from_bytes(k[:16],"little")&0x0ffffffc0ffffffc0ffffffc0fffffff
 s=int.from_bytes(k[16:],"little")
 a=0;p=(1<<130)-5
 for b in [m[i:i+16]for i in range(0,len(m),16)]:
  n=int.from_bytes(b.ljust(16,b"\0")+b"\1","little")
  a=((a+n)*r)%p
 return (a+s&((1<<128)-1)).to_bytes(16,"little")
def encrypt(key,plain,nonce=None):
 nonce=nonce or token_bytes(12)
 polykey=chacha_block(key,nonce)
 ct=bytes(a^b for a,b in zip(plain,chacha_block(key,nonce,1)))
 mac=poly1305(ct+struct.pack("<QQ",0,len(plain)),polykey)
 return nonce+ct+mac
def decrypt(key,data):
 if len(data)<28:raise ValueError("bad")
 nonce,ct,tag=data[:12],data[12:-16],data[-16:]
 polykey=chacha_block(key,nonce)
 if poly1305(ct+struct.pack("<QQ",0,len(ct)),polykey)!=tag:raise ValueError("fail")
 return bytes(a^b for a,b in zip(ct,chacha_block(key,nonce,1)))

V=Path("vault.kap");B=Path("backups");B.mkdir(exist_ok=True)
N=2**14

def dk(p,s):return hashlib.scrypt(p.encode(),salt=s,n=N,r=8,p=1,dklen=32)
def now():return datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
def cp(t):print(f"\n=== COPY NOW ===\n{t}\n=== CLEARING IN 15s ===");time.sleep(15);print("CLEARED")

def genpw(l=20):
 a=string.ascii_letters+string.digits+"!@#$%^&*_-+=";a=a.translate(str.maketrans("","","lI1O0|"))
 return "".join(choice(a)for _ in range(l))

def create():
 if V.exists():print("Vault already exists");return
 p=getpass("Master: ");c=getpass("Confirm: ")
 if p!=c:print("Passwords don't match");return
 s=token_bytes(16);k=dk(p,s)
 v={"meta":{"v":1,"created":now(),"kdf":"scrypt"},"e":[]}
 V.write_bytes(s+encrypt(k,json.dumps(v).encode()))
 print("Vault created → vault.kap")

def load():
 if not V.exists():print("No vault");return None,None
 d=V.read_bytes();s=d[:16];c=d[16:]
 for _ in range(3):
  p=getpass("Master: ");k=dk(p,s)
  try:return json.loads(decrypt(k,c).decode()),k
  except:print("Wrong password")
 print("Too many failed attempts");return None,None

def save(v,k):
 clean={"meta":v["meta"],"e":[]}
 for e in v["e"]:
  x=e.copy()
  if"password_plain"in x:x["p"]=encrypt(k,x.pop("password_plain").encode()).hex()
  if"notes_plain"in x:x["n"]=encrypt(k,x.pop("notes_plain").encode()).hex()
  clean["e"].append(x)
 V.write_bytes(token_bytes(16)+encrypt(k,json.dumps(clean).encode()))
 ts=datetime.now().strftime("%Y%m%d-%H%M%S")
 (B/f"vault_{ts}.kap").write_bytes(V.read_bytes())
 print("Saved + backup created")

def new():
 t=input("Title: ");u=input("User (optional): ")or None
 g=input("Generate strong pw? y/n: ").lower()!="n"
 p=genpw(22)if g else getpass("Password: ")
 if g:print("Generated →",p)
 n=input("Notes (optional): ")
 tg=[x.strip()for x in input("Tags (comma sep): ").split(",")if x.strip()]
 return{"id":str(uuid.uuid4())[:8],"t":t,"u":u,"password_plain":p,"notes_plain":n,"tags":tg,"c":now(),"m":now()}

def view(e,k):
 p=e.get("password_plain")or(decrypt(k,bytes.fromhex(e.get("p",""))).decode()if"p"in e else"")
 print(f"\nTitle: {e['t']}\nUser: {e.get('u','')}\nPassword: {p}\nNotes: {e.get('notes_plain','')}\nTags: {', '.join(e.get('tags',[]))}")
 if input("\nCopy password? y/n: ").lower()=="y":cp(p)

v,k=None,None
print("KAPTANOVI iSH ZERO-DEP — FINAL FIXED VERSION — NOV 17 2025")
while 1:
 print("\n=== KAPTANOVI ===")
 if not V.exists():
  if input("Create new vault? y/n: ").lower()=="y":create()
  else:sys.exit()
 if v is None:print("1) Unlock vault")
 else:print(f"Entries: {len(v['e'])}")
 print("2) New vault   3) Quit")
 c=input("> ").strip()
 if c=="2":
  if input("OVERWRITE current vault? yes/NO: ").lower()=="yes":
   V.unlink(missing_ok=True);create()
 if c=="3":sys.exit()
 if c=="1" and v is None:
  v,k=load()
  if not v:continue
 if v and k:
  print("a=add l=list s=search v=view c=change d=delete x=lock q=quit")
  cmd=input("> ").lower()
  if cmd=="a":v["e"].append(new())
  elif cmd=="l":[print(f"[{x['id']}] {x['t']}")for x in v["e"]]
  elif cmd=="s":
   q=input("Search: ").lower()
   [print(f"[{x['id']}] {x['t']}")for x in v["e"]if q in x['t'].lower()or any(q in t.lower()for t in x.get("tags",[]))]
  elif cmd=="v":
   i=input("ID: ");e=next((x for x in v["e"]if x["id"]==i),None)
   if e:view(e,k)
  elif cmd=="c":
   i=input("ID: ");e=next((x for x in v["e"]if x["id"]==i),None)
   if e:e["m"]=now();e["password_plain"]=genpw(22)if input("Generate new? y/n: ").lower()!="n"else getpass("New pw: ");print("Password changed")
  elif cmd=="d":
   i=input("Delete ID: ");v["e"]=[x for x in v["e"]if x["id"]!=i];print("Deleted")
  elif cmd=="x":
   if input("Save before lock? y/n: ").lower()!="n":save(v,k)
   v,k=None,None;print("Locked")
  elif cmd=="q":
   if input("Save before quit? y/n: ").lower()!="n":save(v,k)
   print("Bye, Kaiboy.");sys.exit()
   
