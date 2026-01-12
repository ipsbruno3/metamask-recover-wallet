import base64
import hashlib
from Crypto.Cipher import AES
from pathlib import Path
import json
import plyvel
from pathlib import Path
from urllib.parse import urlparse, unquote
import os
import re
import json
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip84,
    Bip44Coins, Bip84Coins, Bip44Changes
)
def ipsbruno_ascii_text():
    try:
        from pyfiglet import Figlet
        art = Figlet(font="slant").renderText("ipsbruno").rstrip("\n")
    except Exception:
        art = """
\n
\n
\n
  _           _                            
 (_)         | |                           
  _ _ __  ___| |__  _ __ _   _ _ __   ___  
 | | '_ \\/ __| '_ \\| '__| | | | '_ \\ / _ \\ 
 | | |_) \\__ \\ |_) | |  | |_| | | | | (_) |
 |_| .__/|___/_.__/|_|   \\__,_|_| |_|\\___/ 
   | |                                     
   |_|           

💀 Recovering MetaMask Files
🌐 Website: https://ipsbruno.me
📧 E-mail: bsbruno@pm.me

1. Read extension files from Chrome
2. Extract then with LevelDB
3. Decode file
""".strip("\n")
    t = Text()
    colors = ["white"] * 6
    for i, ln in enumerate(art.splitlines()):
        t.append(ln + "\n", style=colors[i % len(colors)])
    return t


password = "passphrase extension"
username = "USUARIO"
db_path_in = f"/mnt/c/Users/{username}/AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
db_dir = Path(db_path_in)




def normalize_path(p: str | Path) -> Path:
    s = str(p)
    if s.startswith("file:"):
        u = urlparse(s)
        path = unquote(u.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:/", path):
            path = path[1:] 
        return Path(path)

    return Path(s)

db_path = normalize_path(db_path_in)
db_dir = db_path if db_path.is_dir() else db_path.parent


def to_jsonable_bytes(b: bytes):
    try:
        s = b.decode("utf-8")
        try:
            return json.loads(s)
        except Exception:
            return s
    except Exception:
        return {"__hex__": b.hex()}


def decode_leveldb(db_dir):
    db = plyvel.DB(str(db_dir), create_if_missing=False)
    retn = []
    try:
        limit = 200
        for i, (k, v) in enumerate(db.iterator()):
    
            return to_jsonable_bytes(v)
    finally:
        db.close()
    return retn 



decoded_wallet_file = decode_leveldb(db_dir)
balances = decoded_wallet_file["AccountTracker"]["accountsByChainId"]
accounts =decoded_wallet_file["AccountsController"]["internalAccounts"]
vault = json.loads(decoded_wallet_file["KeyringController"]["vault"])
vault_ex = json.loads(decoded_wallet_file["KeyringController"]["vault"])
notifies = decoded_wallet_file["NotificationServicesController"]["metamaskNotificationsList"]
permissions_log = decoded_wallet_file["PermissionLogController"]


data = base64.b64decode(vault["data"])
iv   = base64.b64decode(vault["iv"])
salt = base64.b64decode(vault["salt"])


data_ex = base64.b64decode(vault["data"])
iv_ex   = base64.b64decode(vault["iv"])
salt_ex = base64.b64decode(vault["salt"])


iters = int(vault["keyMetadata"]["params"]["iterations"])
key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)
key_ex = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)
vault_ex = json.loads(decoded_wallet_file["KeyringController"]["vault"])
print(balances,accounts,vault,notifies,permissions_log)

pt=""
for tag_len in (16, 12, 32):
    if len(data) <= tag_len:
        continue
    ct, tag = data[:-tag_len], data[-tag_len:]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        pt = cipher.decrypt_and_verify(ct, tag)
        break
    except Exception as e:
        print("❌ Password inválid: ", e)


if pt:
    vault = json.loads(pt)
    hd = next(x for x in vault if x.get("type") == "HD Key Tree")
    mnemonic = bytes(hd["data"]["mnemonic"]).decode("utf-8")

    seed = Bip39SeedGenerator(mnemonic).Generate()

    eth = (Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
        .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    print("ETH addr:", eth.PublicKey().ToAddress())

    btc = (Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    print("BTC addr:", btc.PublicKey().ToAddress())

    sol = (Bip44.FromSeed(seed, Bip44Coins.SOLANA)
        .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    print("SOL addr:", sol.PublicKey().ToAddress())

    print("Mnemonic: ", mnemonic)
