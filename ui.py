from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse, unquote

import plyvel
from Crypto.Cipher import AES

from bip_utils import (
    Bip39SeedGenerator,
    Bip44, Bip84,
    Bip44Coins, Bip84Coins, Bip44Changes
)

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import Header, Footer, Static, DataTable, TabbedContent, TabPane
from textual.worker import get_current_worker


# -------------------- Defaults --------------------

METAMASK_EXTENSION_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
DEFAULT_PROFILE = "Default"

CHAIN_NAMES = {
    1: "Ethereum Mainnet",
    10: "OP Mainnet",
    56: "BSC",
    137: "Polygon",
    8453: "Base",
    42161: "Arbitrum One",
    43114: "Avalanche C-Chain",
    17000: "Holesky",
    11155111: "Sepolia",
}


# -------------------- Data models --------------------

@dataclass
class VaultParts:
    data: bytes
    iv: bytes
    salt: bytes
    iters: int


@dataclass
class DerivedAddrs:
    eth: str
    btc: str
    sol: str
    mnemonic_sha256: str


@dataclass
class LoadedState:
    db_dir: Path
    state: Dict[str, Any]
    vault_meta: Dict[str, Any]
    parts: VaultParts
    decrypted_vault: Optional[list]
    derived: Optional[DerivedAddrs]
    balances: Dict[str, Any]
    internal_accounts: Dict[str, Any]
    notifications: list
    permissions_log: Dict[str, Any]


# -------------------- Helpers: path / db --------------------

def normalize_path(p: str | Path) -> Path:
    s = str(p)
    if s.startswith("file:"):
        u = urlparse(s)
        path = unquote(u.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:/", path):
            path = path[1:]
        return Path(path)
    return Path(s)


def guess_windows_username() -> Optional[str]:
    root = Path("/mnt/c/Users")
    if not root.exists():
        return None
    best = []
    for u in root.iterdir():
        if not u.is_dir():
            continue
        if (u / "AppData/Local/Google/Chrome/User Data").exists():
            best.append(u.name)
    if not best:
        return None
    return "USUARIO" if "USUARIO" in best else best[0]


def default_metamask_leveldb_dir(
    win_username: Optional[str] = None,
    profile: str = DEFAULT_PROFILE,
    extension_id: str = METAMASK_EXTENSION_ID,
) -> Path:
    if win_username is None:
        win_username = guess_windows_username() or getpass.getuser() or "USUARIO"
    return Path(
        f"/mnt/c/Users/{win_username}/AppData/Local/Google/Chrome/User Data/{profile}/Local Extension Settings/{extension_id}"
    )


def to_jsonable_bytes(b: bytes) -> Any:
    try:
        s = b.decode("utf-8", errors="strict").strip()
        if not s:
            return ""
        try:
            return json.loads(s)
        except Exception:
            return s
    except Exception:
        return {"__hex__": b.hex()}


def iter_leveldb_entries(db_dir: Path) -> Iterable[Tuple[bytes, Any]]:
    db = plyvel.DB(str(db_dir), create_if_missing=False)
    try:
        for k, v in db.iterator(include_key=True, include_value=True):
            yield k, to_jsonable_bytes(v)
    finally:
        db.close()


def find_metamask_state(db_dir: Path) -> Dict[str, Any]:
    best = None
    for _, v in iter_leveldb_entries(db_dir):
        if isinstance(v, dict):
            keys = set(v.keys())
            if "KeyringController" in keys and "AccountsController" in keys:
                return v
            if "KeyringController" in keys:
                best = v
    if best is not None:
        return best
    raise RuntimeError("Não achei state do MetaMask no LevelDB (KeyringController/AccountsController).")


# -------------------- Crypto: vault --------------------

def parse_vault(vault_str: str) -> Tuple[dict, VaultParts]:
    v = json.loads(vault_str)
    parts = VaultParts(
        data=base64.b64decode(v["data"]),
        iv=base64.b64decode(v["iv"]),
        salt=base64.b64decode(v["salt"]),
        iters=int(v["keyMetadata"]["params"]["iterations"]),
    )
    return v, parts


def derive_key_pbkdf2_sha256(password: str, salt: bytes, iters: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=dklen)


def decrypt_vault_gcm(parts: VaultParts, password: str) -> bytes:
    key = derive_key_pbkdf2_sha256(password, parts.salt, parts.iters, 32)

    last_err = None
    for tag_len in (16, 12, 32):
        if len(parts.data) <= tag_len:
            continue
        ct, tag = parts.data[:-tag_len], parts.data[-tag_len:]
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=parts.iv)
            return cipher.decrypt_and_verify(ct, tag)
        except Exception as e:
            last_err = e

    raise RuntimeError(f"Falha ao descriptografar (senha errada ou formato diferente). Último erro: {last_err}")


# -------------------- Parse state fields --------------------

def safe_get(d: Dict[str, Any], *path: str, default=None):
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def parse_balances(state: Dict[str, Any]) -> Dict[str, Any]:
    return safe_get(state, "AccountTracker", "accountsByChainId", default={}) or {}


def parse_internal_accounts(state: Dict[str, Any]) -> Dict[str, Any]:
    return safe_get(state, "AccountsController", "internalAccounts", default={}) or {}


def parse_notifications(state: Dict[str, Any]) -> list:
    return safe_get(state, "NotificationServicesController", "metamaskNotificationsList", default=[]) or []


def parse_permissions(state: Dict[str, Any]) -> Dict[str, Any]:
    return safe_get(state, "PermissionLogController", default={}) or {}


# -------------------- Mnemonic -> public addresses (no leak) --------------------

def derive_addrs_from_decrypted_vault(vault_list: list) -> DerivedAddrs:
    hd = next(x for x in vault_list if x.get("type") == "HD Key Tree")
    mnemonic = bytes(hd["data"]["mnemonic"]).decode("utf-8")
    mnemonic_sha = hashlib.sha256(mnemonic.encode("utf-8")).hexdigest()

    seed = Bip39SeedGenerator(mnemonic).Generate()

    eth = (Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
           .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)).PublicKey().ToAddress()

    btc = (Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
           .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)).PublicKey().ToAddress()

    sol = (Bip44.FromSeed(seed, Bip44Coins.SOLANA)
           .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)).PublicKey().ToAddress()

    return DerivedAddrs(eth=eth, btc=btc, sol=sol, mnemonic_sha256=mnemonic_sha)


# -------------------- Formatting helpers --------------------

def hex_to_int(x: str) -> int:
    if not x:
        return 0
    if isinstance(x, str) and x.startswith("0x"):
        return int(x, 16)
    return int(x)


def wei_to_eth(wei: int) -> str:
    # string sem float (pra não perder precisão)
    # 1 ETH = 1e18 wei
    s = str(wei).rjust(19, "0")
    whole = s[:-18] or "0"
    frac = s[-18:].rstrip("0")
    return f"{whole}.{frac}" if frac else whole


def ts_ms_to_iso(ts_ms: float | int) -> str:
    try:
        dt = datetime.fromtimestamp(float(ts_ms) / 1000.0, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return ""


def chain_label(chain_hex: str) -> str:
    try:
        cid = int(chain_hex, 16) if isinstance(chain_hex, str) and chain_hex.startswith("0x") else int(chain_hex)
    except Exception:
        return str(chain_hex)
    name = CHAIN_NAMES.get(cid)
    return f"{cid} ({name})" if name else str(cid)


# -------------------- Load all --------------------

def load_all(db_dir: Path, password: str) -> LoadedState:
    state = find_metamask_state(db_dir)

    vault_str = safe_get(state, "KeyringController", "vault", default="")
    if not vault_str:
        raise RuntimeError("KeyringController.vault vazio ou ausente.")
    vault_meta, parts = parse_vault(vault_str)

    decrypted_vault = None
    derived = None
    try:
        pt = decrypt_vault_gcm(parts, password)
        decrypted_vault = json.loads(pt)
        derived = derive_addrs_from_decrypted_vault(decrypted_vault)
    except Exception:
        # deixa como None (o app mostra erro no summary)
        decrypted_vault = None
        derived = None

    balances = parse_balances(state)
    internal_accounts = parse_internal_accounts(state)
    notifications = parse_notifications(state)
    permissions_log = parse_permissions(state)

    return LoadedState(
        db_dir=db_dir,
        state=state,
        vault_meta=vault_meta,
        parts=parts,
        decrypted_vault=decrypted_vault,
        derived=derived,
        balances=balances,
        internal_accounts=internal_accounts,
        notifications=notifications,
        permissions_log=permissions_log,
    )


# -------------------- Textual App --------------------

class MetaMaskTUI(App):
    CSS = """
    Screen {
        background: #0b0f14;
    }
    #status {
        padding: 1 2;
        background: #111827;
        border: round #1f2937;
        height: auto;
    }
    .box {
        border: round #1f2937;
        padding: 1 2;
        background: #0f172a;
    }
    DataTable {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "reload", "Reload"),
    ]

    def __init__(self, db_dir: Path, password: str):
        super().__init__()
        self.db_dir = db_dir
        self.password = password
        self.loaded: Optional[LoadedState] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Carregando…", id="status")

        with TabbedContent():
            with TabPane("Summary"):
                yield Container(
                    Static("", id="summary", classes="box"),
                )

            with TabPane("Accounts"):
                t = DataTable(id="tbl_accounts")
                t.cursor_type = "row"
                yield t

            with TabPane("Balances"):
                t = DataTable(id="tbl_balances")
                t.cursor_type = "row"
                yield t

            with TabPane("Notifications"):
                t = DataTable(id="tbl_notifs")
                t.cursor_type = "row"
                yield t

            with TabPane("Permissions"):
                t = DataTable(id="tbl_perms")
                t.cursor_type = "row"
                yield t

        yield Footer()

    async def on_mount(self) -> None:
        await self.reload()

    async def action_reload(self) -> None:
        await self.reload()

    # --- dentro da classe MetaMaskTUI ---

    async def reload(self) -> None:
        self.query_one("#status", Static).update("🔄 Lendo LevelDB / descriptografando vault…")
        # thread=True => agora call_from_thread é válido
        self.run_worker(self._worker_load, exclusive=True, name="load", thread=True)

    def _worker_load(self) -> None:
        worker = get_current_worker()
        try:
            loaded = load_all(self.db_dir, self.password)
            if worker.is_cancelled:
                return
            self.loaded = loaded
            self.call_from_thread(self.render_all)
        except Exception as e:
            self.call_from_thread(self.render_error, str(e))


    def render_error(self, msg: str) -> None:
        self.query_one("#status", Static).update(f"❌ Erro: {msg}")
        self.query_one("#summary", Static).update(f"[b]Erro[/b]\n{msg}")

    def render_all(self) -> None:
        assert self.loaded is not None
        L = self.loaded

        # Status
        self.query_one("#status", Static).update(f"✅ OK — DB: {L.db_dir}")

        # Summary
        lines = []
        lines.append(f"[b]DB[/b]: {L.db_dir}")
        lines.append(f"[b]Vault[/b]: PBKDF2-SHA256 iters={L.parts.iters} | iv_len={len(L.parts.iv)} | salt_len={len(L.parts.salt)}")
        if L.derived:
            lines.append("")
            lines.append("[b]Derived addresses (validação)[/b]")
            lines.append(f"ETH: {L.derived.eth}")
            lines.append(f"BTC: {L.derived.btc}")
            lines.append(f"SOL: {L.derived.sol}")
            lines.append(f"mnemonic sha256: {L.derived.mnemonic_sha256}")
        else:
            lines.append("")
            lines.append("[yellow]Não foi possível derivar endereços (senha errada ou vault não decifrou).[/yellow]")

        # Selected account (se existir)
        sel = safe_get(L.internal_accounts, "selectedAccount", default=None)
        if sel:
            lines.append("")
            lines.append(f"[b]SelectedAccount[/b]: {sel}")

        self.query_one("#summary", Static).update("\n".join(lines))

        # Tables
        self.render_accounts_table()
        self.render_balances_table()
        self.render_notifs_table()
        self.render_perms_table()

    def render_accounts_table(self) -> None:
        assert self.loaded is not None
        data = self.loaded.internal_accounts or {}

        tbl = self.query_one("#tbl_accounts", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Name", "Type", "Address", "Derivation", "Snap")

        accounts = safe_get(data, "accounts", default={}) or {}
        for _id, a in accounts.items():
            addr = a.get("address", "")
            meta = a.get("metadata", {}) or {}
            name = meta.get("name", "") or ""
            atype = a.get("type", "") or ""
            opts = a.get("options", {}) or {}
            deriv = opts.get("derivationPath", "") or safe_get(opts, "entropy", "derivationPath", default="") or ""
            snap_name = safe_get(meta, "snap", "name", default="") or ""
            tbl.add_row(name, atype, addr, deriv, snap_name)

    def render_balances_table(self) -> None:
        assert self.loaded is not None
        balances = self.loaded.balances or {}

        tbl = self.query_one("#tbl_balances", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Chain", "Address", "Balance (hex)", "Balance (ETH)")

        # balances: { "0x2105": { "0xaddr": {"balance":"0x..."} } }
        for chain_id, addr_map in balances.items():
            if not isinstance(addr_map, dict):
                continue
            for addr, info in addr_map.items():
                bal_hex = (info or {}).get("balance", "0x0")
                try:
                    wei = hex_to_int(bal_hex)
                    eth = wei_to_eth(wei)
                except Exception:
                    eth = ""
                tbl.add_row(chain_label(chain_id), addr, str(bal_hex), eth)

    def render_notifs_table(self) -> None:
        assert self.loaded is not None
        notifs = self.loaded.notifications or []

        tbl = self.query_one("#tbl_notifs", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("When", "Chain", "Type", "Amount", "From", "To", "Tx")

        # pega só as mais recentes primeiro
        notifs_sorted = list(notifs)
        # alguns itens têm createdAt ISO, outros têm created_at ISO; não garantimos parse
        notifs_sorted = notifs_sorted[:200]

        for n in notifs_sorted:
            payload = n.get("payload", {}) or {}
            cid = payload.get("chain_id")
            chain = f"{cid} ({CHAIN_NAMES.get(int(cid), '')})" if isinstance(cid, int) else str(cid or "")
            typ = payload.get("type", "") or safe_get(payload, "data", "kind", default="") or ""
            data = payload.get("data", {}) or {}
            amount = safe_get(data, "amount", "eth", default="") or ""
            frm = data.get("from", "") or ""
            to = data.get("to", "") or ""
            tx = data.get("tx_hash", "") or ""
            when = n.get("createdAt") or n.get("created_at") or ""
            tbl.add_row(str(when), chain, str(typ), str(amount), str(frm), str(to), str(tx))

    def render_perms_table(self) -> None:
        assert self.loaded is not None
        ph = safe_get(self.loaded.permissions_log, "permissionHistory", default={}) or {}

        tbl = self.query_one("#tbl_perms", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Origin", "Permission", "Account", "LastApproved")

        for origin, od in ph.items():
            # exemplo: origin -> {"eth_accounts": {"accounts": {...}, "lastApproved": ...}}
            if not isinstance(od, dict):
                continue
            for perm, pd in od.items():
                accs = safe_get(pd, "accounts", default={}) or {}
                last = safe_get(pd, "lastApproved", default=None)
                last_s = ts_ms_to_iso(last) if last is not None else ""
                for acc, ts in (accs.items() if isinstance(accs, dict) else []):
                    tbl.add_row(str(origin), str(perm), str(acc), last_s)


# -------------------- CLI --------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="MetaMask LevelDB Inspector (Textualize)")
    ap.add_argument("--db", default="", help="Caminho do diretório Local Extension Settings/<ext_id> (LevelDB)")
    ap.add_argument("--username", default="", help="Username do Windows (para montar /mnt/c/Users/<username>/...)")
    ap.add_argument("--profile", default=DEFAULT_PROFILE, help="Chrome profile (Default, Profile 1, etc.)")
    ap.add_argument("--extid", default=METAMASK_EXTENSION_ID, help="Extension ID do MetaMask")
    ap.add_argument("--password-env", default="MM_PASSWORD", help="Nome da env var com a senha")
    return ap.parse_args()


def main():
    args = parse_args()

    password = os.environ.get(args.password_env, "")
    if not password:
        password = getpass.getpass("Senha do vault (não será exibida): ")

    if args.db:
        db_dir = normalize_path(args.db)
    else:
        win_user = args.username or guess_windows_username() or "USUARIO"
        db_dir = default_metamask_leveldb_dir(win_user, args.profile, args.extid)

    if not db_dir.exists():
        raise SystemExit(f"DB não existe: {db_dir}")

    MetaMaskTUI(db_dir=db_dir, password=password).run()


if __name__ == "__main__":
    main()
