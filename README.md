<img width="817" height="305" alt="image" src="https://github.com/user-attachments/assets/967a86cf-62ec-41bd-b320-85f7ea3fbeb1" />

🧬 Bruno da Silva — Offensive Security Researcher | Blockchain & Cryptography | Information Security & AI

📧 bsbruno@proton.me
📱 +55 11 99740-2197

GitHub: ipsbruno | ipsbrunoreserva | ipsbruno3
Pastebin: ipsBruno | Drakins

---


# MetaMask Recovery Wallet 🦊


<img width="1720" height="860" alt="image" src="https://github.com/user-attachments/assets/2be107dd-428b-43b0-b59d-bd1a5c04c0eb" />

_A $10 wallet for you_

<img width="1673" height="452" alt="image" src="https://github.com/user-attachments/assets/eab7b389-fcea-46e5-96f5-a2168f54e1d5" />
<img width="1677" height="846" alt="image" src="https://github.com/user-attachments/assets/313c12f1-6847-4fe2-91a1-f1f957a8acea" />



This tool **decompresses/parses Chrome’s LevelDB** entries used by the MetaMask extension, identifies MetaMask’s internal `state`, and reads controller data such as:

- `KeyringController` (vault metadata + encrypted vault blob)
- `AccountsController` (internal accounts, selected account, metadata)
- `AccountTracker` (balances by chain)
- `NotificationServicesController` (notifications list)
- `PermissionLogController` (permission history / dApp origins)

If you provide the **correct MetaMask password**, it can **decrypt the vault** and perform a **non-leaking validation** by deriving public addresses (ETH/BTC/SOL) from the decrypted mnemonic and displaying **only**:
- the derived addresses (public)
- a **SHA-256** of the mnemonic (as a verification fingerprint)

✅ Useful when the Chrome profile / MetaMask DB is **partially corrupted**, as long as the relevant state is still recoverable.



---

## 🖥️ Interface (Textual TUI)
The tool runs as a **terminal UI** with tabs:

- **Summary**: vault parameters + derived public addresses (if decrypted)
- **Accounts**: internal accounts (name/type/address/derivation/snap)
- **Balances**: balances per chain & address
- **Notifications**: last notifications (tx summaries when available)
- **Permissions**: origins + permissions + last-approved timestamps

---

## 📦 Requirements
- Python **3.10+** recommended
- LevelDB directory from Chrome profile:
  - `.../Chrome/User Data/<Profile>/Local Extension Settings/<MetaMaskExtID>/`
- Packages:
  - `plyvel`
  - `pycryptodome`
  - `bip-utils`
  - `textual`

### Notes
- On Windows, many users run this via **WSL** (paths like `/mnt/c/...`).
- Chrome should be **closed** when copying/reading LevelDB to avoid locks/corruption.

---

## ⚙️ Installation
```bash
python -m venv .venv
# Linux/WSL:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install plyvel pycryptodome bip-utils textual
````

> If `plyvel` fails to install on Linux, you may need LevelDB dev libs (WSL/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y libleveldb-dev
```

---

## 🚀 Usage

### 1) Run with automatic default path (WSL-friendly)

```bash
python ui.py
```

### 2) Provide the LevelDB directory explicitly

```bash
python ui.py --db "/mnt/c/Users/USUARIO/AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
```

### 3) Use a Windows file URL

```bash
python ui.py --db "file:///C:/Users/USUARIO/AppData/Local/Google/Chrome/User%20Data/Default/Local%20Extension%20Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/"
```

### 4) Set password via env var (recommended for automation)

```bash
export MM_PASSWORD="your_password_here"
python metamask_tui.py --password-env MM_PASSWORD
```

---

## 🔐 Vault decryption details (for documentation)

MetaMask’s vault commonly stores:

* `data` (ciphertext + tag, base64)
* `iv` (nonce, base64)
* `salt` (base64)
* `keyMetadata.params.iterations` (PBKDF2 iterations)

This tool derives the key using:

* **PBKDF2-HMAC-SHA256**
* `dklen=32` (256-bit)
* `salt` + `iterations` from vault metadata

Then attempts decryption using:

* **AES-GCM**
* with tag length heuristics (16/12/32) to handle variations.

> If decryption fails: wrong password OR different vault format/version OR corrupted vault blob.

---


## 🛡️ Security & privacy posture

* Designed for **offline** use.
* Does not transmit vault/mnemonic.
* Shows only **public derived addresses** and **mnemonic hash** (SHA-256) for verification.
* Avoids printing sensitive plaintext by default.

> If you need a “forensic export” mode, implement it carefully (redactions, encryption-at-rest, client consent).

---

## ⚠️ Compliance (must read)

``` Use this tool only for wallets you **own** or where you have **explicit written authorization**. We do not support, encourage, or assist with unauthorized access. ```
> If you’re performing recovery for a client, ensure you have explicit authorization and documented proof of ownership.


---

##  Roadmap

* Better resilience for heavily corrupted LevelDB states
* Additional browser profile discovery helpers
* Optional “read-only forensic export” (with redaction)
* Assisted recovery workflows for **authorized owners** (details intentionally not published)

---

## 🏅 Recovery Services

In many cases, wallet recovery can be completed in minutes through a guided triage process—without ever requesting your seed phrase.

We deliver high-performance forensic tooling and can also build dedicated hardware + software solutions tailored to your exact environment, data sources, and recovery scenario.


📩 Contact: `bsbruno@proton.me`

Request a quote for your case.


## License

MIT
