# Secure File Server

> Async, end-to-end secure file transfer with **RBAC**, **authenticated sessions**, **integrity checks**, **encryption in transit**, and **encryption at rest** — with a minimal CLI and a Tkinter GUI.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Crypto](https://img.shields.io/badge/Cryptography-AES_GCM%20%7C%20X25519%20%7C%20RSA--PSS-8A2BE2)

---

## ✨ Features

- **Protocol:** TCP + JSONL (one JSON per line), async multi-client (`asyncio`)
- **Transport security:** X25519 (ECDH) → HKDF-SHA256 → AES-256-GCM (strictly ordered nonces)
- **Server authenticity:** RSA-PSS signature over handshake params with **TOFU** public-key caching
- **User auth:** nonce challenge + RSA-PSS (per-user keypair)
- **Integrity:** sign `SHA-256(file)` on upload; verify after download
- **At-rest encryption:** per-file AES-GCM key wrapped by server **KEK**
- **RBAC:** roles `admin`, `maintainer`, `guest`
- **GUI:** Tkinter app with progress bars, status/role display, and UX guards (server still enforces RBAC)

---

## 🧭 Repository Layout

```
secure-file-server/
├─ server/main.py         # async server, DB (SQLite), storage, crypto
├─ client/main.py         # interactive CLI client
├─ gui_client.py          # Tkinter GUI client (no code changes needed)
├─ setup_run.sh           # quick start (server + CLI/GUI)
├─ test.sh                # full end-to-end tests (use this)
└─ logs/ storage/ server.db kek.bin ...
```

---

## 🔐 Security Design (at a glance)

- **Transport:** X25519 ephemerals per connection → HKDF-SHA256 → AES-GCM (ordered nonces)
- **Server authenticity:** server signs (`server_eph_pub || client_eph_pub || salt`) with RSA-PSS; client verifies via **TOFU** (caches pubkey on first run)
- **User login:** RSA-PSS signature over a fresh server nonce
- **Integrity:** sign `SHA-256(file)` during upload; verify post-download with owner’s public key
- **At rest:** each file encrypted with a random AES-GCM key; that key is wrapped with a server-side **KEK** (`kek.bin`)

---

## 🛂 RBAC Matrix

| Operation     | admin | maintainer | guest |
|---------------|:-----:|:----------:|:-----:|
| Upload        |  ✔    |     ✔      |   ✖   |
| Download all  |  ✔    |     ✔      |   ✔   |
| Delete file   |  ✔(all) | ✔(own)   |   ✖   |
| Set role      |  ✔    |     ✖      |   ✖   |
| List users    |  ✔    |     ✖      |   ✖   |

> Server is the source of truth for authorization; the GUI adds client-side guards for better UX.

---

## ⚙️ Quick Start

### Requirements
- Python **3.10+**
- `pip install cryptography` (auto-installed by scripts)

### One-liner (CLI or GUI)
```bash
chmod +x setup_run.sh
./setup_run.sh --cli        # or: ./setup_run.sh --gui
```

### Manual
Start server:
```bash
python3 server/main.py
```

Run CLI client:
```bash
python3 client/main.py --host 127.0.0.1 --port 5050
```

Common CLI commands:
```
genkeys <priv.pem> <pub.pem>
register <username> <pub.pem>
loadkey <priv.pem>
login <username>
whoami
list_files
upload <local_path> [remote_name]
download <file_id> <out_path>
delete_file <file_id>
list_users                 # admin only
set_role <username> <role> # admin only
quit
```

GUI:
```bash
python3 gui_client.py
```

**Bootstrap admin (once):**
```bash
sqlite3 server.db "UPDATE users SET role='admin' WHERE username='alice';"
```

---

## 🔌 Protocol (overview)

- Wire format: **JSONL**. After the handshake, every message is wrapped:
```json
{"type":"secmsg","ct":"<base64(AES-GCM ciphertext)>"}
```
- Main ops: `register`, `login_begin`, `login_finish`, `whoami`, `list_files`,
  `upload_begin/chunk/end`, `download_begin/chunk/end`, `delete_file`, `list_users`, `set_role`, `get_pubkey`.

---

## ✅ Tests

Run the **full end-to-end suite** (concurrency, RBAC, integrity, at-rest encryption, tamper detection, persistence, TOFU):

```bash
chmod +x test.sh
./test.sh
```

Expected: `E2E TESTS: ALL PASS ✅` (logs under `logs/`)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
