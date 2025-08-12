import asyncio, json, time, uuid, sqlite3, base64, os, struct, hashlib, pathlib
from typing import Optional, List, Dict, Any

# RSA for user auth & handshake signing
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
)

# X25519 + HKDF + AES-GCM for transport
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5050
MAX_LINE = 128 * 1024  # allow big JSON lines
DB_PATH = "server.db"

STORAGE_DIR = "storage"  # ciphertext files
KEK_PATH = "kek.bin"  # 32B KEK (or via env SFS_KEK_B64)
CHUNK = 44 * 1024  # ~44KB -> ~60KB base64 (fits JSON safely)

SERVER_PRIV_PATH = "server_priv.pem"
SERVER_PUB_PATH = "server_pub.pem"
SERVER_SIGN_PRIV = None  # set at startup


# ---------- utils ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def hkdf(shared: bytes, salt: bytes, info: bytes = b"file-srv-transport") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(
        shared
    )


# ---------- DB ----------
def db_init() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'guest',
        pubkey_b64 TEXT NOT NULL,          -- RSA public key PEM (base64)
        created_at REAL NOT NULL
    )"""
    )
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        filename TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at REAL NOT NULL,
        sha256_b64 TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,        -- signature over sha256(plain)
        enc_alg TEXT NOT NULL,              -- 'aes-256-gcm'
        nonce_b64 TEXT NOT NULL,            -- data nonce
        path TEXT NOT NULL,                 -- storage path
        wrapped_key_b64 TEXT NOT NULL,      -- AESGCM(KEK).encrypt(wrap_nonce, file_key)
        wrap_nonce_b64 TEXT NOT NULL        -- nonce for wrapping
    )"""
    )
    conn.commit()
    conn.close()


def db_user(username: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT username, role, pubkey_b64 FROM users WHERE username=?", (username,)
    )
    r = c.fetchone()
    conn.close()
    if not r:
        return None
    return {"username": r[0], "role": r[1], "pubkey_b64": r[2]}


def db_create_user(username: str, role: str, pubkey_b64: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO users(username, role, pubkey_b64, created_at) VALUES(?,?,?,?)",
        (username, role, pubkey_b64, time.time()),
    )
    conn.commit()
    conn.close()


def db_set_role(username: str, role: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    ok = c.rowcount > 0
    conn.commit()
    conn.close()
    return ok


def db_list_users() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users ORDER BY id")
    out = [
        {"id": r[0], "username": r[1], "role": r[2], "created_at": r[3]}
        for r in c.fetchall()
    ]
    conn.close()
    return out


def db_insert_file(meta: Dict[str, Any]) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO files(owner, filename, size, created_at, sha256_b64, signature_b64,
             enc_alg, nonce_b64, path, wrapped_key_b64, wrap_nonce_b64)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            meta["owner"],
            meta["filename"],
            meta["size"],
            time.time(),
            meta["sha256_b64"],
            meta["signature_b64"],
            meta["enc_alg"],
            meta["nonce_b64"],
            meta["path"],
            meta["wrapped_key_b64"],
            meta["wrap_nonce_b64"],
        ),
    )
    fid = c.lastrowid
    conn.commit()
    conn.close()
    return fid


def db_get_file(fid: int) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """SELECT id, owner, filename, size, created_at, sha256_b64, signature_b64,
                 enc_alg, nonce_b64, path, wrapped_key_b64, wrap_nonce_b64
                 FROM files WHERE id=?""",
        (fid,),
    )
    r = c.fetchone()
    conn.close()
    if not r:
        return None
    keys = [
        "id",
        "owner",
        "filename",
        "size",
        "created_at",
        "sha256_b64",
        "signature_b64",
        "enc_alg",
        "nonce_b64",
        "path",
        "wrapped_key_b64",
        "wrap_nonce_b64",
    ]
    return dict(zip(keys, r))


def db_list_files() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, owner, filename, size, created_at FROM files ORDER BY id DESC"
    )
    out = [
        {"id": r[0], "owner": r[1], "filename": r[2], "size": r[3], "created_at": r[4]}
        for r in c.fetchall()
    ]
    conn.close()
    return out


def db_delete_file(fid: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE id=?", (fid,))
    ok = c.rowcount > 0
    conn.commit()
    conn.close()
    return ok


# ---------- KEK ----------
def load_or_create_kek() -> bytes:
    """Load KEK (32B). If not found, create and persist."""
    env = os.environ.get("SFS_KEK_B64")
    if env:
        return b64d(env)
    if os.path.exists(KEK_PATH):
        return pathlib.Path(KEK_PATH).read_bytes()
    kek = os.urandom(32)
    pathlib.Path(KEK_PATH).write_bytes(kek)
    return kek


# ---------- server signing key (auto) ----------
def ensure_server_signing_key():
    """Load or generate server RSA keypair (for handshake signing)."""
    if os.path.exists(SERVER_PRIV_PATH):
        with open(SERVER_PRIV_PATH, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(SERVER_PRIV_PATH, "wb") as f:
        f.write(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with open(SERVER_PUB_PATH, "wb") as f:
        f.write(
            priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("Generated server signing keypair: server_priv.pem / server_pub.pem")
    return priv


# ---------- secure channel ----------
class SecureState:
    """Per-connection AES-GCM with strict ordered counters."""

    def __init__(self, key: bytes, salt4: bytes):
        self.key = key
        self.salt4 = salt4
        self.send_ctr = 0
        self.recv_ctr = 0
        self.aes = AESGCM(self.key)

    def _nonce_send(self) -> bytes:
        n = self.salt4 + struct.pack(">Q", self.send_ctr)
        self.send_ctr += 1
        return n

    def _nonce_recv(self) -> bytes:
        n = self.salt4 + struct.pack(">Q", self.recv_ctr)
        self.recv_ctr += 1
        return n

    def wrap(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        pt = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ct = self.aes.encrypt(self._nonce_send(), pt, None)
        return {"type": "secmsg", "ct": b64e(ct)}

    def unwrap(self, env: Dict[str, Any]) -> Dict[str, Any]:
        if env.get("type") != "secmsg":
            raise ValueError("not_secure_msg")
        pt = self.aes.decrypt(self._nonce_recv(), b64d(env["ct"]), None)
        return json.loads(pt.decode("utf-8"))


async def send_line(writer: asyncio.StreamWriter, obj: Dict[str, Any]) -> None:
    data = (
        json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    writer.write(data)
    await writer.drain()


async def recv_line(reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
    line = await reader.readline()
    if not line:
        return None
    if len(line) > MAX_LINE:
        raise ValueError("message too long")
    return json.loads(line.decode("utf-8"))


# ---------- RBAC ----------
def is_admin(role: Optional[str]) -> bool:
    return role == "admin"


def can_upload(role: Optional[str]) -> bool:
    return role in ("admin", "maintainer")


# ---------- server logic ----------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    session_id = str(uuid.uuid4())
    print(f"[+] client {peer} session={session_id}")

    sec: Optional[SecureState] = None
    login_user: Optional[str] = None
    login_role: Optional[str] = None
    login_nonce: Optional[bytes] = None
    uploads: Dict[str, Dict[str, Any]] = {}

    kek = load_or_create_kek()

    try:
        while True:
            msg = await recv_line(reader)
            if msg is None:
                break

            # plaintext ops allowed before secure channel
            op = msg.get("op")
            seq = msg.get("seq")
            payload = msg.get("payload", {})

            # -------- plaintext ops --------
            if op == "get_server_pub":
                with open(SERVER_PUB_PATH, "rb") as f:
                    pub_pem = f.read()
                await send_line(
                    writer,
                    {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"server_pub_pem_b64": b64e(pub_pem)},
                    },
                )
                continue

            if op == "hs1":
                cpub_b64 = payload.get("client_eph_pub_b64")
                if not cpub_b64:
                    await send_line(
                        writer,
                        {
                            "type": "error",
                            "op": op,
                            "ok": False,
                            "seq": seq,
                            "error": "missing client_eph_pub_b64",
                        },
                    )
                    continue
                cpub = X25519PublicKey.from_public_bytes(b64d(cpub_b64))
                spriv = X25519PrivateKey.generate()
                spub = spriv.public_key()
                shared = spriv.exchange(cpub)
                salt4 = os.urandom(4)
                transcript = hashlib.sha256(
                    spub.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                    + cpub.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                    + salt4
                ).digest()
                key = hkdf(shared, salt=transcript)
                sec = SecureState(key, salt4)
                # sign handshake
                to_sign = (
                    spub.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                    + cpub.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                    + salt4
                )
                sig = SERVER_SIGN_PRIV.sign(
                    to_sign,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                resp = {
                    "type": "response",
                    "op": op,
                    "ok": True,
                    "seq": seq,
                    "payload": {
                        "server_eph_pub_b64": b64e(
                            spub.public_bytes(
                                serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw,
                            )
                        ),
                        "salt4_b64": b64e(salt4),
                        "sig_b64": b64e(sig),
                    },
                }
                await send_line(writer, resp)
                continue

            # after secure: unwrap incoming
            if not sec:
                await send_line(
                    writer,
                    {
                        "type": "error",
                        "op": op,
                        "ok": False,
                        "seq": seq,
                        "error": "secure_channel_required",
                    },
                )
                continue
            if msg.get("type") == "secmsg":
                try:
                    msg = sec.unwrap(msg)
                except Exception as e:
                    await send_line(
                        writer, {"type": "error", "error": f"decrypt_failed:{e}"}
                    )
                    continue
                op = msg.get("op")
                seq = msg.get("seq")
                payload = msg.get("payload", {})

            try:
                # ---- basic ----
                if op == "ping":
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {
                            "msg": "pong",
                            "server_time": time.time(),
                            "session": session_id,
                        },
                    }

                elif op == "register":
                    username = payload.get("username")
                    pubkey_pem_b64 = payload.get("pubkey_pem_b64")
                    if not username or not pubkey_pem_b64:
                        raise ValueError("missing username/pubkey_pem_b64")
                    if db_user(username):
                        raise ValueError("username_taken")
                    pub = load_pem_public_key(b64d(pubkey_pem_b64))
                    if not isinstance(pub, rsa.RSAPublicKey):
                        raise ValueError("not_rsa_pubkey")
                    if pub.key_size < 2048:
                        raise ValueError("rsa_key_too_small")
                    db_create_user(username, "guest", pubkey_pem_b64)
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"created": username, "role": "guest"},
                    }

                elif op == "login_begin":
                    username = payload.get("username")
                    u = db_user(username) if username else None
                    if not u:
                        raise ValueError("no_such_user")
                    login_nonce = os.urandom(32)
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {
                            "username": username,
                            "nonce_b64": b64e(login_nonce),
                        },
                    }

                elif op == "login_finish":
                    username = payload.get("username")
                    sig_b64 = payload.get("signature_b64")
                    if not username or not sig_b64:
                        raise ValueError("missing username/signature_b64")
                    u = db_user(username)
                    if not u:
                        raise ValueError("no_such_user")
                    if not login_nonce:
                        raise ValueError("no_login_begin")
                    pub = load_pem_public_key(b64d(u["pubkey_b64"]))
                    pub.verify(
                        b64d(sig_b64),
                        login_nonce,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                    login_user = username
                    login_role = u["role"]
                    login_nonce = None
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"username": login_user, "role": login_role},
                    }

                elif op == "whoami":
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {
                            "username": login_user,
                            "role": login_role,
                            "session": session_id,
                        },
                    }

                elif op == "list_users":
                    if not is_admin(login_role):
                        raise PermissionError("forbidden")
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"users": db_list_users()},
                    }

                elif op == "set_role":
                    if not is_admin(login_role):
                        raise PermissionError("forbidden")
                    target = payload.get("username")
                    newrole = payload.get("role")
                    if newrole not in ("admin", "maintainer", "guest"):
                        raise ValueError("bad_role")
                    ok = db_set_role(target, newrole)
                    if not ok:
                        raise ValueError("no_such_user")
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"username": target, "role": newrole},
                    }

                elif op == "get_pubkey":
                    uname = payload.get("username")
                    u = db_user(uname) if uname else None
                    if not u:
                        raise ValueError("no_such_user")
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {
                            "username": uname,
                            "pubkey_pem_b64": u["pubkey_b64"],
                        },
                    }

                elif op == "list_files":
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"files": db_list_files()},
                    }

                # ---- upload ----
                elif op == "upload_begin":
                    if not can_upload(login_role):
                        raise PermissionError("forbidden")
                    filename = payload.get("filename")
                    size = payload.get("size")
                    sha256_b64 = payload.get("sha256_b64")
                    signature_b64 = payload.get("signature_b64")
                    if (
                        not filename
                        or size is None
                        or not sha256_b64
                        or not signature_b64
                    ):
                        raise ValueError("missing fields")
                    u = db_user(login_user)
                    pub = load_pem_public_key(b64d(u["pubkey_b64"]))
                    pub.verify(
                        b64d(signature_b64),
                        b64d(sha256_b64),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                    upid = str(uuid.uuid4())
                    # keep chunks in memory (OK for class project)
                    uploads[upid] = {
                        "owner": login_user,
                        "filename": filename,
                        "size": int(size),
                        "sha256_b64": sha256_b64,
                        "signature_b64": signature_b64,
                        "buf": bytearray(),
                    }
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"upload_id": upid, "chunk": CHUNK},
                    }

                elif op == "upload_chunk":
                    upid = payload.get("upload_id")
                    data_b64 = payload.get("data_b64")
                    idx = payload.get("idx", 0)
                    st = uploads.get(upid)
                    if not st:
                        raise ValueError("no_such_upload")
                    if login_user != st["owner"]:
                        raise PermissionError("forbidden")
                    st["buf"].extend(b64d(data_b64))
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"upload_id": upid, "idx": idx},
                    }

                elif op == "upload_end":
                    upid = payload.get("upload_id")
                    st = uploads.get(upid)
                    if not st:
                        raise ValueError("no_such_upload")
                    if login_user != st["owner"]:
                        raise PermissionError("forbidden")
                    plain = bytes(st["buf"])
                    if len(plain) != st["size"]:
                        uploads.pop(upid, None)
                        raise ValueError("size_mismatch")
                    if b64e(sha256_bytes(plain)) != st["sha256_b64"]:
                        uploads.pop(upid, None)
                        raise ValueError("sha256_mismatch")
                    file_key = os.urandom(32)
                    data_nonce = os.urandom(12)
                    ct = AESGCM(file_key).encrypt(data_nonce, plain, None)
                    wrap_nonce = os.urandom(12)
                    wrapped = AESGCM(load_or_create_kek()).encrypt(
                        wrap_nonce, file_key, None
                    )
                    pathlib.Path(STORAGE_DIR).mkdir(parents=True, exist_ok=True)
                    tmpname = f"{uuid.uuid4().hex}.bin"
                    path = str(pathlib.Path(STORAGE_DIR) / tmpname)
                    pathlib.Path(path).write_bytes(ct)
                    meta = {
                        "owner": st["owner"],
                        "filename": st["filename"],
                        "size": st["size"],
                        "sha256_b64": st["sha256_b64"],
                        "signature_b64": st["signature_b64"],
                        "enc_alg": "aes-256-gcm",
                        "nonce_b64": b64e(data_nonce),
                        "path": path,
                        "wrapped_key_b64": b64e(wrapped),
                        "wrap_nonce_b64": b64e(wrap_nonce),
                    }
                    fid = db_insert_file(meta)
                    uploads.pop(upid, None)
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"file_id": fid},
                    }

                # ---- download ----
                elif op == "download_begin":
                    fid = int(payload.get("file_id"))
                    rec = db_get_file(fid)
                    if not rec:
                        raise ValueError("no_such_file")
                    data_nonce = b64d(rec["nonce_b64"])
                    wrapped_key = b64d(rec["wrapped_key_b64"])
                    wrap_nonce = b64d(rec["wrap_nonce_b64"])
                    file_key = AESGCM(load_or_create_kek()).decrypt(
                        wrap_nonce, wrapped_key, None
                    )
                    ct = pathlib.Path(rec["path"]).read_bytes()
                    plain = AESGCM(file_key).decrypt(data_nonce, ct, None)
                    # send meta
                    meta = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {
                            "file_id": rec["id"],
                            "filename": rec["filename"],
                            "owner": rec["owner"],
                            "size": rec["size"],
                            "sha256_b64": rec["sha256_b64"],
                            "signature_b64": rec["signature_b64"],
                            "chunk": CHUNK,
                        },
                    }
                    await send_line(writer, sec.wrap(meta))
                    # send chunks
                    idx = 0
                    for i in range(0, len(plain), CHUNK):
                        chunk = plain[i : i + CHUNK]
                        msgc = {
                            "type": "response",
                            "op": "download_chunk",
                            "ok": True,
                            "seq": seq,
                            "payload": {
                                "file_id": rec["id"],
                                "idx": idx,
                                "data_b64": b64e(chunk),
                            },
                        }
                        await send_line(writer, sec.wrap(msgc))
                        idx += 1
                    end = {
                        "type": "response",
                        "op": "download_end",
                        "ok": True,
                        "seq": seq,
                        "payload": {"file_id": rec["id"], "count": idx},
                    }
                    await send_line(writer, sec.wrap(end))
                    continue  # already responded

                elif op == "delete_file":
                    fid = int(payload.get("file_id"))
                    rec = db_get_file(fid)
                    if not rec:
                        raise ValueError("no_such_file")
                    if not (is_admin(login_role) or rec["owner"] == login_user):
                        raise PermissionError("forbidden")
                    try:
                        os.remove(rec["path"])
                    except FileNotFoundError:
                        pass
                    ok = db_delete_file(fid)
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": ok,
                        "seq": seq,
                        "payload": {"file_id": fid},
                    }

                elif op == "quit":
                    out = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"msg": "bye"},
                    }
                    await send_line(writer, sec.wrap(out))
                    break

                else:
                    out = {
                        "type": "error",
                        "op": op,
                        "ok": False,
                        "seq": seq,
                        "error": "unknown_op",
                    }

                await send_line(writer, sec.wrap(out))

            except PermissionError as pe:
                await send_line(
                    writer,
                    sec.wrap(
                        {
                            "type": "error",
                            "op": op,
                            "ok": False,
                            "seq": seq,
                            "error": str(pe),
                        }
                    ),
                )
            except Exception as e:
                await send_line(
                    writer,
                    sec.wrap(
                        {
                            "type": "error",
                            "op": op,
                            "ok": False,
                            "seq": seq,
                            "error": f"{e}",
                        }
                    ),
                )

    except Exception as e:
        print(f"[!] error with {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[-] client {peer} closed session={session_id}")


async def main():
    global SERVER_SIGN_PRIV
    db_init()
    pathlib.Path(STORAGE_DIR).mkdir(parents=True, exist_ok=True)
    _ = load_or_create_kek()
    SERVER_SIGN_PRIV = ensure_server_signing_key()
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Server listening on {addr}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")
