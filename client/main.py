import asyncio, json, argparse, base64, os, struct, hashlib, pathlib
from typing import Optional, Dict, Any

# RSA for signing login nonce and file-hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# X25519 + HKDF + AES-GCM for transport
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_LINE = 128 * 1024
CHUNK = 44 * 1024
SERVER_PUB_CACHE = "server_pub.pem"  # TOFU cache


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


class SecureState:
    """AES-GCM transport with strict ordered counters."""

    def __init__(self, key: bytes, salt4: bytes):
        self.key = key
        self.salt4 = salt4
        self.send_ctr = 0
        self.recv_ctr = 0
        self.aes = AESGCM(key)

    def _n_send(self) -> bytes:
        n = self.salt4 + struct.pack(">Q", self.send_ctr)
        self.send_ctr += 1
        return n

    def _n_recv(self) -> bytes:
        n = self.salt4 + struct.pack(">Q", self.recv_ctr)
        self.recv_ctr += 1
        return n

    def wrap(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        pt = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ct = self.aes.encrypt(self._n_send(), pt, None)
        return {"type": "secmsg", "ct": b64e(ct)}

    def unwrap(self, env: Dict[str, Any]) -> Dict[str, Any]:
        if env.get("type") != "secmsg":
            raise ValueError("not_secure_msg")
        pt = self.aes.decrypt(self._n_recv(), b64d(env["ct"]), None)
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


def gen_rsa_keys(priv_path: str, pub_pem_path: str) -> None:
    """Generate RSA-2048 pair."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pathlib.Path(priv_path).write_bytes(priv_pem)
    pathlib.Path(pub_pem_path).write_bytes(pub_pem)
    print(f"Generated:\n  priv: {priv_path}\n  pub:  {pub_pem_path}")


def try_load_server_pub():
    try:
        with open(SERVER_PUB_CACHE, "rb") as f:
            pem = f.read()
        print(f"Loaded cached server public key from {SERVER_PUB_CACHE}")
        return load_pem_public_key(pem)
    except Exception:
        return None



async def ensure_server_pub(reader, writer):
    """TOFU: fetch server pubkey once if not cached; then cache & return it."""
    pub = try_load_server_pub()
    if pub:
        return pub
    await send_line(writer, {"op": "get_server_pub", "seq": 0, "payload": {}})
    resp = await recv_line(reader)
    if not resp or not resp.get("ok"):
        print("WARN: could not fetch server public key; proceeding unauthenticated.")
        return None
    pem = b64d(resp["payload"]["server_pub_pem_b64"])
    with open(SERVER_PUB_CACHE, "wb") as f:
        f.write(pem)
    print(f"Saved server public key to {SERVER_PUB_CACHE}")
    return load_pem_public_key(pem)


async def cmd_secure(reader, writer) -> SecureState:
    """Perform handshake and return SecureState (with signature verification via TOFU)."""
    server_pub = await ensure_server_pub(reader, writer)

    cpriv = X25519PrivateKey.generate()
    cpub = cpriv.public_key()
    hs1 = {
        "op": "hs1",
        "seq": 1,
        "payload": {
            "client_eph_pub_b64": b64e(
                cpub.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            )
        },
    }
    await send_line(writer, hs1)
    hs2 = await recv_line(reader)
    if not hs2 or not hs2.get("ok"):
        raise RuntimeError("Handshake failed")
    spub = X25519PublicKey.from_public_bytes(b64d(hs2["payload"]["server_eph_pub_b64"]))
    salt4 = b64d(hs2["payload"]["salt4_b64"])
    sig_b64 = hs2["payload"]["sig_b64"]

    shared = cpriv.exchange(spub)
    transcript = hashlib.sha256(
        spub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        + cpub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        + salt4
    ).digest()
    key = hkdf(shared, salt=transcript)
    sec = SecureState(key, salt4)

    if sig_b64 and server_pub:
        to_verify = (
            spub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            + cpub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            + salt4
        )
        try:
            server_pub.verify(
                b64d(sig_b64),
                to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("Handshake signature verified ✔")
        except Exception as e:
            print("WARNING: server signature verification failed!", e)
    elif not server_pub:
        print(
            "NOTE: TOFU: fetched & cached server pubkey; verification applies next time."
        )

    print("Secure channel established.")
    return sec


async def cmd_register(sec, reader, writer, username: str, pub_pem_path: str):
    pub_pem = pathlib.Path(pub_pem_path).read_bytes()
    msg = {
        "op": "register",
        "seq": 2,
        "payload": {"username": username, "pubkey_pem_b64": b64e(pub_pem)},
    }
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(resp, ensure_ascii=False))


async def cmd_login(sec, reader, writer, username: str, priv):
    msg = {"op": "login_begin", "seq": 3, "payload": {"username": username}}
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(resp, ensure_ascii=False))
    if not resp.get("ok"):
        print("login_begin failed")
        return
    nonce = b64d(resp["payload"]["nonce_b64"])
    sig = priv.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    msg = {
        "op": "login_finish",
        "seq": 4,
        "payload": {"username": username, "signature_b64": b64e(sig)},
    }
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(resp, ensure_ascii=False))


async def cmd_whoami(sec, reader, writer):
    msg = {"op": "whoami", "seq": 5, "payload": {}}
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(resp, ensure_ascii=False))


async def cmd_list_files(sec, reader, writer):
    msg = {"op": "list_files", "seq": 6, "payload": {}}
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(resp, ensure_ascii=False))
    return resp


async def cmd_get_pubkey(sec, reader, writer, username: str) -> bytes:
    msg = {"op": "get_pubkey", "seq": 7, "payload": {"username": username}}
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    if not resp.get("ok"):
        raise RuntimeError("get_pubkey failed")
    return b64d(resp["payload"]["pubkey_pem_b64"])


async def cmd_upload(
    sec, reader, writer, priv, local_path: str, remote_name: Optional[str] = None
):
    data = pathlib.Path(local_path).read_bytes()
    name = remote_name or os.path.basename(local_path)
    digest = sha256_bytes(data)
    sig = priv.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    msg = {
        "op": "upload_begin",
        "seq": 8,
        "payload": {
            "filename": name,
            "size": len(data),
            "sha256_b64": b64e(digest),
            "signature_b64": b64e(sig),
        },
    }
    await send_line(writer, sec.wrap(msg))
    resp_env = await recv_line(reader)
    resp = sec.unwrap(resp_env)
    print("<", json.dumps(resp, ensure_ascii=False))
    if not resp or not resp.get("ok"):
        print("upload_begin failed:", resp.get("error") if resp else "no response")
        return
    upid = resp["payload"]["upload_id"]
    # send chunks
    idx = 0
    for i in range(0, len(data), CHUNK):
        chunk = data[i : i + CHUNK]
        msgc = {
            "op": "upload_chunk",
            "seq": 9,
            "payload": {"upload_id": upid, "idx": idx, "data_b64": b64e(chunk)},
        }
        await send_line(writer, sec.wrap(msgc))
        _ = sec.unwrap(await recv_line(reader))
        idx += 1
    # end
    msg = {"op": "upload_end", "seq": 10, "payload": {"upload_id": upid}}
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(resp, ensure_ascii=False))
    return resp


async def cmd_download(sec, reader, writer, file_id: int, out_path: str):
    msg = {"op": "download_begin", "seq": 11, "payload": {"file_id": int(file_id)}}
    await send_line(writer, sec.wrap(msg))
    # meta
    meta = sec.unwrap(await recv_line(reader))
    print("<", json.dumps(meta, ensure_ascii=False))
    if not meta.get("ok"):
        print("download_begin failed:", meta.get("error"))
        return
    owner = meta["payload"]["owner"]
    size = meta["payload"]["size"]
    sha_ref = meta["payload"]["sha256_b64"]
    sig_ref = meta["payload"]["signature_b64"]
    buf = bytearray()
    # chunks until end
    while True:
        env = await recv_line(reader)
        if env is None:
            print("server closed during download")
            return
        msg = sec.unwrap(env)
        if msg.get("op") == "download_chunk":
            buf.extend(b64d(msg["payload"]["data_b64"]))
        elif msg.get("op") == "download_end":
            break
    pathlib.Path(out_path).write_bytes(bytes(buf))
    print(f"Saved: {out_path} ({len(buf)} bytes)")
    # verify integrity
    if b64e(sha256_bytes(bytes(buf))) != sha_ref:
        print("sha256 mismatch after download")
        return
    # verify signature using owner's pubkey
    msg = {"op": "get_pubkey", "seq": 12, "payload": {"username": owner}}
    await send_line(writer, sec.wrap(msg))
    resp = sec.unwrap(await recv_line(reader))
    if not resp.get("ok"):
        print("get_pubkey failed")
        return
    pub = load_pem_public_key(b64d(resp["payload"]["pubkey_pem_b64"]))
    pub.verify(
        b64d(sig_ref),
        b64d(sha_ref),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    print("Integrity & signature verified ✔")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5050)
    args = ap.parse_args()
    
    global SERVER_PUB_CACHE
    cache_dir = os.path.join(os.path.expanduser("~"), ".sfs_cache")
    os.makedirs(cache_dir, exist_ok=True)
    SERVER_PUB_CACHE = os.path.join(cache_dir, f"server_pub_{args.host}_{args.port}.pem")
    print(f"Server pubkey cache path: {SERVER_PUB_CACHE}")

    reader, writer = await asyncio.open_connection(args.host, args.port)
    try:
        sec = await cmd_secure(reader, writer)
        print("Commands:")
        print("  genkeys <priv.pem> <pub.pem>")
        print("  loadkey <priv.pem>")
        print("  register <username> <pub.pem>")
        print("  login <username>")
        print("  whoami")
        print("  list_users")
        print("  set_role <username> <admin|maintainer|guest>")
        print("  list_files")
        print("  upload <local_path> [remote_name]")
        print("  download <file_id> <out_path>")
        print("  get_pubkey <username>")
        print("  delete_file <file_id>")
        print("  quit")

        priv = None

        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                line = "quit"
            if not line:
                continue
            parts = line.split()
            cmd = parts[0]

            if cmd == "genkeys":
                if len(parts) < 3:
                    print("Usage: genkeys <priv.pem> <pub.pem>")
                    continue
                gen_rsa_keys(parts[1], parts[2])
                continue

            if cmd == "loadkey":
                if len(parts) < 2:
                    print("Usage: loadkey <priv.pem>")
                    continue
                try:
                    priv = load_pem_private_key(
                        open(parts[1], "rb").read(), password=None
                    )
                    print("Private key loaded.")
                except Exception as e:
                    print("Failed:", e)
                continue

            if cmd == "register":
                if len(parts) < 3:
                    print("Usage: register <username> <pub.pem>")
                    continue
                await cmd_register(sec, reader, writer, parts[1], parts[2])
                continue

            if cmd == "login":
                if len(parts) < 2:
                    print("Usage: login <username>")
                    continue
                if not priv:
                    print("Load private key first.")
                    continue
                await cmd_login(sec, reader, writer, parts[1], priv)
                continue

            if cmd == "whoami":
                await cmd_whoami(sec, reader, writer)
                continue

            if cmd == "list_users":
                msg = {"op": "list_users", "seq": 20, "payload": {}}
                await send_line(writer, sec.wrap(msg))
                resp = sec.unwrap(await recv_line(reader))
                print("<", json.dumps(resp, ensure_ascii=False))
                continue

            if cmd == "set_role":
                if len(parts) < 3:
                    print("Usage: set_role <username> <admin|maintainer|guest>")
                    continue
                msg = {
                    "op": "set_role",
                    "seq": 21,
                    "payload": {"username": parts[1], "role": parts[2]},
                }
                await send_line(writer, sec.wrap(msg))
                resp = sec.unwrap(await recv_line(reader))
                print("<", json.dumps(resp, ensure_ascii=False))
                continue

            if cmd == "list_files":
                await cmd_list_files(sec, reader, writer)
                continue

            if cmd == "upload":
                if len(parts) < 2:
                    print("Usage: upload <local_path> [remote_name]")
                    continue
                if not priv:
                    print("Load private key first.")
                    continue
                remote = parts[2] if len(parts) > 2 else None
                await cmd_upload(sec, reader, writer, priv, parts[1], remote)
                continue

            if cmd == "download":
                if len(parts) < 3:
                    print("Usage: download <file_id> <out_path>")
                    continue
                await cmd_download(sec, reader, writer, int(parts[1]), parts[2])
                continue

            if cmd == "get_pubkey":
                if len(parts) < 2:
                    print("Usage: get_pubkey <username>")
                    continue
                pk = await cmd_get_pubkey(sec, reader, writer, parts[1])
                print(pk.decode())
                continue

            if cmd == "delete_file":
                if len(parts) < 2:
                    print("Usage: delete_file <file_id>")
                    continue
                msg = {
                    "op": "delete_file",
                    "seq": 22,
                    "payload": {"file_id": int(parts[1])},
                }
                await send_line(writer, sec.wrap(msg))
                resp = sec.unwrap(await recv_line(reader))
                print("<", json.dumps(resp, ensure_ascii=False))
                continue

            if cmd == "quit":
                await send_line(
                    writer, sec.wrap({"op": "quit", "seq": 99, "payload": {}})
                )
                break

            print("Unknown. See help above.")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print("Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())
