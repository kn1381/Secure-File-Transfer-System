# Secure File Client GUI (tkinter) – fixed ownership & RBAC checks in UI
# - No changes to server/client modules
# - Verifies loaded private key matches logged-in user before upload
# - Blocks delete in UI unless admin or owner
# - Progress bars + humanized dates + session tracking

import os
import json
import asyncio
import threading
import traceback
import importlib.util
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from datetime import datetime

# ---------- dynamic import of client/main.py ----------
HERE = os.path.abspath(os.path.dirname(__file__))
CLIENT_PATH = os.path.join(HERE, "client", "main.py")
if not os.path.isfile(CLIENT_PATH):
    raise SystemExit(f"client/main.py not found at: {CLIENT_PATH}")

spec = importlib.util.spec_from_file_location("sfs_client", CLIENT_PATH)
sfs_client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sfs_client)  # load as module (no __main__)


def fmt_ts(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def guess_username_from_path(path):
    name = os.path.basename(path)
    base, _ = os.path.splitext(name)
    for suf in ("_priv", "_private", "_key", "_pub", "_public"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)]
            break
    return base or name


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Client — GUI")
        self.geometry("1000x720")

        # async I/O
        self.loop = asyncio.new_event_loop()
        self.net_thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.net_thread.start()

        # network/session state
        self.reader = None
        self.writer = None
        self.sec = None
        self.loaded_priv = None  # RSA private key
        self.session_user = None
        self.session_role = None

        self._build_widgets()

    # ---------- UI ----------
    def _build_widgets(self):
        top = ttk.Frame(self, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(top, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.host_var, width=16).pack(
            side=tk.LEFT, padx=(4, 10)
        )
        ttk.Label(top, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="5050")
        ttk.Entry(top, textvariable=self.port_var, width=8).pack(
            side=tk.LEFT, padx=(4, 10)
        )

        self.btn_connect = ttk.Button(
            top, text="Connect & Secure", command=self.on_connect_clicked
        )
        self.btn_connect.pack(side=tk.LEFT, padx=6)
        self.btn_disconnect = ttk.Button(
            top,
            text="Disconnect",
            command=self.on_disconnect_clicked,
            state=tk.DISABLED,
        )
        self.btn_disconnect.pack(side=tk.LEFT, padx=6)

        self.status_var = tk.StringVar(value="Not connected.")
        ttk.Label(top, textvariable=self.status_var).pack(side=tk.LEFT, padx=12)

        self.nb = ttk.Notebook(self)
        self.nb.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.tab_keys = ttk.Frame(self.nb, padding=8)
        self.tab_auth = ttk.Frame(self.nb, padding=8)
        self.tab_files = ttk.Frame(self.nb, padding=8)
        self.tab_admin = ttk.Frame(self.nb, padding=8)
        self.nb.add(self.tab_keys, text="Keys & Register")
        self.nb.add(self.tab_auth, text="Login")
        self.nb.add(self.tab_files, text="Files")
        self.nb.add(self.tab_admin, text="Admin")

        self._build_tab_keys()
        self._build_tab_auth()
        self._build_tab_files()
        self._build_tab_admin()

        self.log = ScrolledText(self, height=10, font=("Consolas", 10))
        self.log.pack(side=tk.BOTTOM, fill=tk.BOTH, padx=8, pady=(0, 8))

        self._set_tabs_state(tk.DISABLED)

    def _build_tab_keys(self):
        f = self.tab_keys
        g = ttk.Labelframe(f, text="Generate RSA keypair", padding=8)
        g.pack(fill=tk.X, pady=(0, 8))
        self.gen_priv_var = tk.StringVar()
        self.gen_pub_var = tk.StringVar()

        row = ttk.Frame(g)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Private PEM:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row, textvariable=self.gen_priv_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(
            row,
            text="Browse",
            command=lambda: self._pick_path(
                self.gen_priv_var, save=True, defname="priv.pem"
            ),
        ).pack(side=tk.LEFT, padx=6)

        row = ttk.Frame(g)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Public PEM:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row, textvariable=self.gen_pub_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(
            row,
            text="Browse",
            command=lambda: self._pick_path(
                self.gen_pub_var, save=True, defname="pub.pem"
            ),
        ).pack(side=tk.LEFT, padx=6)

        ttk.Button(g, text="Generate", command=self.on_generate_keys).pack(
            anchor=tk.E, pady=(6, 0)
        )

        r = ttk.Labelframe(f, text="Register user (default role: guest)", padding=8)
        r.pack(fill=tk.X)
        self.reg_user_var = tk.StringVar()
        self.reg_pub_var = tk.StringVar()

        row = ttk.Frame(r)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Username:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row, textvariable=self.reg_user_var, width=24).pack(side=tk.LEFT)

        row = ttk.Frame(r)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Public PEM:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row, textvariable=self.reg_pub_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(
            row,
            text="Browse",
            command=lambda: self._pick_path(self.reg_pub_var, save=False),
        ).pack(side=tk.LEFT, padx=6)

        ttk.Button(r, text="Register", command=self.on_register).pack(
            anchor=tk.E, pady=(6, 0)
        )

    def _build_tab_auth(self):
        f = self.tab_auth
        l = ttk.Labelframe(f, text="Login with RSA-PSS", padding=8)
        l.pack(fill=tk.X)
        self.login_user_var = tk.StringVar()
        self.login_priv_var = tk.StringVar()

        row = ttk.Frame(l)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Username:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row, textvariable=self.login_user_var, width=24).pack(side=tk.LEFT)

        row = ttk.Frame(l)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Private PEM:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row, textvariable=self.login_priv_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(
            row,
            text="Browse",
            command=lambda: self._pick_path(self.login_priv_var, save=False),
        ).pack(side=tk.LEFT, padx=6)

        row = ttk.Frame(l)
        row.pack(fill=tk.X, pady=6)
        ttk.Button(row, text="Load Private Key", command=self.on_load_priv).pack(
            side=tk.LEFT
        )
        ttk.Button(row, text="Login", command=self.on_login).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="Whoami", command=self.on_whoami).pack(
            side=tk.LEFT, padx=6
        )

    def _build_tab_files(self):
        f = self.tab_files
        row = ttk.Frame(f)
        row.pack(fill=tk.X)
        ttk.Button(row, text="Refresh", command=self.on_list_files).pack(side=tk.LEFT)
        ttk.Button(row, text="Upload", command=self.on_upload).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(row, text="Download", command=self.on_download).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(row, text="Delete", command=self.on_delete_file).pack(
            side=tk.LEFT, padx=6
        )

        p = ttk.Labelframe(f, text="Progress", padding=8)
        p.pack(fill=tk.X, pady=6)
        self.ul_label_var = tk.StringVar(value="Upload: idle")
        ttk.Label(p, textvariable=self.ul_label_var).pack(fill=tk.X)
        self.ul_bar = ttk.Progressbar(p, mode="determinate", maximum=100)
        self.ul_bar.pack(fill=tk.X, padx=4, pady=(0, 6))
        self.dl_label_var = tk.StringVar(value="Download: idle")
        ttk.Label(p, textvariable=self.dl_label_var).pack(fill=tk.X)
        self.dl_bar = ttk.Progressbar(p, mode="determinate", maximum=100)
        self.dl_bar.pack(fill=tk.X, padx=4)

        cols = ("id", "owner", "filename", "size", "created_at")
        self.files_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        for c in cols:
            self.files_tree.heading(c, text=c)
            w = 120
            if c == "filename":
                w = 360
            if c == "size":
                w = 100
            self.files_tree.column(c, width=w, anchor="w")
        self.files_tree.pack(fill=tk.BOTH, expand=True, pady=6)

    def _build_tab_admin(self):
        f = self.tab_admin
        row = ttk.Frame(f)
        row.pack(fill=tk.X)
        ttk.Button(row, text="List Users", command=self.on_list_users).pack(
            side=tk.LEFT
        )
        ttk.Label(row, text="   Set Role: user").pack(side=tk.LEFT)
        self.ar_user_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.ar_user_var, width=18).pack(
            side=tk.LEFT, padx=(4, 8)
        )
        ttk.Label(row, text="role").pack(side=tk.LEFT)
        self.ar_role_var = tk.StringVar(value="guest")
        ttk.Combobox(
            row,
            textvariable=self.ar_role_var,
            values=["admin", "maintainer", "guest"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Apply", command=self.on_set_role).pack(
            side=tk.LEFT, padx=6
        )

        cols = ("id", "username", "role", "created_at")
        self.users_tree = ttk.Treeview(f, columns=cols, show="headings", height=12)
        for c in cols:
            self.users_tree.heading(c, text=c)
            self.users_tree.column(c, width=160, anchor="w")
        self.users_tree.pack(fill=tk.BOTH, expand=True, pady=6)

    # ---------- helpers ----------
    def log_print(self, *args):
        msg = " ".join(str(a) for a in args)
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def _pick_path(self, var, save=False, defname=""):
        if save:
            path = filedialog.asksaveasfilename(initialfile=defname)
        else:
            path = filedialog.askopenfilename()
        if path:
            var.set(path)
            if var is self.login_priv_var and not self.login_user_var.get().strip():
                self.login_user_var.set(guess_username_from_path(path))
            if var is self.reg_pub_var and not self.reg_user_var.get().strip():
                self.reg_user_var.set(guess_username_from_path(path))

    def _set_tabs_state(self, state):
        for i in range(self.nb.index("end")):
            self.nb.tab(i, state=state)

    def run_coro(self, coro, on_done=None):
        def _done(fut):
            try:
                res = fut.result()
            except Exception as e:
                tb = traceback.format_exc()
                self.after(0, self.log_print, "[ERROR]", e, "\n", tb)
                if on_done:
                    self.after(0, on_done, None)
                return
            if on_done:
                self.after(0, on_done, res)

        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        fut.add_done_callback(_done)

    # ---------- session helpers ----------
    async def _whoami_rpc(self):
        msg = {"op": "whoami", "seq": 5, "payload": {}}
        await sfs_client.send_line(self.writer, self.sec.wrap(msg))
        resp = await sfs_client.recv_line(self.reader)
        return self.sec.unwrap(resp)

    def _apply_whoami(self, resp):
        try:
            self.session_user = resp["payload"]["username"]
            self.session_role = resp["payload"]["role"]
            self.status_var.set(
                f"Connected — {self.session_user or '-'} : {self.session_role or '-'}"
            )
        except Exception:
            self.session_user = self.session_role = None

    async def _check_session_key_match(self):
        """Ensure loaded_priv matches logged-in user's pubkey (server truth)."""
        if not self.session_user:
            return False, "Not logged in."
        if not self.loaded_priv:
            return False, "No private key loaded."
        # fetch server pubkey for session user
        msg = {
            "op": "get_pubkey",
            "seq": 77,
            "payload": {"username": self.session_user},
        }
        await sfs_client.send_line(self.writer, self.sec.wrap(msg))
        resp = await sfs_client.recv_line(self.reader)
        resp = self.sec.unwrap(resp)
        if not resp or not resp.get("ok"):
            return False, "Failed to fetch server pubkey."
        server_pub_pem = sfs_client.b64d(resp["payload"]["pubkey_pem_b64"])
        server_pub = sfs_client.load_pem_public_key(server_pub_pem)
        # compare with loaded private's public
        lp = self.loaded_priv.public_key().public_bytes(
            sfs_client.serialization.Encoding.PEM,
            sfs_client.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sp = server_pub.public_bytes(
            sfs_client.serialization.Encoding.PEM,
            sfs_client.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if lp != sp:
            return (
                False,
                f"Loaded private key does not match logged-in user '{self.session_user}'.",
            )
        return True, ""

    # ---------- connection ----------
    def on_connect_clicked(self):
        host = self.host_var.get().strip()
        port = int(self.port_var.get().strip() or "5050")

        async def _connect():
            self.log_print(f"Connecting to {host}:{port} ...")
            self.reader, self.writer = await asyncio.open_connection(host, port)
            self.sec = await sfs_client.cmd_secure(self.reader, self.writer)
            return True

        def _after(res):
            if res:
                self.btn_connect.config(state=tk.DISABLED)
                self.btn_disconnect.config(state=tk.NORMAL)
                self._set_tabs_state(tk.NORMAL)
                self.log_print("Ready.")
                self.status_var.set(f"Connected to {host}:{port}")

        self.run_coro(_connect(), _after)

    def on_disconnect_clicked(self):
        async def _disc():
            try:
                if self.writer and self.sec:
                    await sfs_client.send_line(
                        self.writer,
                        self.sec.wrap({"op": "quit", "seq": 99, "payload": {}}),
                    )
            except Exception:
                pass
            try:
                if self.writer:
                    self.writer.close()
                    await self.writer.wait_closed()
            finally:
                return True

        def _after(_):
            self.reader = self.writer = self.sec = None
            self.session_user = self.session_role = None
            self.status_var.set("Not connected.")
            self.btn_connect.config(state=tk.NORMAL)
            self.btn_disconnect.config(state=tk.DISABLED)
            self._set_tabs_state(tk.DISABLED)
            self._reset_progress()
            self.log_print("Disconnected.")

        self.run_coro(_disc(), _after)

    # ---------- keys/register ----------
    def on_generate_keys(self):
        priv = self.gen_priv_var.get().strip()
        pub = self.gen_pub_var.get().strip()
        if not priv or not pub:
            messagebox.showwarning(
                "Missing", "Select output paths for private and public PEM."
            )
            return
        try:
            sfs_client.gen_rsa_keys(priv, pub)
            self.log_print(f"Generated keys:\n  {priv}\n  {pub}")
            self.reg_pub_var.set(pub)
            self.login_priv_var.set(priv)
            if not self.login_user_var.get().strip():
                self.login_user_var.set(guess_username_from_path(priv))
            if not self.reg_user_var.get().strip():
                self.reg_user_var.set(guess_username_from_path(pub))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_register(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        user = self.reg_user_var.get().strip()
        pub = self.reg_pub_var.get().strip()
        if not user or not pub or not os.path.isfile(pub):
            messagebox.showwarning(
                "Missing", "Provide username and a valid public PEM."
            )
            return

        async def _reg():
            await sfs_client.cmd_register(self.sec, self.reader, self.writer, user, pub)
            return True

        self.run_coro(
            _reg(),
            lambda _: self.log_print(
                f"Register attempted for '{user}'. See response above."
            ),
        )

    # ---------- auth ----------
    def on_load_priv(self):
        path = self.login_priv_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("Missing", "Select a valid private key PEM.")
            return
        try:
            self.loaded_priv = sfs_client.load_pem_private_key(
                open(path, "rb").read(), password=None
            )
            self.log_print(f"Private key loaded: {path}")
            if not self.login_user_var.get().strip():
                self.login_user_var.set(guess_username_from_path(path))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_login(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        if not self.loaded_priv:
            messagebox.showwarning("No key", "Load a private key first.")
            return
        user = self.login_user_var.get().strip()
        if not user:
            messagebox.showwarning("Missing", "Enter username.")
            return

        async def _login():
            await sfs_client.cmd_login(
                self.sec, self.reader, self.writer, user, self.loaded_priv
            )
            resp = await self._whoami_rpc()
            return resp

        def _after(resp):
            if resp:
                self.log_print("<", json.dumps(resp, ensure_ascii=False))
                self._apply_whoami(resp)

        self.run_coro(_login(), _after)

    def on_whoami(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        self.run_coro(
            self._whoami_rpc(),
            lambda r: (
                self.log_print("<", json.dumps(r, ensure_ascii=False)),
                self._apply_whoami(r),
            ),
        )

    # ---------- files ----------
    def _reset_progress(self):
        self.ul_bar["value"] = 0
        self.dl_bar["value"] = 0
        self.ul_label_var.set("Upload: idle")
        self.dl_label_var.set("Download: idle")

    def on_list_files(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return

        async def _lf():
            msg = {"op": "list_files", "seq": 6, "payload": {}}
            await sfs_client.send_line(self.writer, self.sec.wrap(msg))
            resp = await sfs_client.recv_line(self.reader)
            return self.sec.unwrap(resp)

        def _after(resp):
            self.log_print("<", json.dumps(resp, ensure_ascii=False))
            for i in self.files_tree.get_children():
                self.files_tree.delete(i)
            if resp and resp.get("ok"):
                for it in resp["payload"]["files"]:
                    self.files_tree.insert(
                        "",
                        tk.END,
                        values=(
                            it["id"],
                            it["owner"],
                            it["filename"],
                            it["size"],
                            fmt_ts(it["created_at"]),
                        ),
                    )

        self.run_coro(_lf(), _after)

    def _pick_file_row(self):
        sel = self.files_tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a file row first.")
            return None
        vals = self.files_tree.item(sel[0], "values")
        return {
            "id": int(vals[0]),
            "owner": vals[1],
            "filename": vals[2],
            "size": int(vals[3]),
        }

    def on_upload(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        if not self.loaded_priv:
            messagebox.showwarning("No key", "Load a private key first.")
            return

        local = filedialog.askopenfilename(title="Select file to upload")
        if not local:
            return
        remote = os.path.basename(local)

        async def _up():
            # refresh whoami
            resp = await self._whoami_rpc()
            self._apply_whoami(resp)
            ok, err = await self._check_session_key_match()
            if not ok:
                return ("err", err)

            data = open(local, "rb").read()
            total = len(data)
            self.after(0, self.ul_label_var.set, f"Upload: {remote} (preparing...)")
            self.after(0, self.ul_bar.config, {"value": 0})

            digest = sfs_client.sha256_bytes(data)
            sig = self.loaded_priv.sign(
                digest,
                sfs_client.padding.PSS(
                    mgf=sfs_client.padding.MGF1(sfs_client.hashes.SHA256()),
                    salt_length=sfs_client.padding.PSS.MAX_LENGTH,
                ),
                sfs_client.hashes.SHA256(),
            )

            begin = {
                "op": "upload_begin",
                "seq": 8,
                "payload": {
                    "filename": remote,
                    "size": total,
                    "sha256_b64": sfs_client.b64e(digest),
                    "signature_b64": sfs_client.b64e(sig),
                },
            }
            await sfs_client.send_line(self.writer, self.sec.wrap(begin))
            r = self.sec.unwrap(await sfs_client.recv_line(self.reader))
            self.after(0, self.log_print, "<", json.dumps(r, ensure_ascii=False))
            if not r or not r.get("ok"):
                return ("err", r.get("error") if r else "upload_begin failed")
            upid = r["payload"]["upload_id"]

            CHUNK = getattr(sfs_client, "CHUNK", 44 * 1024)
            sent = 0
            idx = 0
            for i in range(0, total, CHUNK):
                chunk = data[i : i + CHUNK]
                msgc = {
                    "op": "upload_chunk",
                    "seq": 9,
                    "payload": {
                        "upload_id": upid,
                        "idx": idx,
                        "data_b64": sfs_client.b64e(chunk),
                    },
                }
                await sfs_client.send_line(self.writer, self.sec.wrap(msgc))
                _ = self.sec.unwrap(await sfs_client.recv_line(self.reader))
                sent += len(chunk)
                idx += 1
                pct = int((sent / total) * 100) if total else 100
                self.after(0, self.ul_bar.config, {"value": pct})
                self.after(0, self.ul_label_var.set, f"Upload: {remote} — {pct}%")

            end = {"op": "upload_end", "seq": 10, "payload": {"upload_id": upid}}
            await sfs_client.send_line(self.writer, self.sec.wrap(end))
            r2 = self.sec.unwrap(await sfs_client.recv_line(self.reader))
            return (
                ("ok", r2)
                if r2 and r2.get("ok")
                else ("err", r2.get("error") if r2 else "upload_end failed")
            )

        def _after(res):
            if not res:
                self.ul_label_var.set("Upload failed.")
                return
            status, info = res
            if status == "ok":
                self.ul_bar["value"] = 100
                fid = info["payload"].get("file_id")
                self.ul_label_var.set(f"Upload complete — file_id={fid}")
                self.log_print("<", json.dumps(info, ensure_ascii=False))
                self.on_list_files()
            else:
                self.ul_label_var.set(f"Upload failed: {info}")
                self.log_print("Upload failed:", info)

        self.run_coro(_up(), _after)

    def on_download(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        row = self._pick_file_row()
        if not row:
            return
        out = filedialog.asksaveasfilename(initialfile=row["filename"])
        if not out:
            return

        async def _dl():
            meta_req = {
                "op": "download_begin",
                "seq": 11,
                "payload": {"file_id": row["id"]},
            }
            await sfs_client.send_line(self.writer, self.sec.wrap(meta_req))
            meta = self.sec.unwrap(await sfs_client.recv_line(self.reader))
            self.after(0, self.log_print, "<", json.dumps(meta, ensure_ascii=False))
            if not meta.get("ok"):
                return ("err", meta.get("error"))

            owner = meta["payload"]["owner"]
            size = int(meta["payload"]["size"])
            sha_ref = meta["payload"]["sha256_b64"]
            sig_ref = meta["payload"]["signature_b64"]

            buf = bytearray()
            recvd = 0
            self.after(0, self.dl_bar.config, {"value": 0})
            self.after(0, self.dl_label_var.set, f"Download: {row['filename']} — 0%")

            while True:
                env = await sfs_client.recv_line(self.reader)
                if env is None:
                    return ("err", "server closed during download")
                msg = self.sec.unwrap(env)
                if msg.get("op") == "download_chunk":
                    chunk = sfs_client.b64d(msg["payload"]["data_b64"])
                    buf.extend(chunk)
                    recvd += len(chunk)
                    if size > 0:
                        pct = int((recvd / size) * 100)
                        self.after(0, self.dl_bar.config, {"value": pct})
                        self.after(
                            0,
                            self.dl_label_var.set,
                            f"Download: {row['filename']} — {pct}%",
                        )
                elif msg.get("op") == "download_end":
                    break

            with open(out, "wb") as f:
                f.write(bytes(buf))
            if sfs_client.b64e(sfs_client.sha256_bytes(bytes(buf))) != sha_ref:
                return ("err", "sha256 mismatch")

            req = {"op": "get_pubkey", "seq": 12, "payload": {"username": owner}}
            await sfs_client.send_line(self.writer, self.sec.wrap(req))
            resp = self.sec.unwrap(await sfs_client.recv_line(self.reader))
            if not resp.get("ok"):
                return ("err", "get_pubkey failed")
            pub = sfs_client.load_pem_public_key(
                sfs_client.b64d(resp["payload"]["pubkey_pem_b64"])
            )
            pub.verify(
                sfs_client.b64d(sig_ref),
                sfs_client.b64d(sha_ref),
                sfs_client.padding.PSS(
                    mgf=sfs_client.padding.MGF1(sfs_client.hashes.SHA256()),
                    salt_length=sfs_client.padding.PSS.MAX_LENGTH,
                ),
                sfs_client.hashes.SHA256(),
            )
            return ("ok", out)

        def _after(res):
            if not res:
                self.log_print("Download failed.")
                return
            status, info = res
            if status == "ok":
                self.dl_bar["value"] = 100
                self.dl_label_var.set(f"Download complete — 100%")
                self.log_print(f"Saved: {info}")
                self.log_print("Integrity & signature verified ✔")
            else:
                self.dl_label_var.set(f"Download failed: {info}")
                self.log_print("Download failed:", info)

        self.run_coro(_dl(), _after)

    def on_delete_file(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        row = self._pick_file_row()
        if not row:
            return

        async def _del():
            # refresh whoami
            resp = await self._whoami_rpc()
            self._apply_whoami(resp)
            # client-side RBAC guard (server still enforces)
            if not (self.session_role == "admin" or row["owner"] == self.session_user):
                return {
                    "type": "error",
                    "op": "delete_file",
                    "ok": False,
                    "error": "forbidden (client-side check)",
                }
            msg = {"op": "delete_file", "seq": 22, "payload": {"file_id": row["id"]}}
            await sfs_client.send_line(self.writer, self.sec.wrap(msg))
            resp = await sfs_client.recv_line(self.reader)
            return self.sec.unwrap(resp)

        def _after(resp):
            self.log_print("<", json.dumps(resp, ensure_ascii=False))
            if resp and resp.get("ok"):
                self.on_list_files()
            else:
                err = (resp and resp.get("error")) or "failed"
                messagebox.showwarning("Delete", f"Delete failed: {err}")

        self.run_coro(_del(), _after)

    # ---------- admin ----------
    def on_list_users(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return

        async def _lu():
            msg = {"op": "list_users", "seq": 20, "payload": {}}
            await sfs_client.send_line(self.writer, self.sec.wrap(msg))
            resp = await sfs_client.recv_line(self.reader)
            return self.sec.unwrap(resp)

        def _after(resp):
            self.log_print("<", json.dumps(resp, ensure_ascii=False))
            for i in self.users_tree.get_children():
                self.users_tree.delete(i)
            if resp and resp.get("ok"):
                for it in resp["payload"]["users"]:
                    self.users_tree.insert(
                        "",
                        tk.END,
                        values=(
                            it["id"],
                            it["username"],
                            it["role"],
                            fmt_ts(it["created_at"]),
                        ),
                    )

        self.run_coro(_lu(), _after)

    def on_set_role(self):
        if not self.sec:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        uname = self.ar_user_var.get().strip()
        role = self.ar_role_var.get().strip()
        if not uname or role not in ("admin", "maintainer", "guest"):
            messagebox.showwarning("Invalid", "Enter username and select a valid role.")
            return

        async def _sr():
            msg = {
                "op": "set_role",
                "seq": 21,
                "payload": {"username": uname, "role": role},
            }
            await sfs_client.send_line(self.writer, self.sec.wrap(msg))
            resp = await sfs_client.recv_line(self.reader)
            return self.sec.unwrap(resp)

        def _after(resp):
            self.log_print("<", json.dumps(resp, ensure_ascii=False))
            if resp and resp.get("ok"):
                self.on_list_users()

        self.run_coro(_sr(), _after)


# ---------- main ----------
if __name__ == "__main__":
    app = App()
    app.mainloop()
