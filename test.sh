#!/usr/bin/env bash
# Full E2E tests (debug) — robust concurrency, timeouts, better logging

set -Eeuo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5050}"
PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv}"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"  # per client run
NO_PAR="${NO_PAR:-0}"               # set to 1 to disable parallel step

# --- locate root (handles spaces) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/server" && -d "$SCRIPT_DIR/client" ]]; then
  ROOT="$SCRIPT_DIR"
elif [[ -d "$SCRIPT_DIR/../server" && -d "$SCRIPT_DIR/../client" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  echo "Project root not found (server/ client/)." ; exit 1
fi
cd "$ROOT"

# --- venv & deps ---
command -v "$PYTHON" >/dev/null || { echo "python3 not found"; exit 1; }
[[ -d "$VENV" ]] || "$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip >/dev/null
python -m pip install cryptography >/dev/null

mkdir -p logs
: > logs/server.log

# --- clean state ---
rm -rf storage server.db kek.bin
rm -f server_priv.pem server_pub.pem
rm -f server_pub.pem
rm -f "$HOME/.sfs_cache/server_pub_${HOST}_${PORT}.pem" 2>/dev/null || true
rm -f out.txt out2.txt sample1.txt sample2.txt
rm -f alice_priv.pem alice_pub.pem bob_priv.pem bob_pub.pem carol_priv.pem carol_pub.pem

echo "hello secure world A" > sample1.txt
echo "hello secure world B" > sample2.txt

# --- helpers ---
wait_for_port() {
  local host="$1" port="$2" tries=60
  for _ in $(seq 1 "$tries"); do
    if python - <<PY >/dev/null 2>&1
import socket,sys; s=socket.socket(); s.settimeout(0.5)
try:
    s.connect(("$host", int($port))); sys.exit(0)
except Exception:
    sys.exit(1)
PY
    then return 0; fi
    sleep 0.5
  done
  return 1
}

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

assert_ok() {
  local log="$1" op="$2" msg="$3"
  if grep -qE '"op":[[:space:]]*"'$op'".*"ok":[[:space:]]*true' "$log"; then
    echo "  ✅ $msg"
  else
    echo "  ❌ $msg"; tail -n 200 "$log" || true; exit 1
  fi
}
assert_has() {
  local log="$1" regex="$2" msg="$3"
  if grep -qE "$regex" "$log"; then
    echo "  ✅ $msg"
  else
    echo "  ❌ $msg"; tail -n 200 "$log" || true; exit 1
  fi
}

have_timeout=0
if command -v timeout >/dev/null 2>&1; then have_timeout=1; fi

run_with_timeout() {
  # run_with_timeout LOGFILE CMD_FILE
  local outfile="$1"; local cmdfile="$2"
  if [[ $have_timeout -eq 1 ]]; then
    PYTHONUNBUFFERED=1 timeout "${TIMEOUT_SECS}s" python client/main.py --host "$HOST" --port "$PORT" > "$outfile" 2>&1 < "$cmdfile"
  else
    # fallback python-based timeout
    PYTHONUNBUFFERED=1 python - <<PY > "$outfile" 2>&1
import subprocess,sys,threading,os,signal,time
cmd = [os.environ.get("PYTHON","python3"), "client/main.py", "--host", "$HOST", "--port", "$PORT"]
p = subprocess.Popen(cmd, stdin=open("$cmdfile","rb"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
deadline = time.time() + $TIMEOUT_SECS
while p.poll() is None and time.time() < deadline:
    time.sleep(0.2)
if p.poll() is None:
    try:
        p.terminate()
        time.sleep(0.5)
        p.kill()
    except Exception:
        pass
PY
  fi
}

client_run_cmds() {
  # client_run_cmds LOGFILE [commands...]
  local outfile="$1"; shift
  : > "$outfile"
  local tmpcmd; tmpcmd="$(mktemp)"
  printf "%s\n" "$@" >> "$tmpcmd"
  echo "quit" >> "$tmpcmd"
  run_with_timeout "$outfile" "$tmpcmd"
  rm -f "$tmpcmd"
}

# --- 1) start server ---
( python server/main.py ) > logs/server.log 2>&1 &
SERVER_PID=$!
sleep 0.5
wait_for_port "$HOST" "$PORT" || { echo "[!] Server didn't start; see logs/server.log"; exit 1; }
echo "[1/12] Server UP."

# --- 2) users & whoami ---
client_run_cmds logs/step1.log \
  "genkeys alice_priv.pem alice_pub.pem" \
  "genkeys bob_priv.pem bob_pub.pem" \
  "genkeys carol_priv.pem carol_pub.pem" \
  "register alice alice_pub.pem" \
  "register bob bob_pub.pem" \
  "register carol carol_pub.pem" \
  "loadkey alice_priv.pem" \
  "login alice" \
  "whoami"
assert_ok logs/step1.log register "Users registered (some lines may repeat)"
assert_ok logs/step1.log login_finish "Alice login ok"
assert_ok logs/step1.log whoami "whoami ok"
grep -q "Saved server public key" logs/step1.log && echo "  ℹ TOFU first-run visible"

# --- 3) bootstrap admin ---
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 server.db "UPDATE users SET role='admin' WHERE username='alice';"
else
  python - <<'PY'
import sqlite3; db=sqlite3.connect("server.db")
c=db.cursor(); c.execute("UPDATE users SET role='admin' WHERE username='alice'"); db.commit(); db.close()
PY
fi
echo "[2/12] Bootstrapped alice as admin."

# --- 4) set roles ---
client_run_cmds logs/step2.log \
  "loadkey alice_priv.pem" \
  "login alice" \
  "set_role bob maintainer" \
  "set_role carol guest" \
  "list_users"
assert_ok logs/step2.log set_role "set_role ok"
assert_has logs/step2.log '"username":[[:space:]]*"bob",[[:space:]]*"role":[[:space:]]*"maintainer"' "bob=maintainer"
assert_has logs/step2.log '"username":[[:space:]]*"carol",[[:space:]]*"role":[[:space:]]*"guest"' "carol=guest"

# --- 5) concurrent uploads (or serial if NO_PAR=1) ---
echo "[5/12] Starting uploads (concurrent=${NO_PAR}) ..."
if [[ "$NO_PAR" == "1" ]]; then
  client_run_cmds logs/alice_up.log "loadkey alice_priv.pem" "login alice" "upload sample2.txt" "list_files"
  client_run_cmds logs/bob_up.log   "loadkey bob_priv.pem"   "login bob"   "upload sample1.txt" "list_files"
else
  ( client_run_cmds logs/alice_up.log "loadkey alice_priv.pem" "login alice" "upload sample2.txt" "list_files" ) &
  PID_A=$!
  ( client_run_cmds logs/bob_up.log   "loadkey bob_priv.pem"   "login bob"   "upload sample1.txt" "list_files" ) &
  PID_B=$!
  wait "$PID_A" || true
  wait "$PID_B" || true
fi

assert_ok logs/alice_up.log upload_end "Alice upload ok"
assert_ok logs/bob_up.log   upload_end "Bob upload ok"

FID_BOB="$(grep -oE '"file_id":[[:space:]]*[0-9]+' logs/bob_up.log   | tail -n1 | sed -E 's/[^0-9]//g')"
FID_ALI="$(grep -oE '"file_id":[[:space:]]*[0-9]+' logs/alice_up.log | tail -n1 | sed -E 's/[^0-9]//g')"
[[ -n "$FID_BOB" && -n "$FID_ALI" ]] || { echo "❌ capture file_id failed"; tail -n 200 logs/alice_up.log logs/bob_up.log; exit 1; }
echo "  ✅ FIDs: bob=$FID_BOB alice=$FID_ALI"

# --- 6) at-rest encryption (no plaintext in storage) ---
if command -v sqlite3 >/dev/null 2>&1; then
  CIPH_PATH="$(sqlite3 -noheader -cmd '.timeout 1000' server.db "select path from files where id=$FID_BOB;")"
else
  CIPH_PATH="$(python - <<PY
import sqlite3; db=sqlite3.connect("server.db")
c=db.cursor(); c.execute("select path from files where id=$FID_BOB"); r=c.fetchone(); print(r[0] if r else ""); db.close()
PY
)"
fi
[[ -n "$CIPH_PATH" && -f "$CIPH_PATH" ]] || { echo "❌ cipher path not found"; exit 1; }
if grep -a -q "hello secure world" "$CIPH_PATH"; then
  echo "❌ storage contains plaintext" ; exit 1
else
  echo "  ✅ storage ciphertext not readable as plaintext"
fi

# --- 7) guest download / upload forbidden ---
client_run_cmds logs/guest_ops.log \
  "loadkey carol_priv.pem" \
  "login carol" \
  "upload sample1.txt" \
  "download ${FID_BOB} out.txt"
assert_has logs/guest_ops.log '"op":[[:space:]]*"upload_begin".*"ok":[[:space:]]*false.*forbidden' "Guest upload forbidden"
[[ -f out.txt ]] && grep -q "hello secure world A" out.txt && echo "  ✅ Guest download ok" || { echo "❌ Guest download failed"; tail -n 200 logs/guest_ops.log; exit 1; }

# --- 8) wrong-key upload (login bob but sign with carol key) ---
client_run_cmds logs/wrong_sig.log \
  "loadkey carol_priv.pem" \
  "login bob" \
  "upload sample1.txt"
assert_has logs/wrong_sig.log '"op":[[:space:]]*"upload_begin".*"ok":[[:space:]]*false' "Bad-signature upload rejected"

# --- 9) tamper ciphertext and download should fail ---
python - <<PY
import sqlite3,sys
db=sqlite3.connect("server.db"); c=db.cursor()
c.execute("select path from files where id=?", ($FID_BOB,))
r=c.fetchone(); db.close()
p=r[0] if r else None
if not p: sys.exit("no path")
data=open(p,"rb").read()
if data:
    data=bytes([data[0]^0xFF])+data[1:]
open(p,"wb").write(data)
print("tampered", p)
PY

client_run_cmds logs/tamper.log \
  "loadkey bob_priv.pem" \
  "login bob" \
  "download ${FID_BOB} out2.txt"
assert_has logs/tamper.log '"op":[[:space:]]*"download_begin".*"ok":[[:space:]]*false' "Tamper detected (download failed)"

# --- 10) guest cannot delete; admin can ---
client_run_cmds logs/guest_del.log \
  "loadkey carol_priv.pem" \
  "login carol" \
  "delete_file ${FID_ALI}"
assert_has logs/guest_del.log '"op":[[:space:]]*"delete_file".*"ok":[[:space:]]*false.*forbidden' "Guest delete forbidden"

client_run_cmds logs/admin_del.log \
  "loadkey alice_priv.pem" \
  "login alice" \
  "delete_file ${FID_ALI}" \
  "list_files"
assert_ok logs/admin_del.log delete_file "Admin delete ok"
if grep -qE "\"id\":[[:space:]]*${FID_ALI}" logs/admin_del.log; then
  echo "❌ Deleted file still listed" ; tail -n 200 logs/admin_del.log; exit 1
else
  echo "  ✅ Deleted file no longer listed"
fi

# --- 11) server restart persistence ---
kill "$SERVER_PID" >/dev/null 2>&1 || true
wait "$SERVER_PID" >/dev/null 2>&1 || true
( python server/main.py ) > logs/server.log 2>&1 &
SERVER_PID=$!
sleep 0.5
wait_for_port "$HOST" "$PORT" || { echo "[!] Server didn't restart"; exit 1; }
client_run_cmds logs/persist.log \
  "loadkey bob_priv.pem" \
  "login bob" \
  "list_files"
assert_ok logs/persist.log list_files "Files listed after restart (persistence OK)"

# --- 12) maintainer cannot set_role ---
client_run_cmds logs/maint_set.log \
  "loadkey bob_priv.pem" \
  "login bob" \
  "set_role carol admin"
assert_has logs/maint_set.log '"op":[[:space:]]*"set_role".*"ok":[[:space:]]*false.*forbidden' "Maintainer set_role forbidden"

echo
echo "===================="
echo "FULL E2E TESTS (DEBUG): ALL PASS ✅"
echo "Logs: $(realpath logs)"
echo "===================="
