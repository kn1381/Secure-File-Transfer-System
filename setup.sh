#!/usr/bin/env bash
# Setup & run Secure File Server + (CLI|GUI) client without changing code
# Works on Linux/macOS with bash

set -Eeuo pipefail

# -------- config (override with env or flags) --------
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5050}"
MODE="${MODE:-cli}"   # cli | gui

usage() {
  cat <<EOF
Usage: $0 [--host HOST] [--port PORT] [--cli|--gui]
Environment vars also supported: HOST, PORT, MODE
Examples:
  $0 --gui
  HOST=0.0.0.0 PORT=6060 MODE=cli $0
EOF
}

# parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --cli)  MODE="cli"; shift;;
    --gui)  MODE="gui"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

# -------- locate project root --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Allow running from root or from scripts/
if [[ -d "$SCRIPT_DIR/server" && -d "$SCRIPT_DIR/client" ]]; then
  ROOT="$SCRIPT_DIR"
elif [[ -d "$SCRIPT_DIR/../server" && -d "$SCRIPT_DIR/../client" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  echo "Cannot locate project root (server/ and client/)."; exit 1
fi

cd "$ROOT"

# -------- sanity checks --------
[[ -f server/main.py ]] || { echo "Missing server/main.py"; exit 1; }
[[ -f client/main.py ]] || { echo "Missing client/main.py"; exit 1; }

# pick python
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python3 not found in PATH"; exit 1
fi

# -------- venv & deps --------
VENV="${VENV:-.venv}"
if [[ ! -d "$VENV" ]]; then
  "$PYTHON" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip >/dev/null
python -m pip install cryptography >/dev/null

# -------- helpers --------
wait_for_port() {
  local host="$1" port="$2" tries=60
  for i in $(seq 1 $tries); do
    if python - <<PY >/dev/null 2>&1
import socket,sys; s=socket.socket(); s.settimeout(0.5)
try:
    s.connect(("$host", int($port))); sys.exit(0)
except Exception:
    sys.exit(1)
PY
    then
      return 0
    fi
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

# -------- start server --------
mkdir -p logs
: > logs/server.log
echo "[*] Starting server on $HOST:$PORT ..."
# run from ROOT so server generates keys and storage here
( cd "$ROOT" && python server/main.py ) > logs/server.log 2>&1 &
SERVER_PID=$!
sleep 0.5

if ! wait_for_port "$HOST" "$PORT"; then
  echo "[!] Server didn't start on $HOST:$PORT; see logs/server.log"
  exit 1
fi
echo "[✓] Server is up. Logs: logs/server.log"

# -------- run client (CLI or GUI) --------
if [[ "$MODE" == "gui" ]]; then
  if [[ ! -f gui_client.py ]]; then
    echo "[!] gui_client.py not found at project root. Falling back to CLI."
    MODE="cli"
  fi
fi

if [[ "$MODE" == "gui" ]]; then
  echo "[*] Launching GUI client ..."
  python gui_client.py
else
  echo "[*] Launching interactive CLI client ..."
  echo "(Tip) In client: genkeys / register / loadkey / login / whoami"
  python client/main.py --host "$HOST" --port "$PORT"
fi
