#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-4173}"
SIM_DEVICE_COUNT="${SIM_DEVICE_COUNT:-8}"
SIM_RATE="${SIM_RATE:-5}"
SIM_ATTACK_PROB="${SIM_ATTACK_PROB:-0.08}"
SIM_SEED="${SIM_SEED:-}"

usage() {
  cat <<'EOF'
Usage: ./start.sh [options]

Options:
  --python PATH          Python interpreter to use (default: python3)
  --backend-port PORT    Backend port (default: 8000)
  --frontend-port PORT   Frontend port (default: 4173)
  --devices N            Number of simulated devices (default: 8)
  --rate F               Average simulated flows/sec (default: 5)
  --attack-prob F        Probability of an attack per flow (default: 0.08)
  --seed N               Simulation seed
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    --backend-port)
      BACKEND_PORT="$2"
      shift 2
      ;;
    --frontend-port)
      FRONTEND_PORT="$2"
      shift 2
      ;;
    --devices)
      SIM_DEVICE_COUNT="$2"
      shift 2
      ;;
    --rate)
      SIM_RATE="$2"
      shift 2
      ;;
    --attack-prob)
      SIM_ATTACK_PROB="$2"
      shift 2
      ;;
    --seed)
      SIM_SEED="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python interpreter not found: $PYTHON_BIN" >&2
  exit 1
fi

cleanup() {
  local pids=("${BACKEND_PID:-}" "${SIM_PID:-}" "${FRONTEND_PID:-}")
  for pid in "${pids[@]}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}

trap cleanup EXIT INT TERM

echo "Starting backend on http://127.0.0.1:${BACKEND_PORT}"
(cd "$ROOT_DIR/backend" && "$PYTHON_BIN" -m uvicorn app.main:app --reload --host 127.0.0.1 --port "$BACKEND_PORT") &
BACKEND_PID=$!

echo "Starting frontend on http://127.0.0.1:${FRONTEND_PORT}"
(cd "$ROOT_DIR/frontend" && "$PYTHON_BIN" -m http.server "$FRONTEND_PORT" --bind 127.0.0.1) &
FRONTEND_PID=$!

echo "Waiting for backend health check..."
backend_ready=false
for _ in {1..30}; do
  if "$PYTHON_BIN" - "$BACKEND_PORT" <<'PY'
import json
import sys
import urllib.request

port = sys.argv[1]
url = f"http://127.0.0.1:{port}/api/health"

try:
    with urllib.request.urlopen(url, timeout=1) as response:
        payload = json.load(response)
    sys.exit(0 if payload.get("status") == "ok" else 1)
except Exception:
    sys.exit(1)
PY
  then
    backend_ready=true
    break
  fi
  sleep 1
done

if [[ "$backend_ready" != true ]]; then
  echo "Backend did not become ready on http://127.0.0.1:${BACKEND_PORT}." >&2
  exit 1
fi

echo "Starting simulator"
SIM_ARGS=(
  --backend "http://127.0.0.1:${BACKEND_PORT}"
  --devices "$SIM_DEVICE_COUNT"
  --rate "$SIM_RATE"
  --attack-prob "$SIM_ATTACK_PROB"
)
if [[ -n "$SIM_SEED" ]]; then
  SIM_ARGS+=(--seed "$SIM_SEED")
fi

(cd "$ROOT_DIR/simulator" && "$PYTHON_BIN" simulate_devices.py "${SIM_ARGS[@]}") &
SIM_PID=$!

echo
echo "All services are running:"
echo "  Backend : http://127.0.0.1:${BACKEND_PORT}/api/health"
echo "  Frontend: http://127.0.0.1:${FRONTEND_PORT}/"
echo "  Simulator: streaming into the backend"
echo
echo "Press Ctrl+C to stop everything."

set +e
wait -n
exit_code=$?
set -e

exit "$exit_code"