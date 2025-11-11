#!/usr/bin/env bash
# Auto-miner loop for Songmoney
# Env knobs:
#   CLI=./songmoney-cli        # path + RPC args (e.g. "./songmoney-cli -rpcuser=.. -rpcpassword=..")
#   METHOD=auto                # auto | generate | generatetoaddress
#   ADDRESS=                   # only needed if METHOD=generatetoaddress (or when auto falls back)
#   BATCH=1                    # blocks per call
#   INTERVAL=0.1               # seconds to sleep after success
#   MAX_BACKOFF=30             # seconds, cap on exponential backoff
#   ARGS=                      # extra args (legacy; prefer embedding into CLI)

set -u -o pipefail

CLI="${CLI:-./songmoney-cli}"
METHOD="${METHOD:-auto}"
ADDRESS="${ADDRESS:-}"
BATCH="${BATCH:-1}"
INTERVAL="${INTERVAL:-0.1}"
MAX_BACKOFF="${MAX_BACKOFF:-30}"
ARGS="${ARGS:-}"

rpc() {
  # shellcheck disable=SC2086
  ${CLI} ${ARGS} "$@"
}

log() { printf '[%(%F %T)T] %s\n' -1 "$*"; }

# Graceful exit
trap 'echo; log "Caught signal, exiting."; exit 0' INT TERM

# Preflight: wait for daemon
log "Waiting for songmoneyd RPC..."
until out="$(rpc getblockcount 2>&1)"; do
  log "RPC not ready: $out"
  sleep 2
done
log "RPC ready. Height: $out"
backoff=1

# Helper: ensure ADDRESS if we need generatetoaddress
ensure_address() {
  if [[ -z "$ADDRESS" || "$ADDRESS" == "auto" ]]; then
    addr="$(rpc getnewaddress 2>/dev/null || true)"
    if [[ -n "$addr" ]]; then ADDRESS="$addr"; else return 1; fi
  fi
  return 0
}

# Main loop
while true; do
  if [[ "$METHOD" == "generate" || "$METHOD" == "auto" ]]; then
    if out="$(rpc generate "$BATCH" 2>&1)"; then
      log "Mined via generate: $out"
      backoff=1
      sleep "$INTERVAL"
      continue
    else
      if [[ "$METHOD" == "auto" && ( "$out" == *"Method not found"* || "$out" == *"-32601"* ) ]]; then
        log "'generate' not supported; falling back to 'generatetoaddress'."
        METHOD="generatetoaddress"
      else
        log "generate error: $out"
      fi
    fi
  fi

  if [[ "$METHOD" == "generatetoaddress" ]]; then
    if ! ensure_address; then
      log "Need ADDRESS for generatetoaddress (set ADDRESS=... or enable wallet)."
    else
      if out="$(rpc generatetoaddress "$BATCH" "$ADDRESS" 2>&1)"; then
        log "Mined to $ADDRESS: $out"
        backoff=1
        sleep "$INTERVAL"
        continue
      else
        log "generatetoaddress error: $out"
      fi
    fi
  fi

  # Backoff on any failure
  sleep "$backoff"
  if (( backoff < MAX_BACKOFF )); then
    backoff=$(( backoff * 2 ))
    (( backoff > MAX_BACKOFF )) && backoff=$MAX_BACKOFF
  fi
done
