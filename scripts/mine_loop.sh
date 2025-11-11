# ~/songmoney/scripts/mine_loop.sh
#!/usr/bin/env bash
set -euo pipefail

CLI="${CLI:-$HOME/songmoney/src/songmoney-cli}"
NETFLAG="${NETFLAG:--regtest}"        # change to "" for mainnet or "-testnet" for testnet
BLOCKS="${BLOCKS:-1}"                 # how many blocks to find this run
MAXTRIES="${MAXTRIES:-2000000000}"    # raise if needed
SLEEP="${SLEEP:-0.2}"                 # delay between attempts

addr="$($CLI $NETFLAG getnewaddress "" bech32 2>/dev/null || true)"
if [ -z "$addr" ]; then
  echo "No address yet; starting daemon or unlocking wallet may be needed."
  exit 1
fi
echo "Mining to: $addr ($NETFLAG) — target $BLOCKS blocks, maxtries=$MAXTRIES"

found=0
while [ "$found" -lt "$BLOCKS" ]; do
  # ask for 1 block each time with big maxtries
  out="$($CLI $NETFLAG generatetoaddress 1 "$addr" "$MAXTRIES" 2>/dev/null || true)"
  # extract the first hash if present without jq
  hash="$(echo "$out" | sed -n 's/^[[:space:]]*"\([0-9a-f]\{64\}\)".*$/\1/p' | head -n1)"
  if [ -n "$hash" ]; then
    found=$((found+1))
    echo "✅ Found block $found/$BLOCKS: $hash"
  else
    printf "."
    sleep "$SLEEP"
  fi
done
echo
echo "Done."
