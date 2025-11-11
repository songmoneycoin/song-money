#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== [0] Install build prereqs (idempotent)"
sudo apt-get update -y
sudo apt-get install -y \
  build-essential automake autotools-dev libtool pkg-config \
  curl git python3 rsync ca-certificates cmake bison gperf unzip xxd \
  dos2unix

echo "== [1] Sanitize perms & line endings in depends/"
# Ensure common autotools helpers are executable
find depends -type f \( -name config.guess -o -name config.sub -o -name install-sh -o -name compile -o -name missing -o -name depcomp -o -name ltmain.sh \) -print0 \
  | xargs -0 -r chmod +x

# Strip CRLFs that can make /bin/sh choke with 'Syntax error: "|"'
find depends -type f \( -name 'Makefile' -o -name '*.mk' -o -name 'funcs.mk' -o -name 'config.site.in' -o -name 'config.guess' -o -name 'config.sub' \) -print0 \
  | xargs -0 -r dos2unix -q || true

echo "== [2] Build depends (native host)"
# Normalize the host triple (some distros output '-unknown-')
HOST="$(./depends/config.guess | sed 's/-unknown-/-pc-/')"
echo "HOST=$HOST"
make -C depends HOST="$HOST" NO_QT=1 -j"$(nproc)" V=1

echo "== [3] Bootstrap autotools"
export CONFIG_SITE="$ROOT/depends/$HOST/share/config.site"
./autogen.sh

echo "== [4] Configure (link to depends) — headless build"
./configure --prefix="$ROOT/depends/$HOST" \
  --disable-bench --disable-tests --without-gui

echo "== [5] Compile"
make -j"$(nproc)"

echo "== [6] Binaries"
ls -lh src/songmoneyd src/songmoney-cli 2>/dev/null || true
echo "OK"
