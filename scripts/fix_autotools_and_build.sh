#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
echo "== [0] Install prereqs"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y autoconf automake libtool pkg-config dos2unix build-essential

echo "== [1] Normalize line endings & perms"
# CRLF → LF (prevents /bin/sh parse errors)
find . -type f \( -name "*.sh" -o -name "configure" -o -name "config.guess" -o -name "config.sub" -o -name "*.mk" -o -name "Makefile" -o -name "funcs.mk" -o -name "config.site.in" \) \
  -print0 | xargs -0 -r dos2unix -q || true

# Make common helpers executable
chmod +x autogen.sh || true
find . -type f \( -name "*.sh" -o -name "configure" -o -name "install-sh" -o -name "missing" -o -name "depcomp" -o -name "compile" -o -name "ltmain.sh" -o -name "config.guess" -o -name "config.sub" \) \
  -exec chmod +x {} \; 2>/dev/null || true

echo "== [2] Remove ACLOCAL_AMFLAGS (conflicts with AC_CONFIG_MACRO_DIRS)"
# Kill any ACLOCAL_AMFLAGS lines anywhere (idempotent; keeps a .bak once)
grep -R --line-number --no-messages '^ACLOCAL_AMFLAGS' . || true
find . -maxdepth 2 -name 'Makefile.am' -print0 | while IFS= read -r -d '' f; do
  sed -i.bak '/^ACLOCAL_AMFLAGS[[:space:]]*=.*/d' "$f"
done

echo "== [3] Ensure macro dir & pkg.m4"
mkdir -p build-aux/m4
# Vendor pkg.m4 so autoreconf finds PKG_CHECK_MODULES even without system aclocal paths
if [ -f /usr/share/aclocal/pkg.m4 ]; then
  cp -f /usr/share/aclocal/pkg.m4 build-aux/m4/pkg.m4
fi

echo "== [4] Clean stale caches"
rm -rf autom4te.cache

echo "== [5] (Optional) build depends to get CONFIG_SITE"
HOST=""
if [ -x depends/config.guess ]; then
  HOST="$(./depends/config.guess | sed 's/-unknown-/-pc-/')"
fi

if [ -n "$HOST" ] && [ -f "depends/$HOST/share/config.site" ]; then
  export CONFIG_SITE="$ROOT/depends/$HOST/share/config.site"
  echo "Using CONFIG_SITE=$CONFIG_SITE"
fi

echo "== [6] autoreconf"
./autogen.sh

echo "== [7] configure"
CFG_PREFIX=""
if [ -n "$HOST" ] && [ -d "depends/$HOST" ]; then
  CFG_PREFIX="--prefix=$ROOT/depends/$HOST"
fi
./configure $CFG_PREFIX --disable-tests --disable-bench --without-gui

echo "== [8] build"
make -j"$(nproc)"

echo "== [9] binaries (if built)"
ls -lh src/songmoneyd src/songmoney-cli 2>/dev/null || true
echo "OK"
