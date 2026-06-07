#!/usr/bin/env bash
# Restore a named regtest fixture (overwrites the live chain + cube storage).
# Stops the stack first. Run regtest/up.sh afterward to start from that state.
#
# Usage:  regtest/restore.sh <name>
set -e
NAME="${1:?usage: restore.sh <name>}"
DD=/tmp/cube-regtest
SRC="$(cd "$(dirname "$0")" && pwd)/fixtures/$NAME"
[ -d "$SRC" ] || { echo "no such fixture: $NAME"; exit 1; }

pkill -x lottery-engine 2>/dev/null || true
bitcoin-cli -datadir=$DD stop 2>/dev/null || true
sleep 3

rm -rf "$DD"; cp -r "$SRC/bitcoin" "$DD"
rm -rf "$HOME/cube/storage/regtest"
[ -d "$SRC/cube-storage" ] && cp -r "$SRC/cube-storage" "$HOME/cube/storage/regtest" || true
echo "restored fixture '$NAME'. now: CUBE_ENGINE_NSEC=... regtest/up.sh"
