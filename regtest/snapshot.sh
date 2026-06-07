#!/usr/bin/env bash
# Snapshot the regtest state (bitcoin chain+wallet + cube engine storage +
# covenant pointer) into a named fixture, so tests can restore a known scenario
# (e.g. a pre-funded covenant) instead of rebuilding it. Stops the stack first
# for a consistent copy.
#
# Usage:  regtest/snapshot.sh <name>
set -e
NAME="${1:?usage: snapshot.sh <name>}"
DD=/tmp/cube-regtest
DEST="$(cd "$(dirname "$0")" && pwd)/fixtures/$NAME"

pkill -x lottery-engine 2>/dev/null || true
bitcoin-cli -datadir=$DD stop 2>/dev/null || true
sleep 3

rm -rf "$DEST"; mkdir -p "$DEST"
cp -r "$DD" "$DEST/bitcoin"
[ -d "$HOME/cube/storage/regtest" ] && cp -r "$HOME/cube/storage/regtest" "$DEST/cube-storage" || true
echo "snapshot '$NAME' -> $DEST ($(du -sh "$DEST" | cut -f1))"
echo "restart with: CUBE_ENGINE_NSEC=... regtest/up.sh"
