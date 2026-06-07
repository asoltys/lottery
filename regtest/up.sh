#!/usr/bin/env bash
# Bring up the regtest stack for the non-custodial covenant demo/tests:
#   - a local regtest bitcoind (datadir /tmp/cube-regtest, wallet 'cube', funded)
#   - the lottery-engine + arcade attached, on http://127.0.0.1:8090/
#
# Requires CUBE_ENGINE_NSEC whose pubkey matches the baked REGTEST_ENGINE_PUBLIC_KEY
# in cube (see regtest/README.md — bring-up bakes your own regtest key locally).
#
# Usage:  CUBE_ENGINE_NSEC=nsec1... regtest/up.sh
set -e
DD=/tmp/cube-regtest
NSEC="${CUBE_ENGINE_NSEC:?set CUBE_ENGINE_NSEC (pubkey must match baked REGTEST_ENGINE_PUBLIC_KEY)}"
ENGINE_BIN=/home/adam/lottery/server/target/debug/lottery-engine

# 1) bitcoind (daemonized — survives this shell)
if ! bitcoin-cli -datadir=$DD getblockcount >/dev/null 2>&1; then
  mkdir -p "$DD"
  [ -f "$DD/bitcoin.conf" ] || cat > "$DD/bitcoin.conf" <<CONF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
rpcuser=cube
rpcpassword=cube
[regtest]
rpcport=18443
rpcbind=127.0.0.1
CONF
  bitcoind -datadir="$DD" -daemon
fi
bitcoin-cli -datadir=$DD -rpcwait getblockcount >/dev/null
bitcoin-cli -datadir=$DD -named createwallet wallet_name=cube load_on_startup=true >/dev/null 2>&1 \
  || bitcoin-cli -datadir=$DD -named loadwallet filename=cube load_on_startup=true >/dev/null 2>&1 || true
H=$(bitcoin-cli -datadir=$DD getblockcount)
if [ "$H" -lt 101 ]; then
  ADDR=$(bitcoin-cli -datadir=$DD -rpcwallet=cube getnewaddress)
  bitcoin-cli -datadir=$DD -rpcwallet=cube generatetoaddress $((101 - H)) "$ADDR" >/dev/null
fi
echo "bitcoind up: height $(bitcoin-cli -datadir=$DD getblockcount), balance $(bitcoin-cli -datadir=$DD -rpcwallet=cube getbalance)"

# 2) engine + arcade. stdin is held open with a pipe (the engine CLI reads stdin;
# a TTY isn't needed). setsid detaches it so it survives this shell.
pkill -x lottery-engine 2>/dev/null || true
sleep 1
cd /home/adam/cube
setsid bash -c "tail -f /dev/null | CUBE_ENGINE_NSEC=$NSEC CUBE_ARCADE_ASSETS=/home/adam/lottery CUBE_COVENANT_STATE=$DD/covenant.json $ENGINE_BIN archival regtest engine http://127.0.0.1:18443 cube cube false > /tmp/engine.log 2>&1" &
echo "engine starting → http://127.0.0.1:8090/  (logs: tail -f /tmp/engine.log)"
