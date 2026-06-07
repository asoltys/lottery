#!/usr/bin/env bash
# Stop the regtest stack (engine + regtest bitcoind). Leaves chain + cube storage
# on disk so a later up.sh resumes. Does NOT touch any other bitcoind (e.g. signet).
DD=/tmp/cube-regtest
pkill -x lottery-engine 2>/dev/null || true
bitcoin-cli -datadir=$DD stop 2>/dev/null || true
sleep 2
echo "regtest stack stopped."
