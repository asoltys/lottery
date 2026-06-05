#!/usr/bin/env python3
"""Scoped custody broker for the mainnet lottery arcade.

Runs on the machine that hosts the Bitcoin Core node (desk), talks to the node
ONLY through the dedicated `arcade-main` wallet, and exposes the three narrow
operations the arcade needs. The arcade (on cs) reaches this over a localhost
SSH tunnel with a bearer token, so it never holds the node's RPC credentials and
a compromise of the arcade can never touch any other wallet on the node.

Endpoints (all require `Authorization: Bearer $BROKER_TOKEN`):
  GET  /health
  POST /address            {"label": "<account_key>"}        -> {"address": ...}
  GET  /received?label=..&minconf=1                            -> {"sats": <int>}
  POST /send               {"address","amount_sats","key"}    -> {"txid": ...}

/send is idempotent on "key": a repeated key returns the original txid instead
of broadcasting again (crash-safety against double payouts).

Config via env: BROKER_TOKEN (required), BROKER_PORT (default 9833),
BC_CONTAINER (default "bc"), ARCADE_WALLET (default "arcade-main"),
BROKER_STATE (default ~/.arcade-broker/sends.json).
"""
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = os.environ.get("BROKER_TOKEN", "")
PORT = int(os.environ.get("BROKER_PORT", "9833"))
BC = os.environ.get("BC_CONTAINER", "bc")
WALLET = os.environ.get("ARCADE_WALLET", "arcade-main")
STATE = os.path.expanduser(os.environ.get("BROKER_STATE", "~/.arcade-broker/sends.json"))

_lock = threading.Lock()


def cli(*args):
    """Run bitcoin-cli scoped to the arcade wallet. Wallet is hardcoded; callers
    can never select another wallet."""
    cmd = ["docker", "exec", BC, "bitcoin-cli", f"-rpcwallet={WALLET}", *map(str, args)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "bitcoin-cli error")
    return p.stdout.strip()


def load_sends():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_sends(d):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, STATE)


def sats_to_btc(sats):
    return f"{int(sats) // 100_000_000}.{int(sats) % 100_000_000:08d}"


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        return TOKEN and self.headers.get("Authorization", "") == f"Bearer {TOKEN}"

    def _body(self):
        n = int(self.headers.get("content-length", "0") or "0")
        return json.loads(self.rfile.read(n) or "{}") if n else {}

    def log_message(self, *a):
        pass  # quiet

    def do_GET(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        u = urlparse(self.path)
        try:
            if u.path == "/health":
                h = cli("getblockcount")
                return self._send(200, {"ok": True, "wallet": WALLET, "height": int(h)})
            if u.path == "/received":
                q = parse_qs(u.query)
                label = (q.get("label", [""])[0]).strip()
                minconf = int(q.get("minconf", ["1"])[0])
                if not label:
                    return self._send(400, {"error": "label required"})
                btc = cli("getreceivedbylabel", label, minconf)
                sats = round(float(btc) * 100_000_000)
                return self._send(200, {"sats": sats})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        u = urlparse(self.path)
        try:
            b = self._body()
            if u.path == "/address":
                label = str(b.get("label", "")).strip()
                if not label:
                    return self._send(400, {"error": "label required"})
                addr = cli("getnewaddress", label, "bech32")
                return self._send(200, {"address": addr})
            if u.path == "/send":
                addr = str(b.get("address", "")).strip()
                amount_sats = int(b.get("amount_sats", 0))
                key = str(b.get("key", "")).strip()
                if not addr or amount_sats <= 0 or not key:
                    return self._send(400, {"error": "address, amount_sats, key required"})
                with _lock:
                    sends = load_sends()
                    if key in sends:  # idempotent: never broadcast twice for a key
                        return self._send(200, {"txid": sends[key], "idempotent": True})
                    txid = cli("-named", "sendtoaddress", f"address={addr}", f"amount={sats_to_btc(amount_sats)}")
                    sends[key] = txid
                    save_sends(sends)
                    return self._send(200, {"txid": txid})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})


def main():
    if not TOKEN:
        raise SystemExit("BROKER_TOKEN env is required")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"arcade custody broker on 127.0.0.1:{PORT} wallet={WALLET} container={BC}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
