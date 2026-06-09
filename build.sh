#!/usr/bin/env bash
# Bundle the browser client (app.mjs + noble deps) into bundle.js, then stamp a
# content hash onto the <script src> in index.html so browsers never serve a
# stale bundle against fresh HTML (cache-busting via a never-before-seen URL).
set -e
cd "$(dirname "$0")"

npx esbuild app.mjs --bundle --format=esm --minify --outfile=bundle.js

HASH=$(sha256sum bundle.js | cut -c1-8)
sed -i -E "s|src=\"/bundle\.js(\?v=[0-9a-f]+)?\"|src=\"/bundle.js?v=${HASH}\"|" index.html
echo "stamped bundle.js?v=${HASH} into index.html"

# Stamp the same hash as the service-worker cache version, so every deploy ships a
# byte-different sw.js → the browser detects an update and re-caches the new shell.
sed -i -E "s|const VERSION = '[^']*';|const VERSION = '${HASH}';|" sw.js
echo "stamped service worker VERSION=${HASH} into sw.js"
