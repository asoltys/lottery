#!/usr/bin/env bash
# Bundle the browser client (app.mjs + noble deps) into bundle.js.
npx esbuild app.mjs --bundle --format=esm --minify --outfile=bundle.js
