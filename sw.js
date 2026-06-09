// Cube Lottery service worker — the operator-gone safety net.
//
// Why this exists: a player's only trustless exit is to broadcast their pre-signed
// unroll and CSV-sweep their own VTXO leaf with just their key. That code lives in
// the app shell (index.html + bundle.js). If the operator vanishes, the server that
// serves the shell is gone too — so we keep our OWN copy of the shell in the Cache
// API. With this SW installed, opening lotto.adamsoltys.com loads the cached app
// even with the server dead, and the player can still run "Force exit" (which then
// broadcasts via the public mempool API — see app.mjs doForceExit).
//
// Strategy: network-first for the shell (normal use is always fresh, so the live
// index/bundle stay in lockstep), with a cache fallback only when the network is
// unreachable. API/WS traffic is never intercepted — those need the live server.

const VERSION = 'e1d69bff'; // stamped with the bundle hash by build.sh
const CACHE = 'cube-shell-' + VERSION;
// The shell we keep offline. The hashed bundle URL is added at runtime (we can't
// know ?v=<hash> at install time); precache the entry points we do know.
const SHELL = ['/', '/manifest.webmanifest'];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE).then((c) => Promise.allSettled(SHELL.map((u) => c.add(u)))),
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k.startsWith('cube-shell-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Is this a request for the app shell (the thing we must be able to serve offline)?
function isShell(url, req) {
  if (url.origin !== self.location.origin) return false;
  if (req.mode === 'navigate') return true;            // any page load
  if (url.pathname === '/' || url.pathname === '/index.html') return true;
  if (url.pathname === '/bundle.js') return true;       // incl. ?v=<hash>
  if (url.pathname === '/manifest.webmanifest') return true;
  return false;
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;                     // POSTs (api) — live only
  const url = new URL(req.url);
  // Never touch the live API / websockets — they have no meaning offline.
  if (url.pathname.startsWith('/api/') || url.pathname === '/ws' || url.pathname === '/cosign') return;
  if (!isShell(url, req)) return;

  // Network-first: serve fresh when online, refresh the cached copy, fall back to
  // the cached shell (or cached '/') when the server is unreachable.
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(async () => {
        const c = await caches.open(CACHE);
        return (await c.match(req)) || (await c.match('/')) || (await c.match('/index.html')) ||
          new Response('offline', { status: 503, statusText: 'offline' });
      }),
  );
});
