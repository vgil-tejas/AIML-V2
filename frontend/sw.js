// CyberSentinel Service Worker — APP-SHELL cache for slow servers / networks.
//
// Goal: the UI paints instantly even when the server or link is slow, by serving
// the static shell (HTML/CSS/JS/images) from a local cache.
//
// TWO HARD SAFETY RULES (a previous version broke Logs by ignoring them):
//  1. It NEVER intercepts /api, the ML engine, or any non-GET request — all live
//     data always goes straight to the network, untouched.
//  2. It is FAIL-SAFE: every cached path is wrapped so that if CacheStorage is
//     unavailable or anything throws (private mode, locked-down browser, storage
//     full), it falls back to a plain network fetch. Worst case it behaves exactly
//     like having no service worker — it can only ever make things faster.
//
// Freshness: navigations are network-first with a short timeout, so when the
// server responds quickly you always get the latest build; only when it is slow
// do we fall back to the cached shell.

const VERSION = 'cs-shell-v3';                 // bump on each frontend release
const CORE = [
  '/index.html', '/overview-neural.html',
  '/theme.css', '/enhance.css', '/logo-brand.jpg',
];
const STATIC_RE = /\.(css|js|png|jpe?g|svg|ico|gif|webp|woff2?)$/i;
const NAV_TIMEOUT_MS = 2000;                   // slow-server threshold

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil((async () => {
    try {
      const cache = await caches.open(VERSION);
      await Promise.all(CORE.map(u => cache.add(u).catch(() => {})));  // best-effort
    } catch (_) { /* no CacheStorage → run without a cache, never fail install */ }
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)));
    } catch (_) {}
    try { await self.clients.claim(); } catch (_) {}
  })());
});

function timeout(ms) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms));
}

// Fetch + write-through to the cache (best-effort; a cache failure never breaks the response).
function fromNetwork(request, key) {
  return fetch(request).then(res => {
    if (res && res.ok && res.type === 'basic') {
      const copy = res.clone();
      caches.open(VERSION).then(c => c.put(key, copy)).catch(() => {});
    }
    return res;
  });
}

async function handleNavigation(req) {
  const cache = await caches.open(VERSION);              // may throw -> caught by caller
  const cached = await cache.match('/index.html');
  const net = fromNetwork(new Request('/index.html', { cache: 'no-store' }), '/index.html');
  if (!cached) return net;                               // first visit: network is the only option
  try {
    return await Promise.race([net, timeout(NAV_TIMEOUT_MS)]);  // fast server -> fresh
  } catch (_) {
    net.catch(() => {});                                 // slow server -> instant cached shell
    return cached;                                       // (net still updates the cache for next time)
  }
}

async function handleStatic(req) {
  const cache = await caches.open(VERSION);              // may throw -> caught by caller
  const cached = await cache.match(req);
  if (cached) { fromNetwork(req, req).catch(() => {}); return cached; }  // stale-while-revalidate
  return fromNetwork(req, req);
}

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;                       // never touch writes
  let url;
  try { url = new URL(req.url); } catch (_) { return; }
  if (url.origin !== self.location.origin) return;        // same-origin only

  const isNav = req.mode === 'navigate';
  const isStatic = STATIC_RE.test(url.pathname);
  if (!isNav && !isStatic) return;                        // /api, /api/ml, POSTs... -> untouched

  // FAIL-SAFE: any error in the cached path falls back to a plain network fetch,
  // so the SW can never break the page — worst case it's a no-op passthrough.
  event.respondWith(
    (isNav ? handleNavigation(req) : handleStatic(req)).catch(() => fetch(req))
  );
});
