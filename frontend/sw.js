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

const VERSION = 'cs-shell-v10';                // bump on each frontend release
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

// Serve a navigation from cache only if the network is slow.
//
// CRITICAL: key off the page that was actually requested. An earlier version
// hardcoded '/index.html' here, which broke the app badly — an <iframe> load is
// also `mode === 'navigate'`, so the embedded overview frame was served
// index.html, which embeds the same iframe, which was served index.html… the UI
// rendered itself inside itself over and over. Never assume a navigation is the
// top-level document.
async function handleNavigation(req) {
  const path = new URL(req.url).pathname;
  const key = (path === '/' || path === '') ? '/index.html' : path;
  const cache = await caches.open(VERSION);              // may throw -> caught by caller
  const cached = await cache.match(key);
  const net = fromNetwork(new Request(req.url, { cache: 'no-store' }), key);
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

  // Only these two documents are ever served from cache. Anything else — a new
  // page, a redirect, an embedded frame we don't know about — goes straight to
  // the network, so the worst a mistake here can do is nothing at all.
  const SHELL = ['/', '', '/index.html', '/overview-neural.html'];
  const isNav = req.mode === 'navigate' && SHELL.includes(url.pathname);
  const isStatic = STATIC_RE.test(url.pathname);
  if (!isNav && !isStatic) return;                        // /api, /api/ml, POSTs... -> untouched

  // FAIL-SAFE: any error in the cached path falls back to a plain network fetch,
  // so the SW can never break the page — worst case it's a no-op passthrough.
  event.respondWith(
    (isNav ? handleNavigation(req) : handleStatic(req)).catch(() => fetch(req))
  );
});
