// CyberSentinel Service Worker — RETIRED.
//
// The dashboard is now behind a login gate (see backend/auth.py + nginx). An
// app-shell cache fights that gate: it would serve the cached dashboard from the
// browser without ever contacting the server, so the login page never appears.
//
// This file is now a KILL-SWITCH. Any browser still running an old cached
// service worker will fetch this, which then: deletes every cache, unregisters
// itself, and reloads open tabs so they re-fetch from the network and hit the
// login gate. After that, no service worker runs and every request goes straight
// to the server — deterministic, always gated.

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    // 1) wipe all caches (old dashboard shell, css, images…)
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map(k => caches.delete(k)));
    } catch (_) {}
    // 2) take control, then unregister self
    try { await self.clients.claim(); } catch (_) {}
    try { await self.registration.unregister(); } catch (_) {}
    // 3) reload any open tab once so it re-requests '/' from the network
    //    (the network now redirects an unauthenticated visitor to /login.html)
    try {
      const tabs = await self.clients.matchAll({ type: 'window' });
      tabs.forEach(c => { try { c.navigate(c.url); } catch (_) {} });
    } catch (_) {}
  })());
});

// No fetch handler: nothing is intercepted, everything goes to the network.
