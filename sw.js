// Service Worker — Disfrute de la vida para siempre
// Estrategia:
//   - App shell (HTML/manifest/iconos): network-first con fallback a cache
//   - Lecciones .md y recursos CDN: stale-while-revalidate (cache-first con
//     actualización en segundo plano)

const CACHE_VERSION = 'v1';
const CACHE_NAME = `estudio-biblia-${CACHE_VERSION}`;

const CORE_ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon.svg',
];

const CDN_ASSETS = [
  'https://cdn.tailwindcss.com',
  'https://cdn.jsdelivr.net/npm/marked/marked.min.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Core es obligatorio; CDN es best-effort
    await cache.addAll(CORE_ASSETS).catch(() => {});
    await Promise.allSettled(CDN_ASSETS.map(u => cache.add(u)));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

// Permitir recargar el SW bajo demanda desde la página
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Navegación (documento HTML): network-first, fallback a cache, luego a index
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        const cache = await caches.open(CACHE_NAME);
        cache.put(req, fresh.clone()).catch(() => {});
        return fresh;
      } catch {
        const cache = await caches.open(CACHE_NAME);
        return (await cache.match(req)) || (await cache.match('./index.html')) || Response.error();
      }
    })());
    return;
  }

  // Todo lo demás: stale-while-revalidate
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(req);
    const network = fetch(req).then((resp) => {
      if (resp && resp.status === 200 && (resp.type === 'basic' || resp.type === 'cors' || resp.type === 'opaque')) {
        cache.put(req, resp.clone()).catch(() => {});
      }
      return resp;
    }).catch(() => cached);
    return cached || network;
  })());
});
