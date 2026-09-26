// ODADEAƐ07 service worker — basic offline caching
const CACHE_NAME = 'odadea07-v1';
const PRECACHE = [
  '/static/css/style.css',
  '/static/images/presec-badge.png',
  '/static/manifest.json'
];

self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(PRECACHE);
    })
  );
});

self.addEventListener('fetch', function(event) {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then(function(cached) {
      return cached || fetch(event.request).catch(function() {
        return caches.match('/static/css/style.css');
      });
    })
  );
});