const CACHE_NAME = "since1969zone-v3";

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const request = event.request;

  if (request.method !== "GET") return;

  const url = new URL(request.url);

  if (url.origin !== self.location.origin) return;

  event.respondWith((async () => {
    try {
      const freshResponse = await fetch(request);

      if (freshResponse && freshResponse.status === 200) {
        const cache = await caches.open(CACHE_NAME);
        cache.put(request, freshResponse.clone());
      }

      return freshResponse;
    } catch (error) {
      const cachedResponse = await caches.match(request);
      if (cachedResponse) return cachedResponse;

      if (
        request.mode === "navigate" ||
        request.headers.get("accept")?.includes("text/html")
      ) {
        const fallback = await caches.match("/index.html");
        if (fallback) return fallback;
      }

      throw error;
    }
  })());
});