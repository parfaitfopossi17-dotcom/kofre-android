/* KOFRE - fonctionne hors ligne : tout est mis en cache au premier chargement. */
const VERSION = "kofre-v1";
const FICHIERS = ["./", "./index.html", "./manifest.webmanifest", "./js/main.js", "./js/native.js", "./js/core.js", "./js/api-web.js", "./js/analyse.js",
  "./js/totp.js", "./js/importer.js", "./lib/argon2.umd.min.js", "./icons/icon-192.png", "./icons/icon-512.png", "./icons/icon-180.png"];

self.addEventListener("install", (e) => { e.waitUntil(caches.open(VERSION).then((c) => c.addAll(FICHIERS)).then(() => self.skipWaiting())); });
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((k) => Promise.all(k.filter((n) => n !== VERSION).map((n) => caches.delete(n)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const r = e.request;
  if (r.method !== "GET" || new URL(r.url).origin !== location.origin) return; // jamais les requêtes externes (HIBP)
  e.respondWith(caches.match(r, { ignoreSearch: true }).then((c) => c || fetch(r)));
});
