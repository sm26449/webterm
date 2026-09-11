/* WebTerm service worker — minim, orientat spre INSTALABILITATE (PWA) + reziliență offline a
   shell-ului, NU spre caching agresiv. Un terminal live trebuie să lovească MEREU reţeaua pentru
   date; SW-ul atinge doar navigările şi asset-urile statice (hash-uite, deci imutabile), şi
   network-first ca un deploy să nu servească niciodată o pagină veche. */
const CACHE = 'webterm-shell-v1'
const SHELL = ['/', '/failsafe.js', '/favicon.svg', '/manifest.webmanifest']

self.addEventListener('install', (e) => {
  self.skipWaiting()
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL).catch(() => {})))
})

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

self.addEventListener('fetch', (e) => {
  const req = e.request
  if (req.method !== 'GET') return
  const url = new URL(req.url)
  if (url.origin !== self.location.origin) return
  // Căile VII/dinamice lovesc mereu reţeaua — niciodată din cache: API, WebSocket-uri (agent +
  // browser), handshake-ul de forward, scriptul de install, share-urile read-only.
  if (/^\/(api|ws|agent|__wtfwd|install|shared)(\/|$)/.test(url.pathname)) return
  // Navigări + asset-uri: network-first, cache doar ca plasă offline.
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok && res.type === 'basic') {
          const copy = res.clone()
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {})
        }
        return res
      })
      .catch(() => caches.match(req).then((hit) => hit || caches.match('/'))),
  )
})
