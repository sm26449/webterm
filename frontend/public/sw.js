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

/* Web Push (Faza 2): notificare pe telefon chiar cu aplicaţia ÎNCHISĂ. Payload-ul e JSON GENERIC
   trimis de gateway (push.py) — niciodată text de terminal (trece prin serviciul vendorului). iOS
   cere o notificare VIZIBILĂ la fiecare push (nu există push silenţios), deci afişăm mereu una. */
self.addEventListener('push', (e) => {
  let d = {}
  try { d = e.data ? e.data.json() : {} } catch { d = {} }
  e.waitUntil(self.registration.showNotification(d.title || 'WebTerm', {
    body: d.body || '',
    tag: d.tag || undefined,          // dedup: un tag nou înlocuieşte notificarea veche cu acelaşi tag
    icon: '/favicon.svg',
    badge: '/favicon.svg',
    data: { url: d.url || '/' },
  }))
})

/* Click pe notificare: adu în faţă o fereastră a aplicaţiei (sau deschide una). */
self.addEventListener('notificationclick', (e) => {
  e.notification.close()
  const url = (e.notification.data && e.notification.data.url) || '/'
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    for (const c of all) {
      if ('focus' in c) { try { await c.focus(); return } catch { /* fereastra s-a închis între timp */ } }
    }
    if (self.clients.openWindow) await self.clients.openWindow(url)
  })())
})
