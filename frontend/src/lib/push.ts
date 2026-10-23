import { api } from './api'

/* Web Push (Faza 2): abonează DISPOZITIVUL curent ca gateway-ul să poată trimite o notificare pe
   telefon chiar cu aplicația ÎNCHISĂ (detecția e server-side; vezi docs/ALERTS.md#task-notifications).
   Diferit de Faza 1 (lib/taskNotify.ts), care folosește Notification API cât aplicația e deschisă.
   Pe iOS merge DOAR ca PWA pe Home Screen, iar permisiunea se cere dintr-un GEST de utilizator —
   de aceea subscribeThisDevice() trebuie apelat dintr-un click, nu la montare. */

export type PushStatus = {
  available: boolean       // push configurat server-side (cheie VAPID) — altfel ascundem opțiunea
  publicKey: string | null
  enabled: boolean         // preferința contului „push la task eșuat"
  minSeconds: number
  devices: number          // câte dispozitive abonate are contul (toate, nu doar ăsta)
}

export function pushSupported(): boolean {
  return typeof navigator !== 'undefined' && 'serviceWorker' in navigator
    && typeof window !== 'undefined' && 'PushManager' in window && 'Notification' in window
}

/** base64url (cheia VAPID de la server) → ArrayBuffer pentru applicationServerKey (BufferSource). */
function urlB64ToKey(base64: string): ArrayBuffer {
  const pad = '='.repeat((4 - (base64.length % 4)) % 4)
  const raw = atob((base64 + pad).replace(/-/g, '+').replace(/_/g, '/'))
  const buf = new ArrayBuffer(raw.length)
  const arr = new Uint8Array(buf)
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i)
  return buf
}

/** ArrayBuffer (cheile clientului) → base64url, forma așteptată de server (push.py `_unb64u`). */
function bytesToB64url(buf: ArrayBuffer | null): string {
  if (!buf) return ''
  let s = ''
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function pushStatus(): Promise<PushStatus> {
  return api<PushStatus>('/api/push/status')
}

/** E abonat DISPOZITIVUL ăsta? (status.devices e pe cont, nu pe dispozitiv.) */
export async function thisDeviceSubscribed(): Promise<boolean> {
  if (!pushSupported()) return false
  try {
    const r = await navigator.serviceWorker.ready
    return !!(await r.pushManager.getSubscription())
  } catch {
    return false
  }
}

/** Abonează dispozitivul curent. DIN GEST DE UTILIZATOR (iOS cere asta pentru permisiune).
    Aruncă 'unsupported' | 'unavailable' | 'denied'. La succes pornește și preferința contului. */
export async function subscribeThisDevice(lang: string): Promise<PushStatus> {
  if (!pushSupported()) throw new Error('unsupported')
  const st = await pushStatus()
  if (!st.available || !st.publicKey) throw new Error('unavailable')
  if ((await Notification.requestPermission()) !== 'granted') throw new Error('denied')
  const r = await navigator.serviceWorker.ready
  const sub = (await r.pushManager.getSubscription())
    || (await r.pushManager.subscribe({
      userVisibleOnly: true,                    // iOS/Chrome: push-ul TREBUIE să fie vizibil
      applicationServerKey: urlB64ToKey(st.publicKey),
    }))
  await api('/api/push/subscribe', {
    method: 'POST',
    body: JSON.stringify({
      subscription: {
        endpoint: sub.endpoint,
        p256dh: bytesToB64url(sub.getKey('p256dh')),
        auth: bytesToB64url(sub.getKey('auth')),
      },
      lang,
    }),
  })
  return pushStatus()
}

/** Dezabonează dispozitivul curent (server + browser). Idempotent. */
export async function unsubscribeThisDevice(): Promise<PushStatus> {
  try {
    const r = await navigator.serviceWorker.ready
    const sub = await r.pushManager.getSubscription()
    if (sub) {
      await api('/api/push/unsubscribe', {
        method: 'POST',
        body: JSON.stringify({ endpoint: sub.endpoint, p256dh: '', auth: '' }),
      }).catch(() => { /* server poate să-l fi curățat deja */ })
      await sub.unsubscribe().catch(() => { /* deja dezabonat */ })
    }
  } catch {
    /* fără service worker */
  }
  return pushStatus()
}

/** Pragul/pornit-oprit la nivel de CONT (push-ul e condus de server). */
export function setPushPrefs(enabled: boolean, minSeconds: number): Promise<void> {
  return api<void>('/api/push/prefs', { method: 'POST', body: JSON.stringify({ enabled, minSeconds }) })
}

/** Trimite un push de test către dispozitivele contului. */
export function testPush(): Promise<{ sent: number; gone: number }> {
  return api<{ sent: number; gone: number }>('/api/push/test', { method: 'POST' })
}
