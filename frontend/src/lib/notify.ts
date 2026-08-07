/* Notificări: preferăm Notification API a browserului (funcționează și când
   tabul e în fundal); dacă e refuzată, cădem pe un toast în pagină. */

let toastHost: ((msg: string, kind: 'info' | 'warn') => void) | null = null

export function registerToast(fn: (msg: string, kind: 'info' | 'warn') => void) {
  toastHost = fn
}

export async function ensureNotificationPermission(): Promise<void> {
  if (!('Notification' in window)) return
  if (Notification.permission === 'default') {
    try {
      await Notification.requestPermission()
    } catch {
      /* unele browsere cer un gest de utilizator; ignorăm */
    }
  }
}

export function notify(title: string, body: string, kind: 'info' | 'warn' = 'info', tag?: string) {
  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      // tag-ul deduplichează per-entitate (ex. host-offline-3), nu per-titlu:
      // altfel două host-uri căzute în același poll ar afișa doar ultima notificare
      new Notification(title, { body, tag: tag ?? `${title}|${body}`, icon: '/icon.svg' })
      return
    } catch {
      /* fallback la toast */
    }
  }
  toastHost?.(`${title} — ${body}`, kind)
}
