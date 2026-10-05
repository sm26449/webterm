/* Notificări: preferăm Notification API a browserului (funcționează și când
   tabul e în fundal); dacă e refuzată, cădem pe un toast în pagină. */

export type ToastKind = 'info' | 'warn' | 'error'

let toastHost: ((msg: string, kind: ToastKind) => void) | null = null

export function registerToast(fn: (msg: string, kind: ToastKind) => void) {
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

/** Toast informativ ÎN PAGINĂ, pe o singură linie (fără titlu), care NU foloseşte Notification
    API a OS-ului. De ce nu `notify()`: confirmările de acţiune (paste/drop → „salvat, calea
    inserată") se întâmplă fix când tabul e în faţă şi omul se uită la ecran — un pop-up de
    sistem ar fi spam şi redundant. Mesajul se anunţă oricum prin regiunea live a stivei. */
export function notifyToast(message: string, kind: 'info' | 'warn' = 'info') {
  toastHost?.(message, kind)
}

/** Eroare acţionabilă (ex. „nu m-am putut conecta: port greşit"): MEREU un toast ÎN PAGINĂ,
    nu o notificare de OS. Omul tocmai a apăsat ceva şi se uită la ecran — vrea motivul acolo,
    vizibil şi persistent, nu într-un pop-up de sistem pe care-l poate rata. */
export function notifyError(title: string, body: string) {
  toastHost?.(`${title} — ${body}`, 'error')
}
