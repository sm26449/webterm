/* Notificări: preferăm Notification API a browserului (funcționează și când
   tabul e în fundal); dacă e refuzată, cădem pe un toast în pagină. */

export type ToastKind = 'info' | 'warn' | 'error'

/** `key` (3.6.16): un toast nou cu aceeaşi cheie îl ÎNLOCUIEŞTE pe loc pe cel vechi (acelaşi loc în
    stivă, temporizator nou) — un paste = un singur toast („Se încarcă…" → rezultatul), nu două stivuite */
type ToastHost = (msg: string, kind: ToastKind, key?: string) => void
let toastHost: ToastHost | null = null

export function registerToast(fn: ToastHost) {
  toastHost = fn
}

/** Adaugă `item` în stivă; dacă are `key` şi există deja un toast cu aceeaşi cheie, îl înlocuieşte
    în acelaşi loc. `id`-ul e nou, deci temporizatorul vechiului toast (care ţinteşte id-ul vechi) nu-l
    mai poate închide pe cel nou înainte de vreme. Pur — testat în notify.test.ts. */
export function upsertToast<T extends { id: string; key?: string }>(list: T[], item: T): T[] {
  if (item.key) {
    const i = list.findIndex((x) => x.key === item.key)
    if (i >= 0) { const next = list.slice(); next[i] = item; return next }
  }
  return [...list, item]
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
export function notifyToast(message: string, kind: 'info' | 'warn' = 'info', key?: string) {
  toastHost?.(message, kind, key)
}

/** Eroare acţionabilă (ex. „nu m-am putut conecta: port greşit"): MEREU un toast ÎN PAGINĂ,
    nu o notificare de OS. Omul tocmai a apăsat ceva şi se uită la ecran — vrea motivul acolo,
    vizibil şi persistent, nu într-un pop-up de sistem pe care-l poate rata. */
export function notifyError(title: string, body: string, key?: string) {
  toastHost?.(`${title} — ${body}`, 'error', key)
}
