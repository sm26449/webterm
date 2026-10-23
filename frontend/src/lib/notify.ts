/* Notificări: preferăm Notification API a browserului (funcționează și când
   tabul e în fundal); dacă e refuzată, cădem pe un toast în pagină. */

export type ToastKind = 'info' | 'warn' | 'error'

/** `key` (3.6.16): un toast nou cu aceeaşi cheie îl ÎNLOCUIEŞTE pe loc pe cel vechi (acelaşi loc în
    stivă, temporizator nou) — un paste = un singur toast („Se încarcă…" → rezultatul), nu două stivuite.
    `onClick` (3.6.24): un toast poate fi acţionabil — ex. „terminalul X a terminat" care, la click, te
    duce în panoul X (dispatch `wt-open-session`). Opţional; absenţa lui = toast pur informativ. */
type ToastHost = (msg: string, kind: ToastKind, key?: string, onClick?: () => void) => void
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

/** Notificare la nivel de OS (Notification API), FĂRĂ fallback pe toast — pentru cazul în care
    un toast ÎN pagină a fost deja ridicat şi n-ar trebui dublat (3.6.24: finalizarea unui task
    arată un toast clickabil mereu, iar OS-ul se foloseşte doar în plus cât tabul e în fundal, unde
    toast-ul oricum nu se vede). Întoarce true dacă notificarea a fost afişată. */
export function notifyOs(title: string, body: string, tag?: string): boolean {
  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      new Notification(title, { body, tag: tag ?? `${title}|${body}`, icon: '/icon.svg' })
      return true
    } catch {
      /* indisponibil */
    }
  }
  return false
}

/** Toast informativ ÎN PAGINĂ, pe o singură linie (fără titlu), care NU foloseşte Notification
    API a OS-ului. De ce nu `notify()`: confirmările de acţiune (paste/drop → „salvat, calea
    inserată") se întâmplă fix când tabul e în faţă şi omul se uită la ecran — un pop-up de
    sistem ar fi spam şi redundant. Mesajul se anunţă oricum prin regiunea live a stivei. */
export function notifyToast(message: string, kind: 'info' | 'warn' = 'info', key?: string, onClick?: () => void) {
  toastHost?.(message, kind, key, onClick)
}

/** Eroare acţionabilă (ex. „nu m-am putut conecta: port greşit"): MEREU un toast ÎN PAGINĂ,
    nu o notificare de OS. Omul tocmai a apăsat ceva şi se uită la ecran — vrea motivul acolo,
    vizibil şi persistent, nu într-un pop-up de sistem pe care-l poate rata. */
export function notifyError(title: string, body: string, key?: string) {
  toastHost?.(`${title} — ${body}`, 'error', key)
}

// Hook pentru e2e (acelaşi tipar ca `window.__wtTransfers`): un toast de eroare ridicat cât un dialog
// modal e deschis trebuie să rămână vizibil (3.6.16, N1). Funcţia e exact cea din UI.
if (typeof window !== 'undefined') {
  ;(window as unknown as { __wtNotify?: object }).__wtNotify = { notifyError }
}
