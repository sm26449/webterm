/* Feedback discret „Copiat" la FIECARE copiere. Separat de sistemul de toast-uri (Toasts.tsx),
   care e pentru alerte importante: acolo toast-urile se stivuiesc, stau 6s şi se închid cu
   click. Copierea se întâmplă des (mai ales selecţia din tmux), deci vrem opusul: un SINGUR
   element care se resetează la fiecare copiere şi se stinge singur repede. Modul pub/sub ca
   `copyText` (lib, fără acces la React/i18n) să poată semnala succesul; CopyToast.tsx randează. */

type Sub = (nonce: number, label?: string) => void

let sub: Sub | null = null
let seq = 0

export function onCopyToast(fn: Sub): () => void {
  sub = fn
  return () => { if (sub === fn) sub = null }
}

/** Semnalează o copiere reuşită. `label` opţional suprascrie textul implicit („Copiat"). */
export function showCopyToast(label?: string): void {
  sub?.(++seq, label)
}
