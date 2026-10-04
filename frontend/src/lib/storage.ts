/* Acces la localStorage care nu aruncă. `localStorage` poate lipsi sau arunca `SecurityError`
   la simpla ATINGERE: Safari cu „blochează toate cookie-urile", iframe-uri sandbox, mod privat
   pe browsere vechi, politici de întreprindere. theme.ts/tz.ts/termtheme.ts citeau cheile la
   import — adică ÎNAINTE de montarea React-ului — şi excepţia trimitea utilizatorul direct în
   pagina failsafe, fără nicio legătură cu tema (auditul frontend 2026-10, F-06). Aici: citire
   = valoarea sau null, scriere = best-effort; preferinţa pur şi simplu nu persistă. */

export function lsGet(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

export function lsSet(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    /* cotă depăşită / storage blocat: preferinţa trăieşte doar în sesiunea curentă */
  }
}

export function lsRemove(key: string): void {
  try {
    window.localStorage.removeItem(key)
  } catch {
    /* idem */
  }
}
