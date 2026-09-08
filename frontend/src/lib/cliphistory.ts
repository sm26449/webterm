import { copyText } from './clipboard'

/* History de clipboard PER TERMINAL, în memorie.

   Fiecare sesiune (tab) îşi ţine propria listă cu ce s-a copiat DIN ea: cea mai recentă prima,
   deduplicată, plafonată. Alimentează paste picker-ul (Cmd+Shift+V).

   DELIBERAT în memorie, niciodată pe disc/localStorage: clipboard-ul conţine des parole şi
   tokenuri (exact motivul pentru care agentul NU scrie input-ul în transcript la prompturi de
   parolă). Un history persistat ar fi un depozit de secrete recuperabil. Se pierde la reload —
   e preţul corect pentru un tool de infrastructură. */

const MAX_ENTRIES = 25
const MAX_LEN = 100_000        // nu ţinem în history un `cat` uriaş copiat din greşeală

const store = new Map<string, string[]>()

/** Înregistrează un text copiat în history-ul sesiunii (dedup + newest-first + cap). */
export function record(sid: string, text: string): void {
  if (!sid || !text || text.length > MAX_LEN) return
  const cur = store.get(sid) ?? []
  const next = [text, ...cur.filter((t) => t !== text)].slice(0, MAX_ENTRIES)
  store.set(sid, next)
}

/** History-ul sesiunii (copie, newest-first). */
export function history(sid: string): string[] {
  return [...(store.get(sid) ?? [])]
}

export function clear(sid: string): void {
  store.delete(sid)
}

/** Copiază ŞI înregistrează în history-ul sesiunii. `copyText` face copierea + toast-ul global;
   noi adăugăm doar înregistrarea per-sesiune, la succes. */
export async function copySession(sid: string, text: string): Promise<boolean> {
  const ok = await copyText(text)
  if (ok) record(sid, text)
  return ok
}
