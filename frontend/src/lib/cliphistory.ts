import { copyText } from './clipboard'

/* History de clipboard GLOBAL (toate terminalele din fereastră), în memorie.

   O singură listă cu ce s-a copiat din ORICE terminal: cea mai recentă prima, deduplicată (o
   re-copiere mută intrarea sus şi îi reîmprospătează ora), plafonată la MAX_ENTRIES şi cu
   expirare TTL_MS de la ultima copiere. Alimentează paste picker-ul (Cmd+Shift+V): copiezi în
   terminalul A, lipeşti în B. Fiecare intrare ţine sursa (sid + eticheta sesiunii) şi ora.

   DELIBERAT în memorie, niciodată pe disc/localStorage/sessionStorage/IndexedDB: clipboard-ul
   conţine des parole şi tokenuri (exact motivul pentru care agentul NU scrie input-ul în
   transcript la prompturi de parolă). Un history persistat ar fi un depozit de secrete
   recuperabil. Se pierde la reload — e preţul corect pentru un tool de infrastructură. Tot de
   aceea: TTL scurt, şi `clearAll()` la idle-lock (mesajul `locked` din SessionView) şi la
   logout / sesiune web expirată (App).

   Ferestrele pop-out sunt contexte JS separate (alt `window`, alt modul încărcat): au propriul
   history, care nu se vede în fereastra principală şi invers. Acceptat — nu sincronizăm
   secrete între ferestre (BroadcastChannel ar fi exact canalul pe care nu-l vrem).

   Expirarea nu are timer: intrările vechi se taie la fiecare citire şi înregistrare. */

export const MAX_ENTRIES = 10
export const TTL_MS = 60 * 60 * 1000   // 1 h de la ultima copiere
const MAX_LEN = 100_000                // nu ţinem în history un `cat` uriaş copiat din greşeală

export interface ClipEntry {
  text: string
  sid: string      // sesiunea din care s-a copiat
  label: string    // eticheta sursei (titlul sesiunii / numele hostului), rezolvată la citire
  at: number       // ms epoch, ultima copiere
}

let store: ClipEntry[] = []
// eticheta CURENTĂ a fiecărei sesiuni (SessionView o ţine la zi): un tab redenumit după copiere
// apare cu numele nou. Nu e secret, deci nu se goleşte la clearAll; fallback = eticheta de la copiere.
const labels = new Map<string, string>()

function prune(now = Date.now()): void {
  store = store.filter((e) => now - e.at < TTL_MS)
}

/** Ţine la zi eticheta afişată pentru o sesiune (titlu sau nume de host). */
export function setLabel(sid: string, label: string): void {
  if (!sid) return
  if (label) labels.set(sid, label)
  else labels.delete(sid)
}

/** Înregistrează un text copiat (dedup + newest-first + cap + TTL). Gol / prea lung = ignorat. */
export function record(sid: string, text: string, label?: string): void {
  if (!sid || !text || text.length > MAX_LEN) return
  const now = Date.now()
  prune(now)
  const entry: ClipEntry = { text, sid, label: labels.get(sid) || label || '', at: now }
  store = [entry, ...store.filter((e) => e.text !== text)].slice(0, MAX_ENTRIES)
}

/** History-ul global (copie, newest-first, fără intrările expirate) — acelaşi pentru toate
   terminalele, deci fără `sid`. Eticheta vine din registrul curent, cu fallback la cea de la copiere. */
export function history(): ClipEntry[] {
  prune()
  return store.map((e) => ({ ...e, label: labels.get(e.sid) || e.label }))
}

/** Scoate o intrare (textele sunt unice, datorită dedup-ului). */
export function remove(text: string): void {
  store = store.filter((e) => e.text !== text)
}

/** Goleşte tot history-ul (idle-lock, logout, butonul „Clear history"). */
export function clearAll(): void {
  store = []
}

/** Copiază ŞI înregistrează în history. `copyText` face copierea + toast-ul global; noi adăugăm
   doar înregistrarea, la succes. */
export async function copySession(sid: string, text: string, label?: string): Promise<boolean> {
  const ok = await copyText(text)
  if (ok) record(sid, text, label)
  return ok
}
