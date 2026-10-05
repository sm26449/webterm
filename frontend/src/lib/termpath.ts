// Căi selectate în terminal → acţiuni de fişiere din meniul contextual. Logica PURĂ (fără DOM,
// fără fetch) stă aici ca s-o putem testa cu vitest şi s-o refolosim: `SessionView` doar o apelează.

/** Selecţia din terminal arată a cale? Decide dacă meniul contextual arată „Deschide calea".
    DE CE atât de strict: o selecţie oarecare de text (o propoziţie, un fragment de output) NU
    trebuie să ofere o acţiune de fişiere — doar ceva ce arată fără echivoc a cale. Reguli: un
    singur rând, nevidă după `trim` (nu doar spaţii), şi începe clar a cale (`/abs`, `~`, `~/…`
    sau `./rel`). Plafon de lungime ca o selecţie uriaşă din greşeală să nu intre pe cale. */
export function looksLikePath(sel: string): boolean {
  const s = sel.trim()
  if (!s || s.length > 4096) return false
  if (/[\r\n]/.test(s)) return false                 // un singur rând
  return s === '~' || s.startsWith('/') || s.startsWith('~/') || s.startsWith('./')
}

/** Rezolvă o cale selectată la una pe care o înţelege API-ul de fişiere, relativ la `base`
    (cwd-ul din OSC 7, sau home-ul rezolvat când shell integration e oprită — apelantul alege).
    - `/abs` → absolută, ignoră base-ul (doar normalizăm `/`-urile de la coadă);
    - `~` / `~/…` → neatinse: agentul le expandează el (ca peste tot în panoul de fişiere);
    - `./rel` sau `rel` → legate de `base`.
    Nu „normalizăm" `..` aici: agentul rezolvă calea pe host, iar un `..` prea deştept pe client
    ar putea diverge de ce vede shell-ul. */
export function resolveTermPath(raw: string, base: string): string {
  const s = raw.trim()
  if (s.startsWith('/')) return s.replace(/\/+$/, '') || '/'
  if (s === '~' || s.startsWith('~/')) return s
  const rel = s.startsWith('./') ? s.slice(2) : s
  return `${base.replace(/\/+$/, '')}/${rel}`
}

/** Ultimul segment al unei căi (numele fişierului), pentru titlul editorului. */
export function baseName(p: string): string {
  const s = p.replace(/\/+$/, '')
  const i = s.lastIndexOf('/')
  return i >= 0 ? s.slice(i + 1) : s
}
