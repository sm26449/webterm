// Directorul curent (cwd) raportat de shell prin OSC 7, per sesiune.
// Shell integration emite `OSC 7 ; file://host/cale ST` la fiecare prompt, deci
// urmărește `cd`-ul. Panoul de fișiere (Faza 2) citește de aici ca să se mute
// automat unde ești în terminal. Fără shell integration nu vine nimic —
// degradare curată, panoul rămâne pe navigarea manuală.

const cwds = new Map<string, string>()

/** Ultimul cwd cunoscut pentru o sesiune (undefined dacă nu s-a raportat). */
export function getCwd(sid: string): string | undefined {
  return cwds.get(sid)
}

/** Actualizează cwd-ul și anunță ascultătorii (`wt-cwd`) doar la schimbare. */
export function setCwd(sid: string, cwd: string): void {
  if (cwds.get(sid) === cwd) return
  cwds.set(sid, cwd)
  window.dispatchEvent(new CustomEvent('wt-cwd', { detail: { sid, cwd } }))
}

/** La închiderea sesiunii — nu ținem cwd-uri moarte în memorie. */
export function clearCwd(sid: string): void {
  cwds.delete(sid)
}

/** Extrage calea absolută din payload-ul OSC 7 (`file://host/cale`).
    Host-ul e ignorat (cosmetic). Tolerant la spații/procent-encoding și la
    forma degenerată `file:///cale` (host gol). Întoarce null dacă nu arată a
    cale absolută, ca să nu mutăm panoul pe gunoi. */
export function parseOsc7(data: string): string | null {
  let s = data.trim()
  if (s.startsWith('file://')) {
    s = s.slice('file://'.length)
    // taie host-ul: până la primul '/'. Host gol → calea începe direct cu '/'.
    const slash = s.indexOf('/')
    s = slash >= 0 ? s.slice(slash) : ''
  }
  if (!s.startsWith('/')) return null
  try {
    return decodeURIComponent(s)
  } catch {
    return s // procent-encoding invalid: folosim bruta, mai bine decât nimic
  }
}
