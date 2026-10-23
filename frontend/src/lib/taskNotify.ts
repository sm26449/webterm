import { lsGet, lsSet } from './storage'

/* Notificări de task (Faza 1, LOCAL — fără backend): anunță când un task s-a TERMINAT cât NU te
   uiți la el (tab în fundal sau alt panou). Două surse:
   - comenzi de shell terminate (OSC 133 „D;<exit>") care au rulat peste un prag — ca să nu sune la
     fiecare `ls`; pragul e per-browser. 3.6.24: un TOAST clickabil („terminalul X a terminat") apare
     la ORICE finalizare (succes verde / eșec chihlimbar) şi, la click, te duce în panoul X; la nivel
     de OS (tab în fundal) rămâne doar eşecul, ca înainte (`shouldNotifyCommand`);
   - notificări EXPLICITE emise de un program (OSC 777 „notify;titlu;corp", formatul clar titlu+corp
     folosit de rxvt/WezTerm/Ghostty) — ex. un hook `Stop` de Claude Code care spune „am terminat";
     astea sună mereu (programul a cerut-o explicit), tot doar cât ești plecat.
   Totul e preferință PER-BROWSER (localStorage), ca rendererul/tema. Livrarea reală pe telefon cu
   aplicația ÎNCHISĂ (Web Push: VAPID + service worker + backend) e Faza 2 — separată fiindcă atinge
   un secret nou + un endpoint + review independent; aici folosim doar Notification API a browserului,
   care ajunge cât aplicația/PWA trăiește (chiar în fundal). */

export const TASKNOTIFY_KEY = 'wt_tasknotify'
export const TASKNOTIFY_SEC_KEY = 'wt_tasknotify_sec'
export const DEFAULT_SEC = 30
const MIN_SEC = 1
const MAX_SEC = 3600

export function taskNotifyEnabled(): boolean {
  return lsGet(TASKNOTIFY_KEY) === '1'
}
export function setTaskNotifyEnabled(on: boolean): void {
  lsSet(TASKNOTIFY_KEY, on ? '1' : '0')
}

/** Pragul în secunde (gunoi din storage → implicit; mereu mărginit). */
export function taskNotifySeconds(): number {
  const n = Number(lsGet(TASKNOTIFY_SEC_KEY))
  return Number.isFinite(n) && n >= MIN_SEC ? Math.min(MAX_SEC, Math.floor(n)) : DEFAULT_SEC
}
export function setTaskNotifySeconds(n: number): void {
  const v = Number.isFinite(n) ? Math.max(MIN_SEC, Math.min(MAX_SEC, Math.floor(n))) : DEFAULT_SEC
  lsSet(TASKNOTIFY_SEC_KEY, String(v))
}

/** Decizia PURĂ pentru o comandă terminată (OSC 133): doar la EȘEC (exit≠0), peste prag, cât ești
    plecat. `inactive` = tab în fundal SAU panoul nefocalizat (nu te uiți la el acum). Folosită în
    3.6.24 DOAR pentru ping-ul la nivel de OS (toast-ul în pagină acoperă deja orice finalizare). */
export function shouldNotifyCommand(
  exitCode: number | undefined,
  durationMs: number,
  o: { enabled: boolean; minSeconds: number; inactive: boolean },
): boolean {
  if (!o.enabled || !o.inactive) return false
  if (exitCode == null || exitCode === 0) return false
  return durationMs >= o.minSeconds * 1000
}

/** 3.6.24 — decizia PURĂ pentru toast-ul „terminalul X a terminat": la ORICE finalizare (succes SAU
    eșec), peste prag, cât ești plecat de pe panou/tab. Diferă de `shouldNotifyCommand` prin faptul că
    succesul (exit 0) sună şi el — omul a cerut „la orice finalizare". `exitCode == null` (comandă fără
    marcaj de sfârşit) nu e o finalizare → nu sună. Culoarea (verde/chihlimbar) o alege apelantul. */
export function shouldNotifyDone(
  exitCode: number | undefined,
  durationMs: number,
  o: { enabled: boolean; minSeconds: number; inactive: boolean },
): boolean {
  if (!o.enabled || !o.inactive) return false
  if (exitCode == null) return false
  return durationMs >= o.minSeconds * 1000
}

/** Taie controalele și plafonează lungimea: textul OSC vine de la host (posibil remote) — input
    NEÎNCREDERE, exact ca la OSC 52. Niciodată newline/ESC/BEL în corpul notificării. */
export function sanitizeOscText(s: string, cap = 120): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, cap)
}

/** Parsează o notificare explicită de terminal în {title, body}. Formate acceptate:
    - OSC 777 (rxvt/WezTerm/Ghostty): „notify;<titlu>;<corp>" — formatul clar, cu titlu și corp;
    - OSC 9  (iTerm2): tot payload-ul e corpul;
    - OSC 99 (kitty): metadata cu `;`, corpul după ultimul `;` (cazul simplu, nechunked).
    SessionView leagă în Faza 1 DOAR OSC 777 (9 se suprapune cu progres ConEmu „9;4" și cwd „9;9",
    iar 99 e chunked/encoded — le lăsăm pe viitor); parserul le ține pe toate, testate. Întoarce
    null dacă nu rămâne nimic de arătat. */
export function parseOscNotify(code: 9 | 777 | 99, data: string): { title: string; body: string } | null {
  let title = ''
  let body = ''
  if (code === 777) {
    const parts = data.split(';')
    if (parts[0] !== 'notify') return null
    title = parts[1] ?? ''
    body = parts.slice(2).join(';')
  } else if (code === 99) {
    const i = data.lastIndexOf(';')
    body = i >= 0 ? data.slice(i + 1) : data
  } else {
    body = data
  }
  const st = sanitizeOscText(title)
  const sb = sanitizeOscText(body)
  if (!st && !sb) return null
  return { title: st, body: sb }
}
