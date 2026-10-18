import { type MyPerms, anyHost, can } from './perms'
import { lsGet, lsRemove, lsSet } from './storage'

/* Logica „pură" a walkthrough-ului de primă rulare, scoasă din componentă ca să fie
   TESTABILĂ fără DOM (lista de paşi după permisiuni, clamp-ul de pas + regulile de
   persistenţă). Componenta rămâne doar prezentare; deciziile „ce paşi? / se mai arată? /
   se marchează gata?" trăiesc aici. */

// Cheia MOŞTENITĂ (per browser, până în 3.6.17). Numele e parte din contractul cu testele e2e
// (ele o presetează ca walkthrough-ul să nu blocheze fluxul de login), deci nu-l schimba: la
// prima autentificare e MUTATĂ pe cheia per cont a contului curent (vezi setWalkthroughUser),
// aşa că presetarea ei continuă să însemne „gata" pentru contul care se autentifică. După
// migrare cheia veche NU mai e scrisă de nimeni: o verificare care vrea să vadă „gata" citeşte
// `wt_walkthrough_done:<user_id>` (walkthroughDoneKey), nu numele gol.
export const WALKTHROUGH_DONE_KEY = 'wt_walkthrough_done'

/** Cheia per cont (audit 2026-10-17 UI-06): pe un calculator partajat, al doilea cont îşi vede
    turul; acelaşi om pe alt dispozitiv îl vede din nou (starea e tot în browser, nu pe server). */
export function walkthroughDoneKey(userId: number | null | undefined): string {
  return userId == null ? WALKTHROUGH_DONE_KEY : `${WALKTHROUGH_DONE_KEY}:${userId}`
}

// Contul curent, aflat de la App după autentificare. Până atunci (sau dacă App nu l-a transmis)
// toate citirile/scrierile cad pe cheia moştenită — comportamentul de dinainte, nimic mai larg.
// Modulul e singleton (ca setUploadUser/setCopyUser): logout-ul NU reîncarcă pagina, deci App
// trebuie să-l cheme la FIECARE schimbare de cont (efect pe [authenticated, user_id], cu `null`
// la deconectare), nu o singură dată per montare — altfel al doilea cont din acelaşi tab ar
// citi/scrie cheia primului din Setări şi din bifa „nu mai arăta".
let currentUser: number | null = null

/** SINGURUL punct de înregistrare a contului: App o apelează cu `user_id`-ul din /api/state la
    fiecare schimbare de cont (efectul de lângă setCopyUser), `null` la deconectare. Migrarea unică
    a cheii moştenite: dacă acest cont nu are încă o cheie proprie iar cheia veche spune „gata",
    o copiem DOAR pe contul curent; apoi cheia veche dispare, ca următorul cont de pe acelaşi
    browser să-şi primească turul (cauza UI-06). Idempotentă; `null`/`undefined` = nimeni
    autentificat → înapoi pe cheia moştenită. Testele o cheamă cu `null` în beforeEach. */
export function setWalkthroughUser(userId: number | null | undefined): void {
  currentUser = userId == null ? null : userId
  if (currentUser == null) return
  const own = walkthroughDoneKey(currentUser)
  const legacy = lsGet(WALKTHROUGH_DONE_KEY)
  if (legacy === null) return
  if (lsGet(own) === null && legacy === '1') lsSet(own, '1')
  lsRemove(WALKTHROUGH_DONE_KEY)
}

// ── paşii ────────────────────────────────────────────────────────────────────────────────────

/** Identitatea unui pas; `key` e prefixul din catalogul de limbă (`<key>.title` / `<key>.body`).
    Cheile `walkthrough.stepN` sunt cele istorice (nu se redenumesc), de aceea id-ul ≠ poziţie. */
export type WalkStep = {
  id: 'welcome' | 'addHost' | 'hostsByAdmin' | 'sessions' | 'paste' | 'tools' | 'security' | 'done' | 'noHosts'
  key: string
}

const STEP: Record<WalkStep['id'], WalkStep> = {
  welcome: { id: 'welcome', key: 'walkthrough.step1' },
  addHost: { id: 'addHost', key: 'walkthrough.step2' },
  hostsByAdmin: { id: 'hostsByAdmin', key: 'walkthrough.stepHosts' },
  sessions: { id: 'sessions', key: 'walkthrough.step3' },
  paste: { id: 'paste', key: 'walkthrough.step4' },
  tools: { id: 'tools', key: 'walkthrough.step5' },
  security: { id: 'security', key: 'walkthrough.step6' },
  done: { id: 'done', key: 'walkthrough.step7' },
  noHosts: { id: 'noHosts', key: 'walkthrough.stepNoHosts' },
}

/** uneltele promise de pasul „Session tools" — ajunge una singură pe măcar un host */
const TOOL_PERMS = ['files.read', 'forward.use', 'services.view', 'docker.view', 'toolbox.use'] as const

/** Lista de paşi a contului (audit 2026-10-17 UI-06 / FL-11): fiecare pas apare doar dacă
    contul poate face ce promite pasul — altfel primul contact al unui Viewer era un tur cu
    „Add a host" şi „manage services and Docker", iar butonul „+" din pasul 2 nu exista.
      - „Add a host" cere `hosts.create`; fără el, pasul 2 spune că hosturile vin de la administrator;
      - „Sessions", „Paste" şi „Session tools" cer `session.open` pe măcar un host (paste cere şi
        `files.write` — inbox-ul e un upload; uneltele, măcar una din bara de unelte);
      - fără niciun host vizibil (`host.view` nicăieri) şi fără `hosts.create`: tur scurt care se
        încheie cu „administratorul adaugă hosturi; le vei vedea aici".
    `null` (permisiuni încă necunoscute) = tur complet, regula din lib/perms („necunoscut = permis");
    componenta recalculează când sosesc. */
export function buildSteps(perms: MyPerms | null): WalkStep[] {
  const mayAdd = can(perms, 'hosts.create')
  const seesHost = anyHost(perms, 'host.view')
  if (!mayAdd && !seesHost) return [STEP.welcome, STEP.security, STEP.noHosts]

  const shell = anyHost(perms, 'session.open')
  const out: WalkStep[] = [STEP.welcome, mayAdd ? STEP.addHost : STEP.hostsByAdmin]
  if (shell) {
    out.push(STEP.sessions)
    if (anyHost(perms, 'files.write')) out.push(STEP.paste)
    if (TOOL_PERMS.some((p) => anyHost(perms, p))) out.push(STEP.tools)
  }
  out.push(STEP.security, STEP.done)
  return out
}

/** Numărul maxim de paşi (contul cu toate permisiunile). Numărul REAL e `buildSteps(perms).length`. */
export const TOTAL_STEPS = buildSteps(null).length

/** Ţine indexul de pas în interval, oricât de „sălbatică" ar fi intrarea (clic pe un dot,
    ←/→ la capete, un index salvat devenit invalid dacă scade numărul de paşi — inclusiv când
    permisiunile sosesc după deschidere şi lista se scurtează). Fără asta, un index negativ
    sau ≥N ar randa `steps[i] === undefined` şi componenta ar arunca. */
export function clampStep(i: number, total: number = TOTAL_STEPS): number {
  if (!Number.isFinite(i)) return 0
  if (total <= 0) return 0
  return Math.max(0, Math.min(Math.trunc(i), total - 1))
}

/** Pasul după ←/→, calculat pe indexul AFIŞAT (clamp ÎNTÂI, apoi mutarea): dacă lista s-a
    scurtat după ce ai avansat (permisiunile au sosit după deschidere), `current` poate fi
    dincolo de capăt; fără clamp-ul prealabil ← ar scădea un index fantomă şi prima apăsare
    n-ar mişca nimic vizibil, deşi butonul „Back" se mişcă. `'finish'` = → pe ultimul pas. */
export function stepOnArrow(current: number, total: number, dir: -1 | 1): number | 'finish' {
  const s0 = clampStep(current, total)
  if (dir === 1 && s0 >= total - 1) return 'finish'
  return clampStep(s0 + dir, total)
}

// ── persistenţă ──────────────────────────────────────────────────────────────────────────────

/** Marcat „gata" = citirea întoarce exact '1'. Orice altceva (null, '0', gunoi) = nu.
    Citeşte cheia contului curent (sau pe cea moştenită până când App spune cine e autentificat). */
export function isWalkthroughDone(): boolean {
  return lsGet(walkthroughDoneKey(currentUser)) === '1'
}

export function markWalkthroughDone(): void {
  lsSet(walkthroughDoneKey(currentUser), '1')
}

/** Readuce prima-rulare (toggle-ul din Setări „arată pentru sesiuni noi"): ştergem cheia
    contului, deci la următoarea autentificare a LUI walkthrough-ul se redeschide automat. */
export function resetWalkthrough(): void {
  lsRemove(walkthroughDoneKey(currentUser))
}

/** Se deschide automat DOAR dacă eşti autentificat şi n-a fost marcat gata PENTRU CONTUL CURENT
    (cel înregistrat prin setWalkthroughUser — predicat PUR, fără efecte: înregistrarea şi
    migrarea stau într-un singur loc). Pe ecranul de login (authenticated=false) nu apare
    niciodată — altfel ar acoperi formularul. Testele e2e presetează cheia moştenită, migrată la
    înregistrare pe contul care intră, deci întoarce false la ele şi fluxul de login rămâne neatins. */
export function shouldAutoOpen(authenticated: boolean): boolean {
  if (!authenticated) return false
  return !isWalkthroughDone()
}

/** Aşteptarea permisiunilor la AUTO-deschidere (audit 2026-10-17 UI-06, rest): turul se deschide la
    prima autentificare, de regulă înainte ca /api/me/permissions să fi răspuns, iar `null` = tur
    complet — un Viewer vedea „Step 1 of 7" o fracţiune de secundă, apoi lista se scurta. Componenta
    nu montează dialogul cât timp întoarce true: la auto-open (nu la redeschiderea manuală, când
    permisiunile sunt demult în memorie) şi doar până sosesc permisiunile SAU expiră PERMS_WAIT_MS —
    un fetch eşuat nu are voie să suprime turul (fail-open păstrat, doar amânat). */
export const PERMS_WAIT_MS = 1500
export function waitForPerms(auto: boolean, perms: MyPerms | null, timedOut: boolean): boolean {
  return auto && perms === null && !timedOut
}

/** Regula unică de persistenţă la ÎNCHIDERE, comună tuturor căilor (Gata / Skip / Escape /
    ✕ / backdrop). Întoarce dacă trebuie marcat „gata":
      - bifa „nu mai arăta" bifată  → mereu da (orice cale de închidere);
      - altfel, doar la auto-open ŞI finalizare (butonul „Gata") → tur încheiat la prima rulare.
    „Skip for now" fără bifă NU marchează → reapare la sesiunea următoare. La REDESCHIDERE
    (auto=false, din „?"/Setări) nimic nu atinge cheia dacă bifa nu e pusă — exact cerinţa
    „replay-ul nu schimbă starea decât dacă bifezi". */
export function shouldMarkDoneOnClose(
  opts: { auto: boolean; reason: 'finish' | 'skip'; dontShowAgain: boolean },
): boolean {
  if (opts.dontShowAgain) return true
  return opts.auto && opts.reason === 'finish'
}
