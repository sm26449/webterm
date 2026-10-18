import { askSecret } from './secretPrompt'
import { ssoStepupRedirect } from './stepup'

export interface WatermarkConfig {
  enabled: boolean
  content: string      // template cu ${email} ${host} ${date} ${time}
  opacity: number
  angle: number
  fontSize: number
}

export interface CommandRule {
  pattern: string
  action: 'confirm' | 'block'
}
export interface CommandGuard {
  enabled: boolean
  rules: CommandRule[]
}

export interface AppState {
  setup_required: boolean
  authenticated: boolean
  email: string | null
  /** id-ul contului (null neautentificat): cheia stărilor locale per cont — ex. descărcările
      întrerupte din IndexedDB (lib/dlresume.ts), ca alt cont în acelaşi browser să nu le vadă */
  user_id?: number | null
  webauthn_available: boolean
  /** Factorul de step-up al contului pe un host 2FA (3.5.13): passkey | sso | totp | none.
      `none` = parola singură nu mai ajunge — UI-ul trimite la Setări → Autentificare & 2FA. */
  stepup_method?: 'passkey' | 'sso' | 'totp' | 'none' | null
  backup_ready?: boolean
  signing_missing?: boolean
  signing_locked?: boolean
  /** 3.6.8: System health — verificările warning/critical nemutate (doar cu `security.view`) */
  health_attention?: { count: number; severity: 'ok' | 'info' | 'warning' | 'critical' } | null
  watermark?: WatermarkConfig | null
  command_guard?: CommandGuard | null
  /** Pragul de idle-lock (secunde) pe hosturile cu 2FA; 0 = oprit. Cronometrul e PER sesiune
      de terminal (îl resetează input-ul şi mesajul WS `touch`), nu per sesiune web — de aceea
      `idle_lock_at` e null aici; momentul exact vine în `init`/`lock_at` pe WS-ul sesiunii. */
  idle_lock_seconds?: number
  idle_lock_at?: number | null
  /** Alarme de host-key schimbat nerezolvate (SSH direct/jump) — persistente până la accept. */
  hostkey_changed?: HostKeyAlarm[]
}

export interface HostKeyAlarm {
  host_id: number
  host_name: string
  old_fp: string
  new_fp: string
  changed_at: number | null
}

export interface HostMetrics {
  load1?: number
  load5?: number
  load15?: number
  cpu_pct?: number
  mem_total?: number
  mem_used?: number
  disk_total?: number
  disk_used?: number
}

export interface Connection {
  id: number
  host_id: number
  label: string
  engine: 'postgres' | 'mysql' | 'mongodb' | 'clickhouse' | 'redis' | 'influxdb' | 'influxdb2'
  target_host: string
  target_port: number | null
  username: string
  dbname: string
  cred_policy: 'ask' | 'stored' | 'ephemeral'
}

// Un split-view: layout denumit de 2-4 sesiuni (distincte), per user, sincronizat server-side.
// Definiţiile stau în DB; selecţia activă (care view e deschis) rămâne per-browser. Vezi
// docs/design/SPLIT-VIEWS.md.
export interface SplitView {
  id: number
  name: string
  panes: string[]       // 2-4 sid-uri distincte — DOAR cele pe care contul le vede acum
  ratio: number         // divider pt. 2 panouri, fracţie 0.15..0.85 (compat; 3.6.12: `sizes`)
  /** 3.6.12: forma (`cols2` | `cols3` | `main-left` | `main-top` | `grid`) + fracţiile pe grupuri
      (vezi lib/splitLayout.ts). Lipsesc pe un gateway mai vechi → implicitul pe numărul de panouri. */
  layout?: string
  sizes?: number[]
  /** câte panouri vii sunt ascunse acum (rol / host 2FA fără step-up) — nu se pot rearanja până revin */
  hidden?: number
  broadcast: boolean
  position: number
}

/** Cum revine agentul după un reboot (raportat de agent v57+, vezi docs/HOSTS.md#starting-at-boot). */
export interface HostSupervision {
  mode: 'systemd' | 'cron' | 'none'
  /** systemd --user fără linger porneşte serviciul abia la primul login, nu la boot */
  linger: boolean
  boot: boolean
  scope?: 'user' | 'system'
  watchdog?: boolean
}

export interface Host {
  /** alarmă de host-key schimbat nerezolvată (SSH direct/jump); null când totul e în regulă */
  hostkey_alarm?: { old_fp?: string; new_fp?: string; changed_at?: number } | null
  id: number
  name: string
  note: string
  alerts_muted?: boolean
  /** 3.6.10: rulează gateway-ul / îi ţine backup-urile — un shell aici = Owner (insignă coroană).
      Trimis DOAR unui Owner sau cuiva cu users.manage (revizuirea 3.6.10); absent pentru restul. */
  crown_jewel?: boolean
  /** 3.6.10, doar pentru Owner: pare hostul gateway-ului (ales pentru reînnoirea certificatelor) */
  crown_hint?: 'gateway' | null
  updates?:{ count: number; security: number | null; manager: string | null } | null
  /** pornirea agentului la boot (agent v57+); null = necunoscut (agent mai vechi / ne-agent) */
  supervision?: HostSupervision | null
  online: boolean
  hostname: string | null
  agent_user: string | null
  /** 3.6.9: Python-ul agentului e (probabil / sigur) sub minimul 3.6 — operaţiile pe fişiere cad */
  agent_python_old?: 'likely' | 'confirmed' | null
  agent_version: number | null
  agent_latest: number | null
  update_pending: boolean
  update_blocked?: string | null
  metrics: HostMetrics | null
  backend: string | null
  last_heartbeat: number | null
  folder?: string
  tags?: string[]
  conflict?: boolean
  enroll_pending?: boolean       // link de instalare valabil + nefolosit (agentul nu s-a conectat)
  enroll_protected?: boolean     // link-ul are parolă
  uninstalled_at?: number | null
  install_command?: string
  install_command_dedicated?: string
  // conectare directă
  connection_type?: 'agent' | 'ssh' | 'ssh-jump' | 'telnet' | 'telnet-jump'
  via_host_id?: number | null
  ephemeral?: boolean
  ssh_username?: string | null
  ssh_port?: number | null
  auth_method?: 'password' | 'key' | null
  require_2fa?: boolean
  credential_policy?: 'stored' | 'ask' | 'ephemeral'
  has_credentials?: boolean
}

// Chei de deploy host→host (Toolbox → SSH keys): DOAR material public + graful de deploy;
// privata trăieşte pe hostul sursă şi nu tranzitează niciodată gateway-ul.
export interface DeployKeyDeployment {
  id: number
  key_id: number
  target_host_id: number
  target_name: string
  target_hostname: string
  target_user: string
  options: string
  status: 'deployed' | 'edited' | 'missing' | 'revoked'
  deployed_at: number
  revoked_at: number | null
  /** 3.6: ţinta e pe un host pe care contul nu-l vede — rândul rămâne (uşa există), fără nume/id */
  hidden?: boolean
}
export interface DeployKeyPolicy {
  require_2fa_source: boolean
  require_restrict: boolean
}

export interface DeployKeyInfo {
  key: { id: number; public_key: string; fingerprint: string; created: number } | null
  deployments: DeployKeyDeployment[]
  inbound: { source_host_id: number; source_name: string; fingerprint: string; status: string; hidden?: boolean }[]
}

export interface PortForward {
  id: number
  host_id: number
  label: string
  slug: string
  target_host: string
  target_port: number
  scheme: 'http' | 'https' | 'telnet'
  description: string
  enabled: boolean
  created: number
  url: string
  app_type?: string          // '' | proxmox | portainer | grafana | custom — bookmark/app
}

// forward promovat la „app", agregat pe dashboard (fără target_host:port)
export interface AppLink {
  id: number
  label: string
  app_type: string
  host_id: number
  host_name: string
  enabled: boolean
  url: string
}

export interface Snippet {
  id: number
  title: string
  body: string
  /** ţinte implicite pentru consola de flotă (etichete de host); null = fără */
  targets?: { tags: string[] } | null
}

export interface SearchHit {
  id: string
  title: string
  host_id: number
  state: Session['state']
  created: number
  snippet: string
  matches: number
}

/* O sesiune e „activă" doar dacă hostul ei chiar răspunde.

   `state` devine `lost` abia după 180s (2 × heartbeat stale), iar în fereastra aia interfaţa
   arăta puncte verzi pulsând, badge-uri „2 sesiuni active" şi „0 online" pe ACEEAŞI linie —
   deşi tastele nu mai ajungeau nicăieri. Bara de stare a fost reparată punctual; celelalte
   şapte locuri au rămas. Helperul e comun tocmai ca al optulea să nu reintroducă defectul.

   Fără host în listă (nu s-a încărcat încă) ne bazăm pe `state`: mai bine optimist o clipă
   la pornire decât „offline" fals pe toată interfaţa. */
export function isSessionLive(s: Session, hosts?: Host[]): boolean {
  const alive = s.state === 'live' || s.state === 'creating'
  if (!alive || !hosts) return alive
  const h = hosts.find((x) => x.id === s.host_id)
  return h ? h.online !== false : alive
}

/* Ţintele EFEMERE („conectează o dată", fără salvare) trăiesc în `hosts` doar cât sesiunea
   lor, apoi reaper-ul le şterge. Sidebar-ul le ascundea, dar Dashboard-ul, paleta şi
   Fleet-run iterau `props.hosts` nefiltrat — deci un host „nesalvat" apărea în trei locuri,
   cu contor cu tot. Un singur predicat, ca al patrulea consumator să nu reintroducă defectul.
   Lista COMPLETĂ rămâne necesară pentru `host_id → Host` al sesiunilor (tab, titlu, culoare). */
export const isEphemeralHost = (h: Host): boolean => !!h.ephemeral

export interface Session {
  id: string
  host_id: number
  title: string
  note: string
  state: 'creating' | 'live' | 'closed' | 'lost'
  kind?: 'shell' | 'telnet'   // telnet = bastion telnet-via-agent (poate fi reconectat)
  created: number
  closed_at: number | null
  exit_status: number | null
  close_reason: string | null
  rows: number
  cols: number
  connected_clients: number
  out_offset: number
  /** cine a deschis-o (3.6; null = dinainte de roluri) */
  created_by_id?: number | null
}

/* Rezumatul de securitate (GET /api/security/summary, 3.5.4). Serverul NU trimite proză: doar
   `id` + `status` + `value`; textul îl compune SecurityCard din catalog. Un `id` necunoscut
   (gateway mai nou decât bundle-ul) se sare, nu se randează ca cheie brută. */
export type SecurityStatus = 'ok' | 'warn' | 'bad' | 'info'
export interface SecurityCheck {
  id: string
  status: SecurityStatus
  value: Record<string, unknown>
}

/** Un link de share activ (GET /api/shares). Fără token/URL — nu există nici pe server. */
export interface ShareRow {
  sid: string
  title: string
  host_id: number
  host_name: string
  by: string
  writable: boolean
  expires: number
  viewers: number
}

/** Un link de replay al contului (GET /api/replay-links, 3.5.12). Fără token/URL: URL-ul se
    arată o singură dată, la creare (`ReplayLinkCreated`). */
export interface ReplayLinkRow {
  id: number
  sid: string
  title: string
  host_id: number | null
  host_name: string
  label: string
  redact: boolean
  created: number
  expires: number
  opens: number
  last_opened: number | null
  last_ip: string
}
export interface ReplayLinkCreated {
  id: number
  url: string
  sid: string
  label: string
  redact: boolean
  created: number
  expires: number
}

export class ApiError extends Error {
  status: number
  /** Cod stabil trimis de server în antetul `X-WebTerm-Error` (vezi gateway/app/errors.py).
      Gol pentru erorile încă neconvertite — atunci rămâne mesajul englezesc. */
  code: string
  /** Valorile mesajului (`vars` din corpul erorii: host, limită, utilizatorul agentului, dosarul…),
      doar scalari — interpolate în traducerea codului de `errText`. */
  vars: Record<string, string | number>
  constructor(status: number, detail: string, code = '', vars?: Record<string, string | number>) {
    super(detail)
    this.status = status
    this.code = code
    this.vars = vars ?? {}
  }
}

/** `vars` dintr-un corp de eroare JSON: doar chei simple cu valori string/număr (orice altceva
    cade). Textul ajunge doar ca TEXT în React — nu HTML — dar tot nu lăsăm structuri să treacă. */
export function scalarVars(v: unknown): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  if (!v || typeof v !== 'object' || Array.isArray(v)) return out
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    if (!/^[a-z][a-zA-Z0-9_]{0,31}$/.test(k)) continue
    if (typeof x === 'string') out[k] = x.slice(0, 500)
    else if (typeof x === 'number' && Number.isFinite(x)) out[k] = x
  }
  return out
}

/** ApiError dintr-un răspuns HTTP citit altfel decât prin `api()` (XHR-ul de upload): codul din
    antet sau din corp, `detail` şi `vars` din corpul JSON. */
export function apiErrorFrom(status: number, body: string, headerCode?: string | null): ApiError {
  let detail = String(status), code = headerCode ?? '', vars: Record<string, string | number> = {}
  try {
    const j = JSON.parse(body)
    if (j && typeof j === 'object') {
      if (typeof j.detail === 'string') detail = j.detail
      if (!code && typeof j.code === 'string') code = j.code
      vars = scalarVars(j.vars)
    }
  } catch { /* corp ne-JSON */ }
  return new ApiError(status, detail, code, vars)
}

/* Textul de arătat omului pentru o eroare de API.

   Serverul trimite un cod stabil şi un mesaj în ENGLEZĂ. Dacă avem o traducere pentru cod,
   o folosim; altfel arătăm mesajul serverului. Aşa, mesajele neconvertite încă nu dispar şi
   nu devin „unknown error" — degradează la engleză, care e ce se întâmpla oricum înainte.

   `vars` acoperă mesajele cu valori (nume de host, limite): cheia le interpolează. */
export function errText(e: unknown, t: (k: string, v?: Record<string, string | number>) => string,
                        vars?: Record<string, string | number>): string {
  if (!(e instanceof ApiError)) return e instanceof Error ? e.message : String(e)
  if (e.code) {
    // {detail} = mesajul serverului, la îndemâna oricărei traduceri care vrea să-l arate (ex.
    // „systemctl rejected the command on the host: Access denied") — audit funcţional 3.6.3, #4
    const translated = t('err.' + e.code, { detail: e.message, ...e.vars, ...vars })
    if (translated !== 'err.' + e.code) return translated     // `t` întoarce cheia dacă lipseşte
  }
  return e.message
}

/* Al doilea factor la operaţiile care schimbă materialul de autentificare (passkey-uri,
   tokenuri, coduri de recuperare, parolă/email de cont, ştergere de cont). Îl cerem REACTIV,
   după refuzul serverului: starea locală „am TOTP activ" poate fi veche (activat în alt tab,
   dezactivat de pe server), iar serverul e oricum singurul care decide. O singură reîncercare —
   dacă şi codul e greşit, mesajul serverului e ce trebuie să vadă omul.
   (Extras din SecurityTab când auditul intern a extins second_gate şi la operaţiile de cont.) */
export async function withSecondFactor<T>(t: (k: string, v?: Record<string, string | number>) => string,
                                          send: (extra: object) => Promise<T>,
                                          opts?: { totpOnly?: boolean }): Promise<T> {
  try {
    return await send({})
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
    // totpOnly: apelantul are propriul flux pentru codul de email (câmp inline în formular,
    // ca la schimbarea contului) — interceptăm doar TOTP-ul şi lăsăm restul să treacă la el
    const key = err.code === 'passkey.totpRequired' ? 'totp_code'
      : (err.code === 'account.codeRequired' && !opts?.totpOnly) ? 'email_code' : ''
    if (!key) throw err
    // nemascat: codurile trăiesc 30s şi să vezi ce tastezi ajută — parolele folosesc masca
    const code = await askSecret(key === 'totp_code' ? t('settings.passkeyCodePrompt') : errText(err, t),
                                 { masked: false })
    if (code === null) throw err
    return await send({ [key]: code.trim() })
  }
}

/* Guardrail pe acţiunile din panouri (git care scrie, docker, services, /run): serverul răspunde
   409 `run.guardConfirm` când o regulă `confirm` se potriveşte. Întrebăm omul (`ask` primeşte
   pattern-ul regulii) şi retrimitem cu `confirmed: true`; refuzul întoarce null. `block` (403)
   trece mai departe ca eroare obişnuită — errText îl traduce. */
export async function withGuardConfirm<T>(ask: (pattern: string) => Promise<boolean>,
                                          send: (confirmed: boolean) => Promise<T>): Promise<T | null> {
  try {
    return await send(false)
  } catch (err) {
    if (!(err instanceof ApiError) || err.code !== 'run.guardConfirm') throw err
    const pattern = /\/(.*)\/\s*$/.exec(err.message)?.[1] ?? ''
    if (!(await ask(pattern))) return null
    return await send(true)
  }
}

// Versiunea gateway-ului văzută la primul răspuns API. Când headerul se
// schimbă (s-a făcut deploy cât aplicația era deschisă), anunțăm o singură
// dată — App afișează bannerul „Versiune nouă — Reîncarcă". Fereastra PWA
// nu are F5, deci fără asta rămâi pe bundle-ul vechi până închizi aplicația.
let bootVersion: string | null = null
let lastNotifiedVersion: string | null = null

/** Versiunea gateway-ului din headerul primului răspuns (X-Webterm-Version).
    Disponibilă și înainte de autentificare (footer-ul de login), fără un apel dedicat. */
export function getBootVersion(): string | null {
  return bootVersion
}
/** CHANGELOG-ul aplicaţiei (Markdown), servit din imagine — About → „Ce e nou". */
export async function getChangelog(): Promise<{ text: string; version: string }> {
  return api('/api/changelog')
}

function checkGatewayVersion(res: Response) {
  const v = res.headers.get('X-Webterm-Version')
  if (!v) return
  if (bootVersion === null) {
    bootVersion = v
  } else if (v !== bootVersion && v !== lastNotifiedVersion) {
    // per-versiune, nu one-shot: dacă utilizatorul închide bannerul cu ✕ și
    // apoi vine ÎNCĂ un deploy, trebuie anunțat din nou (PWA stă deschis zile)
    lastNotifiedVersion = v
    window.dispatchEvent(new CustomEvent('wt-new-version', { detail: v }))
  }
}

// H1: step-up 2FA nu mai e doar la crearea sesiunii, ci la ORICE acțiune pe un host cu require_2fa
// (run, fs/*, update, provision, uninstall). Ca să nu împrăștiem ceremonia passkey în fiecare
// componentă, o înregistrăm o dată aici: la un 403 de step-up pe o rută /api/hosts/{id}/…, rulăm
// ceremonia (care deschide fereastra de step-up pe server) și reîncercăm cererea O SINGURĂ dată.
// `code` e codul stabil al refuzului (`stepup.password` / `stepup.totp` / `stepup.passkey`):
// handler-ul alege ce cere omului — passkey, parola contului SAU un cod TOTP de 6 cifre
// (useri cu TOTP activ, fără passkey). Opţional: rutele vechi încă pot chema fără cod.
type StepupHandler = (hostId: number, code?: string) => Promise<boolean>
let stepupHandler: StepupHandler | null = null
export function setStepupHandler(fn: StepupHandler | null): void {
  stepupHandler = fn
}

function hostIdFromPath(path: string): number | null {
  const m = path.match(/\/api\/hosts\/(\d+)(?:\/|\?|$)/)
  return m ? Number(m[1]) : null
}

// Pentru call-site-uri unde host_id NU e în URL (raw fetch de fișiere; /api/forwards/{fid}/telnet;
// /api/sessions/{sid}/reconnect) — deschide manual fereastra de step-up pentru host și spune dacă a
// reușit, ca apelantul să reîncerce. Întoarce false dacă nu e niciun handler sau userul anulează.
export async function ensureStepup(hostId: number, code?: string): Promise<boolean> {
  return stepupHandler ? stepupHandler(hostId, code) : false
}

// Un 403 e „de step-up" (necesită re-verificare 2FA) după detaliul mesajului.
export function isStepupError(e: unknown): boolean {
  if (!(e instanceof ApiError) || e.status !== 403) return false
  // codul e semnalul; regexul rămâne rezervă pentru mesajele încă neconvertite
  return e.code ? e.code.startsWith('stepup.') : /2FA|passkey/i.test(e.message)
}

// Rulează `fn` (un apel `api()` pe o rută FĂRĂ host_id în URL — telnet/reconnect); la un 403 de
// step-up, deschide fereastra pentru `hostId` și reîncearcă o dată. Ridică eroarea originală altfel.
export async function withStepup<T>(hostId: number, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    // trecem codul refuzului (`stepup.totp` vs `stepup.password`) ca handler-ul să ştie ce să ceară
    const code = e instanceof ApiError ? e.code : ''
    if (isStepupError(e) && (await ensureStepup(hostId, code))) return fn()
    throw e
  }
}

/* RB-03 (audit 2026-10-17): re-autentificarea la o SCHIMBARE DE ACCES — grant/revocare/expirare de
   legătură, ştergere/reactivare de cont, rol custom, mapare SSO, parola locală a contului. Serverul
   (`_reauth_for_access_change`, `/api/account`) cere:
     · cont local → parola contului (+ al doilea factor, prin withSecondFactor);
     · cont SSO (sso_subject) → un grant passkey ACCOUNT-SCOPE (host_id=0) SAU fereastra SSO
       account-scope deschisă de callback-ul `intent=stepup` fără host. Parola NU e verificată
       niciodată pentru el (hash aleator) → 403 `account.ssoReauth`.
   Înainte, fiecare panou cerea o parolă (askSecret) şi arăta 403-ul ca text: un Admin SSO-only
   (modelul recomandat de 3.6.2/3.6.5) nu avea nicio cale din UI. Decizia stă acum într-un singur
   loc (`accessReauthPlan`, din rândul propriu de la /api/users: `sso`, `passkeys`):
     'password' → askSecret, ca înainte (sau parola deja tastată inline, `opts.password`);
     'passkey'  → ceremonia passkey account-scope → `stepup_grant` (single-use);
     'sso'      → fără prompt: trimitem direct — după întoarcerea de la IdP fereastra e deschisă;
                  altfel serverul refuză cu 403 şi plecăm la IdP (`ssoStepupRedirect(0)`), ca la
                  hosturi (`?stepup=ok` readuce tab-ul; acţiunea se reia fără alt prompt).
   Pe orice plan, 403 `account.ssoReauth` ⇒ redirect SSO: poarta rămâne pe server (fail closed);
   aici doar nu mai cerem un secret pe care omul nu-l are. `null` = omul a renunţat.
   Limite cunoscute (corecţia RB-03):
     · pe planul 'passkey' serverul CONSUMĂ grantul single-use înainte de `second_gate`
       (api.py `_reauth_for_access_change`): dacă acesta cere al doilea factor, reîncercarea lui
       withSecondFactor pleacă cu grantul deja ars → 403 → redirect SSO. Cu TOTP activ `second_gate`
       cere codul ÎNTOTDEAUNA la prima cerere, deci pentru un cont SSO cu TOTP planul 'passkey' ar
       eşua determinist: de aceea `me.totp` → 'sso' (trimitem direct → 403 → IdP → fereastra
       deschisă → TOTP → reuşeşte). Rămâne cazul dispozitivului nou fără TOTP (ceremonie irosită,
       fail closed); remediul e pe server (second_gate înaintea consumului) — follow-up.
     · `passwordGate`: pentru o rută care ar verifica DOAR parola (niciuna azi — din 3.6.18 şi
       POST /api/tokens trece prin `_reauth_for_access_change`): planul e 'password' pentru oricine,
       ca să nu promitem un passkey/SSO pe care ruta nu l-ar accepta. Păstrat pentru o rută viitoare.
     · „adus înapoi să reiei acţiunea": `?stepup=ok` restaurează doar hash-ul (tab-ul); modalul
       Settings e stare React. Înainte de redirect salvăm ţinta Settings (`opts.returnTo`) sub
       `SETTINGS_RETURN_KEY`, ca App să poată redeschide panoul la întoarcere (vezi App.tsx,
       efectul `?stepup=ok`); până atunci textul spune că Settings trebuie redeschis. */
export type ReauthMe = {
  sso?: boolean; local_password?: boolean; passkeys?: number
  /** TOTP activ: `second_gate` cere codul la prima cerere, deci grantul passkey s-ar arde (vezi nota) */
  totp?: boolean
} | null | undefined
export type ReauthPlan = 'password' | 'passkey' | 'sso'

/** cheia din sessionStorage cu ţinta Settings de redeschis după `?stepup=ok` (JSON: `{ cat, section? }`) */
export const SETTINGS_RETURN_KEY = 'wt_settings_return'
export type SettingsReturn = { cat: string; section?: string }

export function accessReauthPlan(me: ReauthMe, webauthn: boolean, passwordGate = false): ReauthPlan {
  // fără rând (listă neîncărcată, gateway vechi) sau cont local → parola; 403-ul rămâne plasa
  if (!me || !me.sso) return 'password'
  // rută doar-cu-parolă: serverul nu acceptă nici grant, nici fereastra SSO → cerem parola
  // (un cont SSO-only nu are ce tasta; formularul arată motivul, nu o cale care nu există)
  if (passwordGate) return 'password'
  // TOTP activ: grantul single-use ar fi consumat înainte ca second_gate să ceară codul → SSO
  if (me.totp) return 'sso'
  return (me.passkeys ?? 0) > 0 && webauthn ? 'passkey' : 'sso'
}

/** Reţine ţinta Settings înainte de un redirect de step-up, ca App s-o redeschidă la `?stepup=ok`.
    Fără sessionStorage (teste, mod privat) nu face nimic — e o comoditate, nu o poartă. */
export function rememberSettingsReturn(target: SettingsReturn | undefined): void {
  try {
    if (typeof sessionStorage === 'undefined') return
    if (target) sessionStorage.setItem(SETTINGS_RETURN_KEY, JSON.stringify(target))
    else sessionStorage.removeItem(SETTINGS_RETURN_KEY)
  } catch { /* */ }
}

/** Întrebarea dintr-un prompt de confirmare existent („Scoţi X de la Y?\n\nConfirmă cu parola TA:"):
    fără ultimul paragraf când acela e instrucţiunea de parolă (se termină cu `:`). */
export function reauthQuestion(prompt: string): string {
  const i = prompt.lastIndexOf('\n\n')
  if (i < 0) return prompt
  return prompt.slice(i + 2).trim().endsWith(':') ? prompt.slice(0, i).trim() : prompt
}

export type AccessReauthOpts = {
  me?: ReauthMe
  /** WebAuthn utilizabil în acest browser (implicit `window.PublicKeyCredential`) */
  webauthn?: boolean
  /** parola deja tastată într-un câmp inline (formularele Add account / token): fără askSecret */
  password?: string
  /** ruta verifică doar parola (vezi nota de mai sus): planul e 'password' pentru oricine */
  passwordGate?: boolean
  /** panoul Settings de redeschis după întoarcerea de la IdP (salvat înainte de redirect) */
  returnTo?: SettingsReturn
  /** confirmarea acţiunii pe planurile fără parolă (promptul de parolă ERA confirmarea) */
  confirm?: (question: string) => Promise<boolean>
  /** ceremonia passkey account-scope → grant; null = anulată de om; '' = nu a mers (serverul decide) */
  passkey?: () => Promise<string | null>
  redirect?: () => void
}

/** Grant passkey account-scope (host_id=0): aceeaşi ceremonie ca pe un host 2FA (App.stepupCredential),
    dar pentru contul însuşi. `null` = omul a închis dialogul; `''` = ceremonia nu a reuşit (passkey-ul
    e pe alt dispozitiv etc.) — atunci cererea pleacă fără grant şi serverul decide (403 → SSO). */
export async function accountPasskeyGrant(): Promise<string | null> {
  try {
    const { startAuthentication } = await import('@simplewebauthn/browser')
    const options = await api<Record<string, unknown>>('/api/webauthn/stepup/options', {
      method: 'POST', body: JSON.stringify({ host_id: 0 }),
    })
    const credential = await startAuthentication({ optionsJSON: options as never })
    const r = await api<{ grant: string }>('/api/webauthn/stepup/verify', {
      method: 'POST', body: JSON.stringify({ host_id: 0, credential }),
    })
    return r.grant || ''
  } catch (e) {
    return e instanceof Error && e.name === 'NotAllowedError' ? null : ''
  }
}

export async function withAccessReauth<T>(t: (k: string, v?: Record<string, string | number>) => string,
                                          prompt: string,
                                          send: (cred: object) => Promise<T>,
                                          opts: AccessReauthOpts = {}): Promise<T | null> {
  const webauthn = opts.webauthn ?? (typeof window !== 'undefined' && !!window.PublicKeyCredential)
  const plan = accessReauthPlan(opts.me, webauthn, !!opts.passwordGate)
  let cred: Record<string, string> = {}
  if (plan === 'password') {
    const pw = opts.password ?? await askSecret(prompt)
    if (!pw) return null
    cred = { current_password: pw }
  } else {
    if (opts.confirm && !(await opts.confirm(
      reauthQuestion(prompt) + '\n\n' + t(plan === 'passkey' ? 'access.reauth.viaPasskey' : 'access.reauth.viaSso')))) return null
    if (plan === 'passkey') {
      const grant = await (opts.passkey ?? accountPasskeyGrant)()
      if (grant === null) return null
      if (grant) cred = { stepup_grant: grant }
    }
  }
  try {
    return await send(cred)
  } catch (e) {
    if (!(e instanceof ApiError)) throw e
    if (e.code === 'account.ssoReauth' || e.code === 'history.ssoReauth') {   // DELETE /api/history are codul lui (3.5.13)
      rememberSettingsReturn(opts.returnTo)
      ;(opts.redirect ?? (() => ssoStepupRedirect(0)))()
      return null
    }
    // serverul a verificat totuşi o parolă (SSO oprit între timp; o rută încă pe poarta de parolă,
    // ex. /api/tokens): o cerem o singură dată, ca înainte
    if (plan !== 'password' && e.status === 401
        && (e.code === 'auth.wrongPassword' || e.code === 'auth.wrongCurrentPassword')) {
      const pw = await askSecret(prompt)
      if (!pw) return null
      return await send({ current_password: pw })
    }
    throw e
  }
}

export async function api<T>(path: string, options: RequestInit = {}, _retried = false): Promise<T> {
  const res = await fetch(path, {
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    credentials: 'same-origin',
    ...options,
  })
  checkGatewayVersion(res)
  if (!res.ok) {
    let detail = res.statusText
    let code = res.headers.get('X-WebTerm-Error') ?? ''
    let errVars: Record<string, string | number> = {}
    try {
      const j = await res.json()
      detail = j.detail ?? detail
      if (!code && typeof j.code === 'string') code = j.code
      errVars = scalarVars(j.vars)
    } catch {
      /* non-JSON error body */
    }
    // 403 de step-up: rulează ceremonia și reîncearcă o dată (H1). Exclude chiar ruta /stepup
    // (acolo handler-ul DESCHIDE fereastra) ca un grant respins să nu declanșeze recursie.
    // Decidea după TEXTUL mesajului (`/2FA|passkey|parola contului/i`) — fragil la orice
    // reformulare, şi deja greşit: prindea şi „the host requires 2FA — not reachable with an
    // automation token", care nu e o cerere de step-up. Codul e semnalul corect; regexul
    // rămâne ca rezervă pentru mesajele încă neconvertite.
    // Step-up SSO: userul e federat (fără passkey/parolă locală) pe un host cu 2FA. Nu există
    // ceremonie inline — cerem re-auth PROASPĂT la IdP printr-un redirect de pagină întreagă.
    // Păstrăm tab-ul curent (location.hash) ca să revenim exact acolo după callback.
    if (res.status === 403 && code === 'host.needs2faSso') {
      const hostId = hostIdFromPath(path)
      if (hostId != null) {
        try { sessionStorage.setItem('wt_stepup_return', window.location.hash) } catch { /* */ }
        window.location.href = '/api/oidc/login?intent=stepup&host_id=' + hostId
        return new Promise<T>(() => {})   // pagina navighează; promisiunea nu se mai rezolvă
      }
    }
    // 401 FĂRĂ cod = poarta generică `require_user` („not authenticated"): cookie-ul de
    // sesiune a expirat / a fost revocat. Până acum nu-l trata nimeni: aplicaţia afla abia
    // la următorul poll şi se înlocuia tăcut cu pagina de login. Semnalăm explicit; App
    // arată motivul. 401-urile CU cod (`auth.wrongPassword` la schimbarea parolei etc.) nu
    // sunt expirări şi rămân ale apelantului; la fel rutele de autentificare în sine.
    if (res.status === 401 && !code && !/^\/api\/(login|setup|state|oidc)/.test(path)) {
      window.dispatchEvent(new Event('wt-unauth'))
    }
    const isStepup = code ? code.startsWith('stepup.') : /2FA|passkey/i.test(detail)
    if (res.status === 403 && !_retried && stepupHandler
        && !path.endsWith('/stepup') && isStepup) {
      const hostId = hostIdFromPath(path)
      if (hostId != null && (await stepupHandler(hostId, code))) {
        return api<T>(path, options, true)
      }
    }
    throw new ApiError(res.status, detail, code, errVars)
  }
  return res.json()
}

// `t` e obligatoriu: abrevierile erau engleză fixă (`now`, `d`) aici şi română fixă (`z`) în
// trei componente, deci ACELAŞI produs scria „văzut now" pe un dashboard românesc şi „acum 3z"
// pe unul englezesc. Unităţile stau în catalog, ca restul.
export function timeAgo(epoch: number, t: (k: string) => string): string {
  const s = Math.max(0, Date.now() / 1000 - epoch)
  if (s < 60) return t('time.now')
  if (s < 3600) return `${Math.floor(s / 60)}${t('time.m')}`
  if (s < 86400) return `${Math.floor(s / 3600)}${t('time.h')}`
  return `${Math.floor(s / 86400)}${t('time.d')}`
}
