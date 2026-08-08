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
  webauthn_available: boolean
  backup_ready?: boolean
  signing_missing?: boolean
  signing_locked?: boolean
  watermark?: WatermarkConfig | null
  command_guard?: CommandGuard | null
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

export interface Host {
  id: number
  name: string
  note: string
  online: boolean
  hostname: string | null
  agent_user: string | null
  agent_version: number | null
  agent_latest: number | null
  update_pending: boolean
  update_blocked?: string | null
  metrics: HostMetrics | null
  backend: string | null
  last_heartbeat: number | null
  folder?: string
  conflict?: boolean
  install_command?: string
  install_command_dedicated?: string
  // conectare directă
  connection_type?: 'agent' | 'ssh' | 'telnet'
  ssh_username?: string | null
  ssh_port?: number | null
  auth_method?: 'password' | 'key' | null
  require_2fa?: boolean
  credential_policy?: 'stored' | 'ask' | 'ephemeral'
  has_credentials?: boolean
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
}

export interface Snippet {
  id: number
  title: string
  body: string
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
}

export class ApiError extends Error {
  status: number
  /** Cod stabil trimis de server în antetul `X-WebTerm-Error` (vezi gateway/app/errors.py).
      Gol pentru erorile încă neconvertite — atunci rămâne mesajul englezesc. */
  code: string
  constructor(status: number, detail: string, code = '') {
    super(detail)
    this.status = status
    this.code = code
  }
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
    const translated = t('err.' + e.code, vars)
    if (translated !== 'err.' + e.code) return translated     // `t` întoarce cheia dacă lipseşte
  }
  return e.message
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
type StepupHandler = (hostId: number) => Promise<boolean>
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
export async function ensureStepup(hostId: number): Promise<boolean> {
  return stepupHandler ? stepupHandler(hostId) : false
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
    if (isStepupError(e) && (await ensureStepup(hostId))) return fn()
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
    const code = res.headers.get('X-WebTerm-Error') ?? ''
    try {
      detail = (await res.json()).detail ?? detail
    } catch {
      /* non-JSON error body */
    }
    // 403 de step-up: rulează ceremonia și reîncearcă o dată (H1). Exclude chiar ruta /stepup
    // (acolo handler-ul DESCHIDE fereastra) ca un grant respins să nu declanșeze recursie.
    // Decidea după TEXTUL mesajului (`/2FA|passkey|parola contului/i`) — fragil la orice
    // reformulare, şi deja greşit: prindea şi „the host requires 2FA — not reachable with an
    // automation token", care nu e o cerere de step-up. Codul e semnalul corect; regexul
    // rămâne ca rezervă pentru mesajele încă neconvertite.
    const isStepup = code ? code.startsWith('stepup.') : /2FA|passkey/i.test(detail)
    if (res.status === 403 && !_retried && stepupHandler
        && !path.endsWith('/stepup') && isStepup) {
      const hostId = hostIdFromPath(path)
      if (hostId != null && (await stepupHandler(hostId))) {
        return api<T>(path, options, true)
      }
    }
    throw new ApiError(res.status, detail, code)
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
