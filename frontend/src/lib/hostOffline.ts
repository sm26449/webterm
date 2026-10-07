import { Host, Session } from './api'

/* Logica PURĂ a overlay-ului „host offline" din sesiune (componenta: HostOfflineOverlay).
   Separată de React ca s-o putem testa în vitest fără DOM: ce variantă se arată, de când e
   hostul căzut, de ce (dacă ştim) şi ce acţiuni are sens să oferim. Nicio presupunere nouă
   despre server: totul derivă din câmpurile `/api/hosts` şi din jurnalul `/events`. */

/** Hostul poate fi trezit prin Wake-on-LAN? ACEEAŞI regulă ca butonul ⏻ din sidebar: host de
    agent (WoL n-are sens pe SSH/telnet) aflat offline. Un singur predicat, ca overlay-ul şi
    sidebarul să nu se contrazică vreodată. */
export function canWake(host: Host | undefined | null): boolean {
  if (!host || host.online) return false
  return !host.connection_type || host.connection_type === 'agent'
}

const JUMP = new Set(['ssh-jump', 'telnet-jump'])

/** Variantele overlay-ului:
    - `agent`: hostul de agent al sesiunii a căzut (agentul nu mai e conectat);
    - `via`:   ţintă SSH/telnet-jump al cărei host-părinte (agentul prin care trece tunelul)
               a căzut — acţiunile (Diagnostic, Wake, pagina hostului) privesc PĂRINTELE;
    - `connLost`: sesiune SSH/telnet fără agent propriu, pierdută de gateway (dial-ul a căzut).
    null = nimic de arătat. */
export type OfflineMode = 'agent' | 'via' | 'connLost'

export interface OfflineInput {
  session: Pick<Session, 'state' | 'kind' | 'closed_at'>
  host?: Host | null
  /** hostul-părinte (`via_host_id`) pentru ţintele jump */
  viaHost?: Host | null
  /** sesiunea a primit `lost` pe WS (motivul, ex. „agent-gone"); `exited` normal NU contează */
  lostReason?: string | null
}

const isAgent = (h: Host) => !h.connection_type || h.connection_type === 'agent'

export function offlineMode(i: OfflineInput): OfflineMode | null {
  const { session: s, host } = i
  if (!host) return null
  // sesiune închisă normal (exit): nu e o cădere, e istoric. `lost` rămâne relevant — pe un
  // host de agent sesiunea tmux e re-adoptată când agentul revine.
  const open = s.state === 'live' || s.state === 'creating' || s.state === 'lost'
  const lost = s.state === 'lost' || !!i.lostReason
  if (isAgent(host)) {
    if (open && host.online === false) return 'agent'
    // telnet-bastion prin agent (kind=telnet): agentul e viu, dar legătura spre device a căzut
    return s.kind === 'telnet' && lost ? 'connLost' : null
  }
  if (JUMP.has(host.connection_type ?? '') && i.viaHost && !i.viaHost.online && open) return 'via'
  // SSH/telnet fără agent: „offline" înseamnă o legătură pierdută de gateway (sesiunea vine
  // `lost`). Un host direct cu `online=false` şi sesiunea vie e doar „la cerere" (fără dial
  // încă, ex. după un restart de gateway) — re-dial-ul îl face chiar ataşarea WS, nu e o cădere.
  return lost ? 'connLost' : null
}

/** Hostul ale cărui date (heartbeat, jurnal, Wake, pagină) le arată overlay-ul. */
export function offlineTarget(mode: OfflineMode, host: Host, viaHost?: Host | null): Host {
  return mode === 'via' && viaHost ? viaHost : host
}

export interface AgentEvent { ts: number; event: string; reason: string; detail: string }

/** Evenimentul de deconectare al căderii CURENTE: cel mai recent `disconnect` care nu e mai vechi
    decât ultimul heartbeat (unul de ieri ar descrie altă cădere). Jurnalul vine DESC. */
export function outageDisconnect(host: Pick<Host, 'last_heartbeat'>, events: AgentEvent[] | null | undefined): AgentEvent | null {
  if (!events?.length) return null
  const hb = host.last_heartbeat ?? 0
  const ev = [...events].sort((a, b) => b.ts - a.ts).find((e) => e.event === 'disconnect')
  // deconectarea vine DUPĂ ultimul heartbeat (cel mult cu 90s la heartbeat_stale); 5s de toleranţă
  // pentru ceasuri şi pentru scrierea heartbeat-ului în acelaşi tick cu închiderea
  return ev && ev.ts >= hb - 5 ? ev : null
}

/** De când e hostul jos (epoch, secunde). Ordinea de încredere: momentul deconectării din jurnal
    (exact) → ultimul heartbeat (cel mult un interval de heartbeat mai devreme) → momentul în care
    a observat-o pagina asta (pentru sesiunile fără agent: `closed_at` al sesiunii pierdute). */
export function offlineSince(
  mode: OfflineMode, target: Pick<Host, 'last_heartbeat'>, events: AgentEvent[] | null | undefined,
  session: Pick<Session, 'closed_at'>, observedAt: number,
): number {
  if (mode === 'connLost') return session.closed_at ?? observedAt
  const d = outageDisconnect(target, events)
  if (d) return d.ts
  return target.last_heartbeat ?? observedAt
}

/** Durata scurtă „3m", „1h 4m", „2d 5h" (unităţile din catalog, ca `timeAgo`). */
export function fmtOfflineDuration(sec: number, t: (k: string) => string): string {
  const s = Math.max(0, Math.floor(sec))
  if (s < 60) return `${s}${t('time.s')}`
  if (s < 3600) return `${Math.floor(s / 60)}${t('time.m')}`
  if (s < 86400) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
    return m ? `${h}${t('time.h')} ${m}${t('time.m')}` : `${h}${t('time.h')}`
  }
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600)
  return h ? `${d}${t('time.d')} ${h}${t('time.h')}` : `${d}${t('time.d')}`
}

/** Sub ~20h ajunge ora (HH:MM); mai vechi de atât ora singură e ambiguă → dată + oră. */
export function sinceNeedsDate(since: number, now: number): boolean {
  return now - since >= 20 * 3600
}

// motivele de deconectare scrise de gateway (core.py `_stop_reason`) → textul deja tradus din
// panoul de diagnostic. Un cod necunoscut NU se ghiceşte: overlay-ul pur şi simplu nu arată motiv.
const DISCONNECT_REASON: Record<string, string> = {
  heartbeat_stale: 'diag.reasonHeartbeatStale',
  ws_error: 'diag.reasonWsError',
  instance_refused: 'diag.reasonInstanceRefused',
  superseded: 'diag.reasonSuperseded',
  closed: 'diag.reasonClosed',
}

/** Cheia i18n a motivului căderii, DOAR din ce ştie serverul; null = necunoscut (nu inventăm):
    - agent dezinstalat (`uninstalled_at`, expus de API doar când marcajul e credibil);
    - refuzat ca relocat/clonat (`instance_refused`, la deconectare sau la reîncercările de după);
    - restart pentru un update de agent (`update_pushed` cu ≤120s înainte, fără `update_deferred`);
    - altfel motivul deconectării din jurnal. */
export function offlineReason(
  target: Pick<Host, 'last_heartbeat' | 'uninstalled_at'>, events: AgentEvent[] | null | undefined,
): string | null {
  if (target.uninstalled_at) return 'hostOffline.reasonUninstalled'
  const d = outageDisconnect(target, events)
  if (!d) return null
  const after = (events ?? []).filter((e) => e.ts >= d.ts)
  if (d.reason === 'instance_refused'
      || after.some((e) => (e.event === 'disconnect' || e.event === 'handshake_refused')
                           && /instance/.test(e.reason))) {
    return 'hostOffline.reasonRelocated'
  }
  const before = (events ?? []).filter((e) => e.ts <= d.ts && d.ts - e.ts <= 120)
  const pushed = before.some((e) => e.event === 'update_pushed')
  const deferred = before.some((e) => e.event === 'update_deferred')
  if (pushed && !deferred) return 'hostOffline.reasonUpdate'
  return DISCONNECT_REASON[d.reason] ?? null
}

export interface OfflineActions {
  diagnostics: boolean
  wake: boolean
  hostPage: boolean
  reconnect: boolean
}

/** Ce butoane are overlay-ul. Diagnostic merge şi cu agentul căzut (DiagnosticModal arată jurnalul
    + ultimul snapshot persistat); pe SSH/telnet fără agent n-ar avea ce arăta. Wake = regula
    sidebarului, aplicată hostului-ţintă. Reconectarea există doar pentru sesiunile telnet
    (`/api/sessions/{sid}/reconnect`); SSH-ul se re-dial-uieşte singur la ataşare. */
export function offlineActions(
  mode: OfflineMode, target: Host, session: Pick<Session, 'kind'>,
): OfflineActions {
  if (mode === 'connLost') {
    return { diagnostics: false, wake: false, hostPage: true, reconnect: session.kind === 'telnet' }
  }
  return { diagnostics: true, wake: canWake(target), hostPage: true, reconnect: false }
}
