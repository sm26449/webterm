import { api, withFreshFactor, type FreshFactorOpts } from './api'
import type { MyPerms } from './perms'

/* 3.8, criptarea la repaus — logica panoului Owner „Encryption at rest" (Setări → Backup) şi a
   acţiunii „Erase permanently" din lista de înregistrări / player. Componentele rămân subţiri:
   aici stau tipurile răspunsurilor, ce se arată (tonuri, procente, stări de destinaţie), cuvintele
   de confirmare tastate (aceleaşi ca pe server, share_api.py) şi apelurile, fiecare prin
   `withFreshFactor` (serverul cere un factor REAL proaspăt în corp; vezi lib/api.ts).
   Gating-ul de aici e COSMETIC: serverul verifică `backups.manage` + Owner @ all la fiecare rută. */

export type Protection = { mode: '' | 'legacy' | 'reduced' | 'protected' | string; source: string | null }

export type EraseDestination = {
  id: string
  configured: boolean
  required: boolean
  attested_n: number
  attested_time: number | null
  state: string
  since: number | null
  error: string
  behind: boolean
  rolled_back: boolean
  ahead: number | null
  retirable: boolean
}

export type ConflictHead = { n: number; time: number; mac: string }

export type ErasureOverview = {
  journal: { n: number; diag: string | null; uncertain: string | null; cap: number; near_cap: boolean }
  continuity: { since: number; n: number; date: string; readable: boolean } | null
  conflict: {
    recorded: boolean; diag: string; since: number; heads: ConflictHead[]; bases: ConflictHead[]
    sids: number; dests: string[]; overflow: boolean
  } | null
  destinations: EraseDestination[]
  destinations_known: boolean
  health: { severity: string; key: string; params: Record<string, string> }[]
}

export type Recompaction = {
  left: number; left_bytes: number; done: number; saved_bytes: number; failed: number; error: string
  corrupt: number; corrupt_sids: string[]; corrupt_error: string; oversize: number
}

export type MigrationStatus = {
  format: string; total: number; done: number; todo: number; left_bytes: number; failed: number
  stray: number; leftovers: number; one_kind: number; orphans: number; error: string
  format_block: string | null; recompaction: Recompaction
}

export type FailedMigration = {
  sid: string; kinds: string[]; size: number; error: string; encrypted: boolean
  title: string; host_id: number | null; live: boolean
}

export type EncryptionStatus = {
  protection: Protection
  active: boolean
  erasure: ErasureOverview | null
  migration: MigrationStatus | null
  failed: FailedMigration[]
  recording: { sid: string; kinds: Record<string, string>; encrypted: boolean; tombstoned: boolean } | null
}

export type QuarantineItem = {
  sid: string
  kinds: string[]
  status: 'quarantined' | 'recovery' | 'plaintext' | 'mixed' | string
  reason: string
  since: number | null
  recoverable: boolean
  recovery: 'continuity' | 'journal' | null
  confirm_word?: string
  /** sesiunea (0 = fără rând): factorul proaspăt al acţiunii se leagă de hostul ei */
  title?: string
  host_id?: number
  live?: boolean
}
export type QuarantineList = {
  items: QuarantineItem[]
  continuity: { state: string; since: number; n: number } | null
  journal_diag: string | null
}

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral'

/** Owner @ all cu `backups.manage` — pentru a ARĂTA acţiunile. Până la primul răspuns (`null`)
    nu arătăm nimic: altfel un cont fără drept ar vedea un buton distructiv clipind la pornire. */
export function isEncryptionOwner(p: MyPerms | null): boolean {
  return !!p && p.owner && p.global.includes('backups.manage')
}

/** „Erase permanently" se oferă doar pentru o sesiune închisă cu înregistrare CRIPTATĂ. */
export function canErase(p: MyPerms | null, rec: EncryptionStatus['recording'] | null | undefined,
                         live: boolean): boolean {
  return isEncryptionOwner(p) && !live && !!rec && rec.encrypted && !rec.tombstoned
}

export function protectionView(p: Protection | null | undefined): { tone: Tone; key: string } {
  const mode = p?.mode || ''
  if (!mode) return { tone: 'neutral', key: 'enc.protection.unknown' }
  if (mode === 'legacy') return { tone: 'info', key: 'enc.protection.legacy' }
  if (mode === 'reduced') return { tone: 'warn', key: 'enc.protection.reduced' }
  if (p?.source === 'env') return { tone: 'warn', key: 'enc.protection.env' }
  return { tone: 'ok', key: 'enc.protection.protected' }
}

/** Procentul migrării (0–100); fără nimic de migrat = 100. */
export function migrationPercent(m: Pick<MigrationStatus, 'done' | 'total'> | null | undefined): number {
  if (!m || m.total <= 0) return 100
  return Math.max(0, Math.min(100, Math.floor((m.done / m.total) * 100)))
}

/** Procentul recompactării generaţiilor v1: făcute / (făcute + rămase); nimic rămas = 100. */
export function recompactionPercent(r: Pick<Recompaction, 'done' | 'left'> | null | undefined): number {
  if (!r) return 100
  const all = r.done + r.left
  return all <= 0 ? 100 : Math.max(0, Math.min(100, Math.floor((r.done / all) * 100)))
}

export type DestState = 'rolledBack' | 'ahead' | 'missing' | 'failing' | 'behind' | 'attested' | 'none'

/** Starea unei destinaţii, de la cea mai gravă: rollback / obiect mai nou neverificabil / jurnal
    dispărut / erori de încărcare / atestare în urmă / la zi. */
export function destState(d: EraseDestination): DestState {
  if (d.rolled_back) return 'rolledBack'
  if (d.ahead != null) return 'ahead'
  if (d.state === 'missing') return 'missing'
  if (d.state !== 'ok' && d.error) return 'failing'
  // nicio atestare pe o destinaţie care nu mai e configurată (ex. cerută doar de un restore): nu „la zi"
  if (d.attested_n <= 0 && !d.configured) return 'none'
  if (d.attested_n <= 0 && d.behind) return 'behind'
  if (d.behind) return 'behind'
  return 'attested'
}

export function destTone(s: DestState): Tone {
  switch (s) {
    case 'rolledBack': case 'ahead': return 'danger'
    case 'missing': case 'failing': case 'behind': return 'warn'
    case 'attested': return 'ok'
    default: return 'neutral'
  }
}

export const healthTone = (sev: string): Tone =>
  sev === 'critical' ? 'danger' : sev === 'warning' ? 'warn' : sev === 'info' ? 'info' : 'ok'

/** Data UTC (YYYY-MM-DD) a unui epoch în secunde — aceeaşi ca serverul (`time.gmtime`). */
export function utcDate(epoch: number): string {
  return new Date((epoch || 0) * 1000).toISOString().slice(0, 10)
}

/** Confirmarea tastată a ştergerii / discard-ului: primele 8 caractere ale sesiunii. */
export const eraseWord = (sid: string): string => sid.slice(0, 8)

/** Confirmarea tastată a recuperării: data backup-ului (continuitate) sau „<sid8> <diagnostic>"
    (jurnal stricat). `null` = înregistrarea nu se poate recupera acum. */
export function recoveryWord(item: QuarantineItem, q: Pick<QuarantineList, 'continuity'>): string | null {
  if (!item.recoverable) return null
  if (item.recovery === 'continuity') return q.continuity ? utcDate(q.continuity.since) : null
  if (item.recovery === 'journal' && item.confirm_word) return `${eraseWord(item.sid)} ${item.confirm_word}`
  return null
}

/** Confirmarea tastată a rezolvării unui conflict: „<n> <primele 16 ale MAC-ului>". */
export const conflictWord = (h: Pick<ConflictHead, 'n' | 'mac'>): string => `${h.n} ${h.mac.slice(0, 16).toLowerCase()}`

/** Spaţiile de la margini nu contează (serverul face `strip()`); restul trebuie să fie identic. */
export const typedMatches = (typed: string, want: string): boolean =>
  typed.trim().split(/\s+/).join(' ') === want

// ── apeluri (fiecare cu factorul proaspăt cerut de rută) ─────────────────────────────────────

const post = <T>(path: string, body: object) => api<T>(path, { method: 'POST', body: JSON.stringify(body) })
const enc = encodeURIComponent

export const loadEncryption = (sid?: string) =>
  api<EncryptionStatus>('/api/recordings/encryption' + (sid ? `?sid=${enc(sid)}` : ''))
export const loadQuarantine = () => api<QuarantineList>('/api/recordings/quarantine')

/** Hostul de care se leagă factorul: al sesiunii (rutele cu sid) sau 0 (fără sesiune). */
export type EraseResult = { erased: boolean; n: number; state: string; attested: boolean }

export const eraseRecording = (sid: string, hostId: number, confirm: string, o?: FreshFactorOpts) =>
  withFreshFactor(hostId, (cred) => post<EraseResult>(`/api/sessions/${enc(sid)}/erase`, { confirm, ...cred }), o)

export const recoverRecording = (sid: string, hostId: number, confirm: string, o?: FreshFactorOpts) =>
  withFreshFactor(hostId, (cred) => post<{ ok: boolean }>(`/api/sessions/${enc(sid)}/recovery`, { confirm, ...cred }), o)

export const releaseRecording = (sid: string, hostId: number, o?: FreshFactorOpts) =>
  withFreshFactor(hostId, (cred) => post<{ ok: boolean }>(`/api/sessions/${enc(sid)}/recovery/release`, { ...cred }), o)

/** Reduce accesul: fără factor proaspăt (doar Owner). */
export const requarantineRecording = (sid: string) =>
  post<{ ok: boolean }>(`/api/sessions/${enc(sid)}/recovery/requarantine`, {})

export const retireDestination = (id: string, confirm: string, o?: FreshFactorOpts) =>
  withFreshFactor(0, (cred) => post<{ ok: boolean; lifted: boolean }>(
    `/api/recordings/continuity/destinations/${id.split('/').map(enc).join('/')}/retire`, { confirm, ...cred }), o)

export const resolveConflict = (h: Pick<ConflictHead, 'n' | 'mac'>, confirm: string, o?: FreshFactorOpts) =>
  withFreshFactor(0, (cred) => post<{ ok: boolean; lifted: boolean; rejected: number }>(
    '/api/recordings/continuity/conflict/resolve', { n: h.n, mac: h.mac, confirm, ...cred }), o)

export const retryMigration = (sid: string, hostId: number, o?: FreshFactorOpts) =>
  withFreshFactor(hostId, (cred) => post<{ ok: boolean }>(`/api/recordings/migration/${enc(sid)}/retry`, { ...cred }), o)

export const discardMigration = (sid: string, hostId: number, confirm: string, o?: FreshFactorOpts) =>
  withFreshFactor(hostId, (cred) => post<EraseResult>(`/api/recordings/migration/${enc(sid)}/discard`, { confirm, ...cred }), o)

/** Link-ul de citire auditată a unei înregistrări în `recovery` (descărcare; fiecare citire auditată). */
export const recoveryTranscriptUrl = (sid: string, format: 'out' | 'cast' = 'cast') =>
  `/api/sessions/${enc(sid)}/recovery/transcript?format=${format}`
