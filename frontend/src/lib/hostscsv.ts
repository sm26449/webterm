/* Import CSV de hosturi — parserul şi previzualizarea (fără React, testate în hostscsv.test.ts).

   Fişierul vine de la `GET /api/hosts/export.csv` (alt gateway) sau dintr-un spreadsheet editat
   de mână. Parsăm AICI, în browser, ca omul să vadă un tabel de previzualizare cu un status pe
   fiecare rând ÎNAINTE să trimită ceva; serverul re-verifică oricum totul (`POST /api/hosts/import`
   trece fiecare rând prin aceeaşi validare ca `POST /api/hosts` şi re-detectează duplicatele). */

import type { Host } from './api'

export const CSV_COLUMNS = ['name', 'connection_type', 'hostname', 'port', 'username', 'via_host',
  'folder', 'tags', 'note', 'require_2fa', 'credential_policy', 'auth_method', 'agent_note'] as const

export const IMPORT_MAX = 500

/** RFC 4180: virgulă, ghilimele duble (`""` = o ghilimea), câmpuri citate care pot conţine
    virgule şi rânduri noi; CRLF sau LF; BOM-ul UTF-8 de la început e ignorat. Un rând gol la
    final (fişierul se termină cu CRLF) nu devine un rând de date. */
export function parseCsv(text: string): string[][] {
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let quoted = false
  let i = 0
  const endRow = () => { row.push(cell); rows.push(row); row = []; cell = '' }
  while (i < s.length) {
    const c = s[i]
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { cell += '"'; i += 2; continue }
        quoted = false; i++; continue
      }
      cell += c; i++; continue
    }
    if (c === '"' && cell === '') { quoted = true; i++; continue }
    if (c === ',') { row.push(cell); cell = ''; i++; continue }
    if (c === '\r' && s[i + 1] === '\n') { endRow(); i += 2; continue }
    if (c === '\n' || c === '\r') { endRow(); i++; continue }
    cell += c; i++
  }
  if (cell !== '' || row.length) endRow()
  // rândurile complet goale (linii albe) nu sunt date
  return rows.filter((r) => !(r.length === 1 && r[0].trim() === ''))
}

/** Exportul neutralizează formulele (= + - @ TAB CR la început) cu un `'`; aici îl scoatem —
    EXACT unul, doar când urmează un declanşator (pereche cu `_csv_cell` din gateway/app/api.py). */
export function stripFormulaPrefix(cell: string): string {
  return /^'+[=+\-@\t\r]/.test(cell) ? cell.slice(1) : cell
}

export type CsvRow = Record<(typeof CSV_COLUMNS)[number], string>

/** Text CSV → rânduri cu cheile antetului (coloanele necunoscute sunt ignorate, cele lipsă
    devin ''). `error`: fişier gol / fără coloana `name` (nu e un export de hosturi). */
export function csvToRows(text: string): { rows: CsvRow[]; error?: 'empty' | 'noHeader' } {
  const table = parseCsv(text)
  if (!table.length) return { rows: [], error: 'empty' }
  const head = table[0].map((h) => stripFormulaPrefix(h).trim().toLowerCase())
  if (!head.includes('name') || !head.includes('connection_type')) return { rows: [], error: 'noHeader' }
  const rows = table.slice(1).map((cells) => {
    const r = Object.fromEntries(CSV_COLUMNS.map((k) => [k, ''])) as CsvRow
    head.forEach((h, idx) => {
      if ((CSV_COLUMNS as readonly string[]).includes(h)) r[h as keyof CsvRow] = stripFormulaPrefix(cells[idx] ?? '')
    })
    return r
  })
  return { rows }
}

export type RowStatus =
  | { kind: 'new' | 'agent' }
  | { kind: 'exists'; code: 'hostcsv.duplicate'; vars: { name: string } }
  | { kind: 'error'; code: string; vars?: Record<string, string> }

const TYPES = ['agent', 'ssh', 'ssh-jump', 'telnet', 'telnet-jump']
const JUMP = ['ssh-jump', 'telnet-jump']
const DIRECT = ['ssh', 'ssh-jump', 'telnet', 'telnet-jump']
const SSHLIKE = ['ssh', 'ssh-jump']
const POLICIES = ['stored', 'ask', 'ephemeral']

type Known = { name: string; type: string; hostname: string; port: number | null; username: string }

/** Statusul fiecărui rând, în ACEEAŞI ordine de verificări ca serverul (`_import_row` +
    `_validate_host`): agenţii întâi (ca ţintele jump să-i găsească după nume), apoi restul;
    fiecare rând „creat" intră în setul cunoscut, deci un nume repetat în fişier e duplicat. */
export function previewRows(rows: CsvRow[], hosts: Host[], credentialPolicy = ''): RowStatus[] {
  const known: Known[] = hosts.filter((h) => !h.ephemeral).map((h) => ({
    name: h.name, type: h.connection_type || 'agent', hostname: h.hostname ?? '',
    port: h.ssh_port ?? null, username: h.ssh_username ?? '',
  }))
  const out: RowStatus[] = new Array(rows.length)
  const isAgent = (r: CsvRow) => r.connection_type.trim().toLowerCase() === 'agent'
  const order = [...rows.keys()].sort((a, b) => Number(!isAgent(rows[a])) - Number(!isAgent(rows[b])))
  const lc = (s: string) => s.trim().toLowerCase()
  for (const i of order) {
    const r = rows[i]
    const err = (code: string, vars?: Record<string, string>): RowStatus => ({ kind: 'error', code, vars })
    const ctype = lc(r.connection_type)
    const agent = ctype === 'agent'
    const st = ((): RowStatus | Known => {
      if (!ctype) return err('hostcsv.typeRequired')
      let port: number | null = null
      if (!agent && r.port.trim()) {
        if (!/^\d+$/.test(r.port.trim()) || +r.port < 1 || +r.port > 65535) return err('host.badPort')
        port = +r.port
      }
      let viaNotAgent = false
      if (JUMP.includes(ctype)) {
        const via = r.via_host.trim()
        if (!via) return err('hostcsv.viaRequired')
        const cands = known.filter((k) => lc(k.name) === lc(via))
        const agents = cands.filter((k) => k.type === 'agent')
        if (agents.length > 1) return err('hostcsv.viaAmbiguous', { name: via })
        if (!agents.length && !cands.length) return err('hostcsv.viaMissing', { name: via })
        viaNotAgent = !agents.length
      }
      // validarea comună (ordinea din `_validate_host`)
      if (!TYPES.includes(ctype)) return err('host.badType')
      if (!r.name.trim()) return err('host.nameRequired')
      const policy = agent ? 'stored' : (credentialPolicy || lc(r.credential_policy) || 'ask')
      if (!POLICIES.includes(policy)) return err('host.badCredentialPolicy')
      if (DIRECT.includes(ctype) && !r.hostname.trim()) return err('host.hostnameRequired')
      if (SSHLIKE.includes(ctype) && !r.username.trim()) return err('ssh.userRequired')
      if (SSHLIKE.includes(ctype) && !['password', 'key'].includes(lc(r.auth_method) || 'password')) return err('host.badAuthMethod')
      if (viaNotAgent) return err('sshjump.needsAgent')
      const k: Known = { name: r.name.trim(), type: ctype, hostname: r.hostname.trim(),
        port: agent ? null : (port ?? (ctype.startsWith('telnet') ? 23 : 22)), username: agent ? '' : r.username.trim() }
      const dup = known.some((h) => lc(h.name) === lc(k.name)) || (!agent && known.some((h) =>
        h.type !== 'agent' && lc(h.hostname) === lc(k.hostname) && h.port === k.port && lc(h.username) === lc(k.username)))
      if (dup) return { kind: 'exists', code: 'hostcsv.duplicate', vars: { name: k.name } }
      return k
    })()
    if ('kind' in st) { out[i] = st; continue }
    known.push(st)
    out[i] = { kind: agent ? 'agent' : 'new' }
  }
  return out
}

/** Rândurile de trimis: doar cele bifate, ca obiecte de şiruri (fără `agent_note`). */
export function importPayload(rows: CsvRow[], selected: boolean[]) {
  return rows.filter((_, i) => selected[i]).map((r) =>
    Object.fromEntries(CSV_COLUMNS.filter((k) => k !== 'agent_note').map((k) => [k, r[k]])))
}
