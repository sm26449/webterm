/* Uploads into folders the agent's user cannot write (3.6.9).

   Files acts as the AGENT's user (often an unprivileged `webterm`), not as whoever the terminal
   became with sudo — by design. When a write is refused, the person gets three ways out:
     1. grant access — a `setfacl` command to COPY (never run by us);
     2. "Upload and move as root" — the file goes to the agent's inbox (written as the agent's user),
        then a `sudo install …` command is TYPED, not run, into their own terminal for that host;
     3. upload to the agent's home instead.
   The command text comes from the gateway (gateway/app/rootmove.py: validated values, shlex-quoted,
   round-trip checked). Typing it reuses the terminal's insert path (lib/transfers.ts) — the same
   one that types an uploaded file's path — so it passes the same gates as a keystroke: a read-only
   or muted session types nothing, and the server enforces the session's write access again. No
   newline is ever sent: the person reads the command and presses Enter. */
import { api, ApiError } from './api'
import { startUpload } from './uploads'
import { uploadStore } from './uploadStore'
import { shellQuote, typeInto } from './transfers'

/** Codurile de refuz care înseamnă „userul agentului nu poate scrie aici" (gateway: _fs_write_error). */
export const WRITE_DENIED = new Set(['files.writeDenied', 'files.writeDeniedMode', 'files.permissionDenied'])
export const isWriteDenied = (code: string | undefined): boolean => !!code && WRITE_DENIED.has(code)
export const errIsWriteDenied = (e: unknown): boolean => e instanceof ApiError && isWriteDenied(e.code)

// ── dosare unde scrierea a fost refuzată (învăţat din refuzuri reale, nu ghicit) ─────────────
// fs_list/fs_stat dau modul dar NU proprietarul (agent v58), deci „nu poate scrie" nu se poate
// deduce corect din listare; îl ştim abia după un refuz. Memorat pe durata paginii, per host.
const denied = new Map<number, Set<string>>()
const listeners = new Set<() => void>()
let version = 0
const bump = () => { version++; listeners.forEach((f) => f()) }
export const deniedStore = {
  subscribe(f: () => void) { listeners.add(f); return () => { listeners.delete(f) } },
  snapshot: () => version,
}
export function markDenied(hostId: number, dir: string): void {
  const s = denied.get(hostId) ?? new Set<string>()
  if (s.has(dir)) return
  s.add(dir); denied.set(hostId, s); bump()
}
export function clearDenied(hostId: number, dir: string): void {
  if (denied.get(hostId)?.delete(dir)) bump()
}
export const isDenied = (hostId: number, dir: string): boolean => !!denied.get(hostId)?.has(dir)

/** Numele de user al agentului e text raportat de agent; îl punem într-o comandă de COPIAT doar
    dacă arată a nume de user POSIX. Altfel nu oferim comanda deloc (fail closed). */
const USER_RE = /^[a-z_][a-z0-9_.-]{0,31}\$?$/i

/** `sudo setfacl -m u:<user>:rwx -- <dir>` — de copiat şi rulat de om, ca root. null dacă userul
    sau dosarul nu sunt utilizabile. */
export function setfaclCommand(user: string | null | undefined, dir: string): string | null {
  if (!user || !USER_RE.test(user) || !dir.startsWith('/') || /[\x00-\x1f\x7f-\x9f]/.test(dir)) return null
  return `sudo setfacl -m u:${user}:rwx -- ${shellQuote(dir)}`
}

/** Caractere care n-au ce căuta într-un text TASTAT în terminal: C0/C1, DEL, separatori de
    linie/paragraf, controale bidi şi zero-width. Serverul le refuză deja; aici e a doua barieră. */
const UNSAFE_TYPED = new RegExp('[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]')
export const isSafeToType = (cmd: string): boolean => !!cmd && cmd.length <= 32768 && !UNSAFE_TYPED.test(cmd)

/** Tastează comanda în terminalul `sid` FĂRĂ Enter. false = nimic tastat (sesiune închisă, doar
    citire, comandă refuzată de verificare) — apelantul oferă atunci „Copy". */
export function typeCommandInto(sid: string | undefined, cmd: string): boolean {
  if (!isSafeToType(cmd)) return false
  return typeInto(sid, cmd)
}

export interface RootMovePlan { uploads: { name: string; upload_path: string }[]; command: string; inbox: string }

export async function planRootMove(hostId: number, dir: string, names: string[]): Promise<RootMovePlan> {
  return api<RootMovePlan>(`/api/hosts/${hostId}/fs/root-move`, {
    method: 'POST', body: JSON.stringify({ dir, names }),
  })
}

export interface RootMoveResult {
  command: string
  /** comanda a fost tastată în terminalul curent (altfel: de copiat) */
  typed: boolean
  /** fişierele care n-au ajuns în inbox (atunci nu tastăm nimic) */
  failed: string[]
}

/** Upload în inbox-ul agentului + comanda `sudo install` tastată (nu rulată) în terminalul `sid`.
    Comanda se tastează DOAR dacă toate fişierele au ajuns în inbox — altfel ar instala ceva lipsă. */
export async function uploadAndMoveAsRoot(o: {
  hostId: number; hostName: string; dir: string; files: { file: File; name: string }[]; sid?: string
}): Promise<RootMoveResult> {
  const plan = await planRootMove(o.hostId, o.dir, o.files.map((f) => f.name))
  const byName = new Map(o.files.map((f) => [f.name, f.file]))
  const failed: string[] = []
  for (const u of plan.uploads) {
    const file = byName.get(u.name)
    if (!file) { failed.push(u.name); continue }
    const id = await startUpload({ hostId: o.hostId, hostName: o.hostName, dest: u.upload_path, name: u.name, file })
    if (uploadStore.get(id)?.state !== 'done') failed.push(u.name)
  }
  if (failed.length) return { command: plan.command, typed: false, failed }
  return { command: plan.command, typed: typeCommandInto(o.sid, plan.command), failed }
}
