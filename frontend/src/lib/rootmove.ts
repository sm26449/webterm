/* Uploads into folders the agent's user cannot write (3.6.9).

   Files acts as the AGENT's user (often an unprivileged `webterm`), not as whoever the terminal
   became with sudo — by design. When a write is refused, the person gets three ways out:
     1. grant access — a `setfacl` command to COPY (never run by us);
     2. "Upload and move as root" — the file goes to the agent's inbox (written as the agent's user),
        then a `sudo sh -c …` command is TYPED, not run, into their own terminal for that host. It
        reads the staged file as the agent's user and installs it only if its SHA-256 matches the
        bytes uploaded through the gateway (the inbox belongs to that user, who could swap it);
     3. upload to the agent's home instead.
   The command text comes from the gateway (gateway/app/rootmove.py: validated values, shlex-quoted,
   round-trip checked), AFTER the uploads (it carries their hashes). Typing it reuses the terminal's
   insert path (lib/transfers.ts) — the same one that types an uploaded file's path — so it passes
   the same gates as a keystroke: a read-only or muted session types nothing, and the server
   enforces the session's write access again. It is typed only as a bracketed paste at a prompt
   (never as keystrokes into mc/vim/less), and no newline is ever sent: the person reads the
   command and presses Enter. */
import { api, ApiError } from './api'
import { startUpload } from './uploads'
import { uploadStore } from './uploadStore'
import { isSafeToType, shellQuote, typeIntoOutcome, type TypeOutcome } from './transfers'

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


export { isSafeToType }

/** Tastează comanda în terminalul `sid` FĂRĂ Enter, ca bracketed paste şi doar la un prompt
    (lib/transfers.ts typeIntoOutcome). Altceva decât 'typed' = nimic tastat → „Copy".
    Fără „Tastează oricum" aici (hotfix 3.6.13, decizie): pentru o CALE după 'notPrompt' există
    typeIntoConfirmed (un CLI ca Claude Code o aşteaptă), dar o comandă `sudo install …` tastată într-un
    program necunoscut (un REPL, un ssh spre alt host, mc) e mult mai riscantă — rămâne doar Copy. */
export function typeCommandOutcome(sid: string | undefined, cmd: string): TypeOutcome {
  return typeIntoOutcome(sid, cmd)
}
export const typeCommandInto = (sid: string | undefined, cmd: string): boolean => typeCommandOutcome(sid, cmd) === 'typed'

export interface RootMovePlan { plan_id: string; uploads: { name: string; upload_path: string }[]; inbox: string }

export async function planRootMove(hostId: number, dir: string, names: string[]): Promise<RootMovePlan> {
  return api<RootMovePlan>(`/api/hosts/${hostId}/fs/root-move`, {
    method: 'POST', body: JSON.stringify({ dir, names }),
  })
}

/** Comanda, DUPĂ upload: gateway-ul o construieşte cu SHA-256-ul octeţilor care au trecut prin el. */
export async function rootMoveCommand(hostId: number, planId: string): Promise<string> {
  const r = await api<{ command: string }>(`/api/hosts/${hostId}/fs/root-move/${encodeURIComponent(planId)}/command`,
    { method: 'POST' })
  return r.command
}

export interface RootMoveResult {
  command: string
  /** comanda a fost tastată în terminalul curent (altfel: de copiat) */
  typed: boolean
  /** de ce NU a fost tastată: 'notPrompt' = în prim-plan rulează un program (mc, vim, less…), nu un shell */
  outcome: TypeOutcome | 'none'
  /** fişierele care n-au ajuns în inbox (atunci nu există comandă) */
  failed: string[]
}

/** Upload în inbox-ul agentului + comanda `sudo` tastată (nu rulată) în terminalul `sid`.
    Comanda există DOAR dacă toate fişierele au ajuns în inbox: gateway-ul o construieşte cu hash-ul
    fiecăruia, iar comanda refuză un fişier schimbat între timp. */
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
  if (failed.length) return { command: '', typed: false, outcome: 'none', failed }
  const command = await rootMoveCommand(o.hostId, plan.plan_id)
  const outcome = typeCommandOutcome(o.sid, command)
  return { command, typed: outcome === 'typed', outcome, failed }
}
