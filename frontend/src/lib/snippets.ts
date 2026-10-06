import type { Host, Snippet } from './api'

/** Parametrii unui snippet: placeholder-ele `{{nume}}` din corp devin câmpuri (terminal ŞI flotă). */
export const snippetParams = (body: string): string[] =>
  [...new Set([...body.matchAll(/\{\{\s*([\w.-]+)\s*\}\}/g)].map((m) => m[1]))]

export const fillSnippet = (body: string, values: Record<string, string>): string =>
  body.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (_, k: string) => values[k] ?? '')

/** Etichetele-ţintă ale unui snippet (consola de flotă); [] = fără ţinte. */
export const snippetTags = (s: Pick<Snippet, 'targets'>): string[] => s.targets?.tags ?? []

/** Câmpul liber „prod, web" → lista trimisă serverului. Serverul normalizează oricum (lowercase,
    dedup, 32 car.) — aici doar despărţim, ca UI-ul să arate aceleaşi chip-uri pe care le va stoca. */
export const parseTagInput = (s: string): string[] => {
  const out: string[] = []
  for (const raw of s.replace(/,/g, ' ').split(/\s+/)) {
    const tag = raw.trim().toLowerCase().slice(0, 32)
    if (tag && !out.includes(tag)) out.push(tag)
  }
  return out
}

/** Corpul `targets` pentru POST/PATCH: listă goală = null (şterge ţintele). */
export const targetsPayload = (tags: string[]): { tags: string[] } | null =>
  tags.length ? { tags } : null

/** Hosturile (deja filtrate la „rulabile") care poartă ORICARE dintre etichete. */
export const hostsMatchingTags = (hosts: Host[], tags: string[]): Host[] => {
  if (!tags.length) return []
  const want = new Set(tags.map((x) => x.toLowerCase()))
  return hosts.filter((h) => (h.tags ?? []).some((x) => want.has(x.toLowerCase())))
}

/** Etichetele distincte ale hosturilor selectate — propunerea pentru „ţine minte ţintele". */
export const tagsOfHosts = (hosts: Host[]): string[] => {
  const out: string[] = []
  for (const h of hosts) for (const x of h.tags ?? []) if (!out.includes(x)) out.push(x)
  return out
}

/** Ordinea din consola de flotă: întâi cele cu ţinte (sunt „comenzi de flotă" propriu-zise),
    apoi restul; în fiecare grup, alfabetic (stabil faţă de ordinea serverului). */
export const sortForFleet = (snips: Snippet[]): Snippet[] =>
  [...snips].sort((a, b) => {
    const ta = snippetTags(a).length ? 0 : 1
    const tb = snippetTags(b).length ? 0 : 1
    return ta - tb || a.title.localeCompare(b.title)
  })

// ── Migrarea one-time a comenzilor de flotă din localStorage ─────────────────────────────
// Până în 3.5.4 comenzile salvate în consola de flotă trăiau doar în browser (`wt-fleet-saved`).
// La prima deschidere a consolei după upgrade le urcăm ca snippet-uri. Reguli:
//  - dedup pe CORP: o comandă care există deja pe server (sub orice titlu) nu se mai urcă;
//  - cheia locală se şterge DOAR dacă toate au ajuns pe server; altfel rămâne şi reîncercăm data
//    viitoare (cele deja urcate sunt sărite atunci, prin dedup) → idempotent;
//  - două taburi deschise simultan: un lacăt în localStorage cu timestamp (expiră singur, ca un
//    tab închis la mijloc să nu blocheze migrarea pentru totdeauna). Chiar dacă lacătul ar fi
//    ocolit, dedup-ul pe corp + idempotenţa serverului (titlu+corp) nu produc duplicate.

export const FLEET_SAVED_KEY = 'wt-fleet-saved'
export const FLEET_MIGRATE_LOCK = 'wt-fleet-saved-migrating'
export const FLEET_MIGRATE_LOCK_TTL = 30_000

export type LegacySaved = { name: string; command: string }
type KV = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

export interface MigrateDeps {
  storage: KV
  list: () => Promise<Pick<Snippet, 'body'>[]>
  create: (s: { title: string; body: string }) => Promise<unknown>
  now?: () => number
  /** identitatea tabului (pentru lacăt) */
  owner?: string
}

export type MigrateResult =
  | { status: 'none' }                                   // nimic de migrat
  | { status: 'locked' }                                 // alt tab migrează chiar acum
  | { status: 'done'; uploaded: number; skipped: number }
  | { status: 'partial'; uploaded: number; failed: number }

/** Intrările valide din valoarea veche (JSON stricat / forme ciudate → ignorate). */
export function parseLegacySaved(raw: string | null): LegacySaved[] | null {
  if (raw == null) return null
  let v: unknown
  try { v = JSON.parse(raw) } catch { return [] }
  if (!Array.isArray(v)) return []
  return v.filter((x): x is LegacySaved =>
    !!x && typeof x === 'object' && typeof (x as LegacySaved).command === 'string'
      && (x as LegacySaved).command.trim() !== '')
    .map((x) => ({ name: typeof x.name === 'string' ? x.name : '', command: x.command }))
}

const safe = <T,>(f: () => T, dflt: T): T => { try { return f() } catch { return dflt } }

export async function migrateFleetSaved(deps: MigrateDeps): Promise<MigrateResult> {
  const { storage } = deps
  const now = deps.now ?? (() => Date.now())
  const owner = deps.owner ?? Math.random().toString(36).slice(2)
  const items = parseLegacySaved(safe(() => storage.getItem(FLEET_SAVED_KEY), null))
  if (items === null) return { status: 'none' }

  // lacătul: unul viu al ALTUI tab → nu ne atingem (va termina el, sau expiră şi reluăm noi)
  const held = safe(() => JSON.parse(storage.getItem(FLEET_MIGRATE_LOCK) || 'null'), null) as
    { owner?: string; ts?: number } | null
  if (held && held.owner !== owner && typeof held.ts === 'number' && now() - held.ts < FLEET_MIGRATE_LOCK_TTL) {
    return { status: 'locked' }
  }
  safe(() => storage.setItem(FLEET_MIGRATE_LOCK, JSON.stringify({ owner, ts: now() })), undefined)
  // re-citire: dacă două taburi au scris aproape simultan, câştigă ultimul scris; celălalt iese
  const mine = safe(() => JSON.parse(storage.getItem(FLEET_MIGRATE_LOCK) || 'null'), null) as { owner?: string } | null
  if (mine && mine.owner !== owner) return { status: 'locked' }

  const release = () => safe(() => {
    const cur = JSON.parse(storage.getItem(FLEET_MIGRATE_LOCK) || 'null')
    if (!cur || cur.owner === owner) storage.removeItem(FLEET_MIGRATE_LOCK)
  }, undefined)

  try {
    if (!items.length) {                      // cheie goală/coruptă: nimic de salvat din ea
      safe(() => storage.removeItem(FLEET_SAVED_KEY), undefined)
      return { status: 'done', uploaded: 0, skipped: 0 }
    }
    let existing: Pick<Snippet, 'body'>[]
    try { existing = await deps.list() } catch { return { status: 'partial', uploaded: 0, failed: items.length } }
    const bodies = new Set(existing.map((s) => s.body.trim()))
    let uploaded = 0, skipped = 0, failed = 0
    for (const it of items) {
      const body = it.command.trim()
      if (bodies.has(body)) { skipped++; continue }
      const title = (it.name.trim() || body).slice(0, 60)
      try {
        await deps.create({ title, body })
        bodies.add(body)
        uploaded++
      } catch {
        failed++
      }
    }
    if (failed) return { status: 'partial', uploaded, failed }
    safe(() => storage.removeItem(FLEET_SAVED_KEY), undefined)
    return { status: 'done', uploaded, skipped }
  } finally {
    release()
  }
}
