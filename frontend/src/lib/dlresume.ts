/* Reluarea download-urilor host→browser DUPĂ UN RELOAD (3.5.13) — partea pură + persistenţa.

   Motorul (lib/downloads.ts) scrie prin File System Access într-un fişier ales de om. Ca să putem
   relua după un reload, ţinem în IndexedDB tot ce nu se poate reconstrui: handle-ul fişierului
   (FileSystemFileHandle e structured-cloneable în IDB — NU în localStorage), host + cale, mărimea,
   validatorul de pe server (ETag `W/"size-mtime"` din `GET /fs/download`) şi CHECKPOINT-ul —
   octeţii despre care ştim sigur că sunt pe disc.

   De ce checkpoint şi nu „octeţii scrişi": Chromium scrie un FileSystemWritableFileStream într-un
   fişier SWAP (`<nume>.crswap`) şi abia la `close()` îl mută peste fişierul ales. Ce s-a scris dar
   n-a fost `close()`-uit se PIERDE la reload. De aceea motorul închide şi redeschide periodic
   writable-ul (`createWritable({ keepExistingData: true })` + `seek`) şi persistă DOAR offset-ul
   comis. Preţul: la redeschidere Chromium copiază fişierul existent în swap (pe ext4/NTFS = copie
   completă; pe APFS/btrfs = clonă ieftină), iar `close()` îl citeşte o dată pentru verificarea Safe
   Browsing. Cost O(fişier) per checkpoint → checkpoint-uri cu pas GEOMETRIC (vezi shouldCheckpoint):
   overhead-ul total rămâne LINIAR — suma offset-urilor comise ≤ ~3× mărimea fişierului, deci până
   la ~3× copiere (la redeschidere) + ~3× citire (la close) în I/O LOCAL, pe lângă scrierea normală
   (estimare din sursele Chromium, nemăsurată pe toate platformele) — iar la un reload pierzi cel
   mult ~1/3 din progres (sau ultimii ≤256 MiB / 30 s la început). Un pas fix ar fi pătratic.

   Verificat în Chromium 153 real (headless, handle-uri OPFS în locul celor din selector — acelaşi
   FileSystemWritableFileStream): octeţii scrişi fără close() lipsesc după un reload; handle-ul trece
   prin IndexedDB între documente; keepExistingData + truncate + seek reia exact; truncate NU mută
   cursorul (de aceea seek după el); createWritable() fără keepExistingData + close = fişier gol.

   Ce NU ţinem: tokenuri, cookie-uri, conţinut. Înregistrările sunt cheiate pe user id (alt cont în
   acelaşi browser nu le vede), expiră după 7 zile fără activitate şi se şterg la logout. */

// ── politica de checkpoint ────────────────────────────────────────────────────────────────
/** pas minim: sub atât nu merită închis/redeschis (costul fix al close/reopen) */
export const CK_MIN_BYTES = 64 * 1024 * 1024
/** la acest pas checkpoint-ul se face imediat, indiferent de timp */
export const CK_BYTES = 256 * 1024 * 1024
/** pas geometric: următorul checkpoint abia după încă 50% din ce e deja comis (cost liniar total) */
export const CK_GROWTH = 0.5
/** sub CK_BYTES (legături lente): checkpoint şi după atâta timp, dacă s-au strâns ≥ CK_MIN_BYTES */
export const CK_INTERVAL_MS = 30_000
/** înregistrările fără activitate mai vechi de atât se şterg la pornire */
export const DL_REC_TTL_MS = 7 * 24 * 3600 * 1000

/** Trebuie comis ACUM ce s-a scris? `committed` = offset-ul deja pe disc, `written` = octeţii scrişi
    în writable-ul curent (incl. cei comişi), `sinceMs` = timp de la ultimul checkpoint.
    Pasul e max(64 MiB, 50% din `committed`) (cu 256 MiB imediat / 30 s sub el): la un fişier de
    40 GB ≈ 12 checkpoint-uri (256 MiB, 512, 768, 1152… ×1.5), nu 160 (cât ar da un pas fix de
    256 MiB, cu cost pătratic: fiecare checkpoint copiază tot fişierul). */
export function shouldCheckpoint(committed: number, written: number, sinceMs: number): boolean {
  const pending = written - committed
  if (!(pending > 0)) return false
  const step = Math.max(CK_MIN_BYTES, committed * CK_GROWTH)
  if (pending < step) return false
  return pending >= CK_BYTES || sinceMs >= CK_INTERVAL_MS
}

/** De unde reluăm: checkpoint-ul persistat, dar niciodată peste ce e REAL pe disc (fişierul poate să fi
    fost trunchiat/înlocuit între timp). Valori invalide → 0 (start over sigur). */
export function resumeOffset(checkpoint: number, actualSize: number): number {
  const ck = Number.isFinite(checkpoint) && checkpoint > 0 ? Math.floor(checkpoint) : 0
  const act = Number.isFinite(actualSize) && actualSize > 0 ? Math.floor(actualSize) : 0
  return Math.min(ck, act)
}

/** totalul din `Content-Range: bytes a-b/TOTAL` (null dacă lipseşte / e `*`) */
export function contentRangeTotal(h: string | null): number | null {
  const m = h ? h.match(/\/(\d+)\s*$/) : null
  return m ? Number(m[1]) : null
}

/** Validatorul răspunsului e acelaşi cu cel de la începutul descărcării? ETag-ul trebuie să existe
    pe AMBELE părţi (fără validator nu putem şti nimic → nu e „acelaşi"); totalul, când se ştie,
    trebuie să fie mărimea salvată. */
export function validatorMatches(saved: { etag: string | null; size: number },
                                 got: { etag: string | null; total: number | null }): boolean {
  if (!saved.etag || !got.etag || saved.etag !== got.etag) return false
  return got.total == null || saved.size <= 0 || got.total === saved.size
}

/** `Last-Modified` → secunde epoch (doar informativ în înregistrare; validatorul e ETag-ul) */
export function lastModifiedSec(h: string | null): number | null {
  const t = h ? Date.parse(h) : NaN
  return Number.isFinite(t) ? Math.floor(t / 1000) : null
}

// ── înregistrarea persistată ──────────────────────────────────────────────────────────────
/** Minimul din FileSystemFileHandle de care avem nevoie (tipurile lipsesc în lib.dom mai vechi). */
export interface FileHandleLike {
  name?: string
  createWritable(o?: { keepExistingData?: boolean }): Promise<WritableLike>
  getFile?(): Promise<{ size: number }>
  queryPermission?(o: { mode: 'read' | 'readwrite' }): Promise<PermissionState>
  requestPermission?(o: { mode: 'read' | 'readwrite' }): Promise<PermissionState>
  remove?(): Promise<void>
}
export interface WritableLike {
  write(d: BufferSource): Promise<void>
  close(): Promise<void>
  abort?(): Promise<void>
  seek?(position: number): Promise<void>
  truncate?(size: number): Promise<void>
}

/** Metadatele persistate. Handle-ul fişierului stă SEPARAT (vezi DlRecStore): lista de la pornire
    nu-l deserializează niciodată. */
export interface DlRecord {
  key: string
  v: 1
  userId: number
  hostId: number
  hostName: string
  path: string
  name: string
  size: number
  etag: string
  mtime: number | null
  /** octeţi COMIŞI pe disc (după un close()) — punctul de reluare */
  checkpoint: number
  created: number
  updated: number
}

export const dlRecKey = (userId: number, hostId: number, path: string) => `${userId}:${hostId}:${path}`
export const isExpired = (r: Pick<DlRecord, 'updated' | 'created'>, now: number) =>
  now - (r.updated || r.created || 0) > DL_REC_TTL_MS

/** Validare defensivă a unei valori citite din IDB (alt build, date stricate): null = de şters. */
export function asRecord(x: unknown): DlRecord | null {
  if (!x || typeof x !== 'object') return null
  const r = x as Partial<DlRecord>
  if (r.v !== 1 || typeof r.key !== 'string' || typeof r.userId !== 'number' || typeof r.hostId !== 'number'
      || typeof r.path !== 'string' || typeof r.etag !== 'string' || !r.etag
      || typeof r.checkpoint !== 'number') return null
  return r as DlRecord
}

/** Stocul (IndexedDB în browser, Map în teste). Metadatele şi handle-urile sunt în DOUĂ locuri:
    `all()` citeşte doar metadatele, iar un handle se deserializează abia la `handle(key)` — adică la
    click-ul pe Resume. Motivul e măsurat: într-un profil off-the-record (contextul implicit al
    Playwright, echivalentul unei ferestre Incognito) citirea unui FileSystemFileHandle din IndexedDB
    a OPRIT tot browserul (Chromium 153 headless). Dacă asta se întâmplă şi în Incognito real, cel
    puţin nu se întâmplă la fiecare încărcare a aplicaţiei, ci doar la un Resume explicit.
    Toate operaţiile sunt best-effort: un IDB blocat înseamnă doar că reluarea după reload lipseşte. */
export interface DlRecStore {
  /** doar metadatele (niciun handle deserializat) */
  all(): Promise<unknown[]>
  /** scrie metadatele; handle-ul doar când e dat (prima dată), în aceeaşi tranzacţie */
  put(r: DlRecord, handle?: FileHandleLike): Promise<void>
  /** şterge metadatele ŞI handle-ul */
  del(key: string): Promise<void>
  /** handle-ul unei înregistrări (null dacă lipseşte) — o singură deserializare, la cerere */
  handle(key: string): Promise<FileHandleLike | null>
  /** cheile handle-urilor (fără să le deserializeze) — pentru curăţarea celor rămase fără metadate */
  handleKeys(): Promise<string[]>
}

/** La pornire: înregistrările CONTULUI curent, valide şi neexpirate. Cele expirate sau stricate se
    şterg (indiferent de cont — sunt gunoi), la fel handle-urile rămase fără metadate; cele ale ALTUI
    cont rămân neatinse şi invizibile. */
export async function loadForUser(store: DlRecStore, userId: number, now: number): Promise<DlRecord[]> {
  let raw: unknown[] = []
  try { raw = await store.all() } catch { return [] }
  const mine: DlRecord[] = []
  const live = new Set<string>()
  for (const x of raw) {
    const r = asRecord(x)
    if (!r) {
      const k = (x as { key?: unknown } | null)?.key
      if (typeof k === 'string') await store.del(k).catch(() => {})
      continue
    }
    if (isExpired(r, now)) { await store.del(r.key).catch(() => {}); continue }
    live.add(r.key)
    if (r.userId === userId) mine.push(r)
  }
  try {
    for (const k of await store.handleKeys()) if (!live.has(k)) await store.del(k).catch(() => {})
  } catch { /* best-effort */ }
  return mine.sort((a, b) => a.created - b.created)
}

/** Logout explicit: uită toate descărcările întrerupte ale contului. */
export async function forgetUser(store: DlRecStore, userId: number): Promise<void> {
  let raw: unknown[] = []
  try { raw = await store.all() } catch { return }
  for (const x of raw) {
    const r = x as { key?: unknown; userId?: unknown } | null
    if (r && typeof r.key === 'string' && r.userId === userId) await store.del(r.key).catch(() => {})
  }
}

// ── IndexedDB ─────────────────────────────────────────────────────────────────────────────
const DB_NAME = 'webterm-transfers'
const META = 'downloads'
const HANDLES = 'handles'

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => {
      const d = req.result
      if (!d.objectStoreNames.contains(META)) d.createObjectStore(META, { keyPath: 'key' })
      if (!d.objectStoreNames.contains(HANDLES)) d.createObjectStore(HANDLES)   // cheie = key-ul metadatelor
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
    req.onblocked = () => reject(new Error('idb blocked'))
  })
}

function idbStore(): DlRecStore {
  let dbp: Promise<IDBDatabase> | null = null
  const db = () => (dbp ??= openDb().catch((e) => { dbp = null; throw e }))
  const tx = <T>(stores: string[], mode: IDBTransactionMode, fn: (t: IDBTransaction) => IDBRequest<T> | void): Promise<T> =>
    db().then((d) => new Promise<T>((resolve, reject) => {
      const t = d.transaction(stores, mode)
      const req = fn(t)
      t.oncomplete = () => resolve(req ? req.result : (undefined as T))
      t.onerror = () => reject(t.error)
      t.onabort = () => reject(t.error)
    }))
  return {
    all: () => tx([META], 'readonly', (t) => t.objectStore(META).getAll()),
    put: (r, h) => tx(h ? [META, HANDLES] : [META], 'readwrite', (t) => {
      t.objectStore(META).put(r)
      if (h) t.objectStore(HANDLES).put(h, r.key)
    }),
    del: (k) => tx([META, HANDLES], 'readwrite', (t) => {
      t.objectStore(META).delete(k)
      t.objectStore(HANDLES).delete(k)
    }),
    handle: (k) => tx([HANDLES], 'readonly', (t) => t.objectStore(HANDLES).get(k))
      .then((h) => (h && typeof (h as FileHandleLike).createWritable === 'function' ? h as FileHandleLike : null)),
    handleKeys: () => tx([HANDLES], 'readonly', (t) => t.objectStore(HANDLES).getAllKeys())
      .then((ks) => ks.filter((k): k is string => typeof k === 'string')),
  }
}

/** stocul implicit: IndexedDB dacă există, altfel un no-op (reluarea după reload indisponibilă) */
export function defaultStore(): DlRecStore {
  if (typeof indexedDB === 'undefined') {
    return { all: async () => [], put: async () => {}, del: async () => {}, handle: async () => null, handleKeys: async () => [] }
  }
  return idbStore()
}
