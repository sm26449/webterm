import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  BACKOFF_CAP_MS, backoffMs, classifyUpKeys, crc32, dirName, etaSec, fmtBytes, fmtEta, forgetUploads,
  hideUploads, isLegacyUpKey, nextChunkSize, parseUpLsKey, parseUploadMeta, pauseUpload, refusedForGood, resolveResync,
  restoreOrphans, setUploadUser, speedTracker, startUpload, UP_CHUNK, UP_CHUNK_MAX, UP_CHUNK_MIN, upLsKey,
} from './uploads'
import { ApiError } from './api'
import { hostJobSig, uploadStore } from './uploadStore'
import type { UploadJob } from './uploadStore'

const UID = 'a'.repeat(32)

describe('metadate persistate (wt_up_*)', () => {
  it('cheia (cheiată pe cont) se construieşte şi se parsează înapoi, chiar cu `_` în cale', () => {
    const k = upLsKey(4, 7, '/srv/my_dir/big_file.iso', 17_000_000_000, 1700000000000)
    expect(k.startsWith('wt_up_u4_7_')).toBe(true)
    expect(parseUpLsKey(k)).toEqual({ userId: 4, hostId: 7, dest: '/srv/my_dir/big_file.iso', size: 17_000_000_000, lastModified: 1700000000000 })
    expect(parseUpLsKey('wt_lang')).toBeNull()
  })

  it('cheile VECHI, fără cont, nu se parsează → legacy', () => {
    expect(parseUpLsKey('wt_up_7_/srv/a.iso_10_20')).toBeNull()
    expect(isLegacyUpKey('wt_up_7_/srv/a.iso_10_20')).toBe(true)
    expect(isLegacyUpKey(upLsKey(1, 7, '/srv/a.iso', 10, 20))).toBe(false)
    expect(isLegacyUpKey('wt_lang')).toBe(false)
  })

  it('classifyUpKeys: ale mele / vechi / ale altora (u1 ≠ u12)', () => {
    const mine = upLsKey(1, 2, '/a', 1, 1)
    const other = upLsKey(12, 2, '/a', 1, 1)
    const legacy = 'wt_up_2_/a_1_1'
    expect(classifyUpKeys([mine, other, legacy, 'wt_theme'], 1)).toEqual({ mine: [mine], legacy: [legacy], others: [other] })
  })

  it('valoare uid simplu: metadatele se reconstruiesc din cheie, pos necunoscut = 0', () => {
    const k = upLsKey(1, 3, '/tmp/a_b.bin', 10, 20)
    const m = parseUploadMeta(UID, k)
    expect(m).toMatchObject({ uid: UID, hostId: 3, dest: '/tmp/a_b.bin', name: 'a_b.bin', size: 10, lastModified: 20, pos: 0, hostName: '' })
  })

  it('format JSON: se citeşte întreg', () => {
    const raw = JSON.stringify({ uid: UID, hostId: 2, hostName: 'nas', dest: '/x/y.iso', name: 'y.iso', size: 5, lastModified: 9, pos: 3, updated: 1 })
    expect(parseUploadMeta(raw, 'wt_up_u1_2_/x/y.iso_5_9')).toEqual({ uid: UID, hostId: 2, hostName: 'nas', dest: '/x/y.iso', name: 'y.iso', size: 5, lastModified: 9, pos: 3, updated: 1 })
  })

  it('valori corupte → null (cheia e ştearsă de restoreOrphans)', () => {
    expect(parseUploadMeta('not json, not hex', 'wt_up_u1_1_/a_1_1')).toBeNull()
    expect(parseUploadMeta(JSON.stringify({ uid: 'zz' }), 'wt_up_u1_1_/a_1_1')).toBeNull()
    expect(parseUploadMeta(null, 'wt_up_u1_1_/a_1_1')).toBeNull()
    expect(parseUploadMeta(UID, 'wt_up_broken')).toBeNull()   // uid simplu, dar cheia nu se poate parsa
  })
})

describe('upload-uri neterminate per cont (restoreOrphans / hideUploads / forgetUploads)', () => {
  class FakeStorage {
    m = new Map<string, string>()
    get length() { return this.m.size }
    key(i: number) { return [...this.m.keys()][i] ?? null }
    getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
    setItem(k: string, v: string) { this.m.set(k, v) }
    removeItem(k: string) { this.m.delete(k) }
  }
  let storage: FakeStorage
  let fetched: string[]
  const meta = (uid: string, hostId: number, dest: string) =>
    JSON.stringify({ uid, hostId, hostName: 'nas', dest, name: dest.slice(1), size: 100, lastModified: 1, pos: 40, updated: 1 })
  const U1 = '1'.repeat(32), U2 = '2'.repeat(32), U3 = '3'.repeat(32)
  beforeEach(() => {
    storage = new FakeStorage()
    fetched = []
    vi.stubGlobal('window', { localStorage: storage, addEventListener: () => {} })
    vi.stubGlobal('document', { addEventListener: () => {}, visibilityState: 'visible' })
    vi.stubGlobal('fetch', (u: string) => { fetched.push(u); return Promise.resolve(new Response(null)) })
    for (const id of [...uploadStore.snapshot().keys()]) uploadStore.remove(id)
  })
  afterEach(() => {
    forgetUploads()       // curăţă controlerele modulului între teste
    for (const id of [...uploadStore.snapshot().keys()]) uploadStore.remove(id)
    vi.unstubAllGlobals()
  })

  it('arată doar orfanii contului curent, şterge cheile vechi, nu atinge alte conturi', () => {
    storage.setItem(upLsKey(5, 1, '/a.iso', 100, 1), meta(U1, 1, '/a.iso'))
    storage.setItem(upLsKey(6, 1, '/b.iso', 100, 1), meta(U2, 1, '/b.iso'))
    storage.setItem('wt_up_1_/c.iso_100_1', U3)                  // format vechi, fără cont
    storage.setItem('wt_theme', 'dark')
    setUploadUser(5)
    restoreOrphans(5)
    const rows = [...uploadStore.snapshot().values()]
    expect(rows.map((r) => [r.id, r.state])).toEqual([[U1, 'orphan']])
    expect(storage.getItem('wt_up_1_/c.iso_100_1')).toBeNull()
    expect(storage.getItem(upLsKey(6, 1, '/b.iso', 100, 1))).not.toBeNull()
    expect(storage.getItem('wt_theme')).toBe('dark')
  })

  it('fără cont cunoscut nu arată nimic şi nu şterge nimic', () => {
    storage.setItem('wt_up_1_/c.iso_100_1', U3)
    restoreOrphans(null)
    expect(uploadStore.snapshot().size).toBe(0)
    expect(storage.getItem('wt_up_1_/c.iso_100_1')).toBe(U3)
  })

  it('expirarea sesiunii ascunde rândurile, dar cheile rămân pentru acelaşi cont', () => {
    const k = upLsKey(5, 1, '/a.iso', 100, 1)
    storage.setItem(k, meta(U1, 1, '/a.iso'))
    setUploadUser(5)
    restoreOrphans(5)
    hideUploads()
    expect(uploadStore.snapshot().size).toBe(0)
    expect(storage.getItem(k)).not.toBeNull()
    setUploadUser(5)
    restoreOrphans(5)
    expect(uploadStore.get(U1)?.state).toBe('orphan')
  })

  it('logout explicit: uită cheile + rândurile contului, cere ştergerea temp-ului, lasă alte conturi', () => {
    const mine = upLsKey(5, 1, '/a.iso', 100, 1)
    const other = upLsKey(6, 1, '/b.iso', 100, 1)
    storage.setItem(mine, meta(U1, 1, '/a.iso'))
    storage.setItem(other, meta(U2, 1, '/b.iso'))
    setUploadUser(5)
    restoreOrphans(5)
    forgetUploads()
    expect(storage.getItem(mine)).toBeNull()
    expect(storage.getItem(other)).not.toBeNull()
    expect(uploadStore.snapshot().size).toBe(0)
    expect(fetched).toEqual([`/api/hosts/1/fs/upload?path=%2Fa.iso&upload_id=${U1}`])
    restoreOrphans(5)                                          // nimic de restaurat după logout
    expect(uploadStore.snapshot().size).toBe(0)
  })
})

// Bucla reală (startUpload → runLoop) cu un XMLHttpRequest fals: sonda de status răspunde prin
// `fetch` (stub), felia prin FakeXHR, care răspunde cu ce îi spune testul (refuz definitiv al
// hostului, disc plin, 2xx, sau „atârnă" până la pauză). Fără jsdom — doar globalele atinse.
describe('refuz definitiv şi izolarea între conturi (FS-01 / FL-06, audit 2026-10-17)', () => {
  class FakeStorage {
    m = new Map<string, string>()
    get length() { return this.m.size }
    key(i: number) { return [...this.m.keys()][i] ?? null }
    getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
    setItem(k: string, v: string) { this.m.set(k, v) }
    removeItem(k: string) { this.m.delete(k) }
  }
  type Reply = { status: number; body: string; code?: string } | 'hang'
  let storage: FakeStorage
  let reply: Reply
  let aborted: number
  class FakeXHR {
    static inflight: FakeXHR[] = []
    status = 0
    responseText = ''
    timeout = 0
    upload = { onprogress: null as null | ((ev: { lengthComputable: boolean; loaded: number }) => void) }
    onload: null | (() => void) = null
    onerror: null | (() => void) = null
    ontimeout: null | (() => void) = null
    onabort: null | (() => void) = null
    private hdr: string | null = null
    open() { /* url-ul nu contează: un singur upload per test */ }
    getResponseHeader() { return this.hdr }
    send() {
      FakeXHR.inflight.push(this)
      if (reply === 'hang') return
      const r = reply
      queueMicrotask(() => {
        this.status = r.status; this.responseText = r.body; this.hdr = r.code ?? null
        this.onload?.()
      })
    }
    abort() { aborted++; queueMicrotask(() => this.onabort?.()) }
  }
  const refusal = (code: string): Reply =>
    ({ status: 400, code, body: JSON.stringify({ detail: `refused: ${code}`, code, vars: { user: 'webterm', dir: '/srv' } }) })
  const file = (name: string, lm = 1) => new File([new Uint8Array(16)], name, { lastModified: lm })
  const metaOf = (uid: string, dest: string, size: number, lm: number) =>
    JSON.stringify({ uid, hostId: 1, hostName: 'nas', dest, name: dest.slice(1), size, lastModified: lm, pos: 0, updated: 1 })
  const rows = () => [...uploadStore.snapshot().values()].filter((j) => !j.dir || j.dir === 'up')
  const U1 = '1'.repeat(32), U2 = '2'.repeat(32)
  beforeEach(() => {
    storage = new FakeStorage()
    reply = 'hang'
    aborted = 0
    FakeXHR.inflight = []
    vi.stubGlobal('window', { localStorage: storage, addEventListener: () => {},
                              setTimeout, clearTimeout, setInterval, clearInterval, dispatchEvent: () => true })
    vi.stubGlobal('document', { addEventListener: () => {}, visibilityState: 'visible' })
    vi.stubGlobal('navigator', { languages: ['en'], language: 'en' })
    vi.stubGlobal('XMLHttpRequest', FakeXHR)
    // sonda de status (offset 0, fără CRC) şi commit-ul: ambele prin fetch → 200
    vi.stubGlobal('fetch', () => Promise.resolve(new Response(JSON.stringify({ offset: 0 }), { status: 200 })))
    for (const id of [...uploadStore.snapshot().keys()]) uploadStore.remove(id)
  })
  afterEach(() => {
    forgetUploads()
    for (const id of [...uploadStore.snapshot().keys()]) uploadStore.remove(id)
    vi.unstubAllGlobals()
  })

  it('FS-01: refuz definitiv → rândul `err` rămâne (cu motivul), cheia dispare, restoreOrphans nu-l învie', async () => {
    reply = refusal('files.writeDenied')
    setUploadUser(5)
    const f = file('x.bin')
    const k = upLsKey(5, 1, '/srv/x.bin', f.size, f.lastModified)
    const id = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/x.bin', file: f })
    expect(uploadStore.get(id)).toMatchObject({ state: 'err', errorCode: 'files.writeDenied', owner: 5 })
    expect(storage.getItem(k)).toBeNull()                      // ÎNAINTE: cheia rămânea (scrisă la pornire)
    // reload: memoria se pierde, rămâne doar localStorage → niciun „orfan 0 %"
    hideUploads()
    setUploadUser(5)
    restoreOrphans(5)
    expect(rows()).toEqual([])
  })

  it('FS-01: acelaşi fişier re-tras după refuz regăseşte ACELAŞI rând (nu un al doilea), apoi cheia revine la succes', async () => {
    reply = refusal('files.dirMissing')
    setUploadUser(5)
    const f = file('y.bin')
    const id = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/y.bin', file: f })
    expect(uploadStore.get(id)?.state).toBe('err')
    reply = { status: 200, body: JSON.stringify({ offset: f.size }) }
    const id2 = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/y.bin', file: f })
    expect(id2).toBe(id)
    expect(rows().map((j) => [j.id, j.state])).toEqual([[id, 'done']])
  })

  it('FS-01: disc plin → rândul `err`, dar cheia RĂMÂNE (temp-ul parţial merită reluat)', async () => {
    reply = refusal('files.noSpaceAt')
    setUploadUser(5)
    const f = file('z.bin')
    const k = upLsKey(5, 1, '/srv/z.bin', f.size, f.lastModified)
    const id = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/z.bin', file: f })
    expect(uploadStore.get(id)).toMatchObject({ state: 'err', errorCode: 'files.noSpaceAt' })
    expect(storage.getItem(k)).not.toBeNull()
    hideUploads()
    setUploadUser(5)
    restoreOrphans(5)
    expect(rows().map((j) => [j.id, j.state])).toEqual([[id, 'orphan']])
  })

  it('FS-01 (P1): refuz definitiv DUPĂ felii aterizate → cheia RĂMÂNE (temp-ul de pe host merită reluat); fără nimic aterizat → dispare', async () => {
    // sonda de status spune că 8 din 16 octeţi sunt deja pe host (sesiune anterioară / felie anterioară)
    vi.stubGlobal('fetch', () => Promise.resolve(new Response(JSON.stringify({ offset: 8 }), { status: 200 })))
    for (const code of ['files.agentInternal', 'files.readOnlyAt', 'files.writeDenied']) {
      reply = refusal(code)
      setUploadUser(5)
      const f = file(`${code}.bin`)
      const k = upLsKey(5, 1, `/srv/${code}.bin`, f.size, f.lastModified)
      const id = await startUpload({ hostId: 1, hostName: 'nas', dest: `/srv/${code}.bin`, file: f })
      expect(uploadStore.get(id)).toMatchObject({ state: 'err', errorCode: code, pos: 8 })
      expect(storage.getItem(k), code).not.toBeNull()          // ÎNAINTE: ştearsă indiferent de `landed`
      hideUploads()
      setUploadUser(5)
      restoreOrphans(5)
      expect(rows().map((j) => [j.id, j.state, j.pos])).toEqual([[id, 'orphan', 8]])
      forgetUploads()
    }
    // acelaşi refuz cu NIMIC aterizat (offset 0) → cheia dispare, niciun orfan
    vi.stubGlobal('fetch', () => Promise.resolve(new Response(JSON.stringify({ offset: 0 }), { status: 200 })))
    reply = refusal('files.agentInternal')
    setUploadUser(5)
    const f0 = file('zero.bin')
    const k0 = upLsKey(5, 1, '/srv/zero.bin', f0.size, f0.lastModified)
    const id0 = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/zero.bin', file: f0 })
    expect(uploadStore.get(id0)).toMatchObject({ state: 'err', errorCode: 'files.agentInternal', pos: 0 })
    expect(storage.getItem(k0)).toBeNull()
    hideUploads()
    setUploadUser(5)
    restoreOrphans(5)
    expect(rows()).toEqual([])
  })

  it('refusedForGood: decizia pură — definitiv + landed 0 → şterge; definitiv + landed > 0 → păstrează; noSpace păstrează mereu', () => {
    const k = upLsKey(5, 1, '/srv/p.bin', 16, 1)
    const def = (code: string) => new ApiError(400, 'refused', code)
    expect(refusedForGood(def('files.writeDenied'), 0, k)).toBe(true)
    expect(refusedForGood(def('files.agentInternal'), 0, k)).toBe(true)
    expect(refusedForGood(def('files.agentInternal'), 8, k)).toBe(false)   // ÎNAINTE: true (landed ignorat)
    expect(refusedForGood(def('files.readOnlyAt'), 1, k)).toBe(false)
    expect(refusedForGood(def('files.noSpaceAt'), 0, k)).toBe(false)
    expect(refusedForGood(new Error('network'), 0, k)).toBe(false)
  })

  it('FL-06: rândurile err/done/paused ale lui A dispar la setUploadUser(B); cheile lui A rămân', async () => {
    setUploadUser(5)
    // err (cu File în controler → ar oferi Retry)
    reply = refusal('files.noSpaceAt')
    const fe = file('e.bin')
    const ke = upLsKey(5, 1, '/srv/e.bin', fe.size, fe.lastModified)
    const idErr = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/e.bin', file: fe })
    // done (fără controler: File-ul e eliberat la commit; rândul zace până la expirare)
    reply = { status: 200, body: JSON.stringify({ offset: 16 }) }
    const idDone = await startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/d.bin', file: file('d.bin') })
    // paused (felie în zbor, pusă pe pauză) — uid cunoscut dinainte, din metadatele persistate
    const fp = file('p.bin', 7)
    const kp = upLsKey(5, 1, '/srv/p.bin', fp.size, 7)
    storage.setItem(kp, metaOf(U1, '/srv/p.bin', fp.size, 7))
    reply = 'hang'
    const pPaused = startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/p.bin', file: fp })
    while (!FakeXHR.inflight.length) await new Promise((r) => setTimeout(r, 1))
    pauseUpload(U1)
    expect(await pPaused).toBe(U1)
    expect(rows().map((j) => [j.id, j.state]).sort()).toEqual([[idErr, 'err'], [idDone, 'done'], [U1, 'paused']].sort())
    // rând al altui modul (download), ca să vedem că nu e atins
    uploadStore.set({ id: 'dl', dir: 'down', hostId: 1, hostName: 'nas', dest: '/x', name: 'x', size: 1, pos: 0, pct: 0,
                      bytesPerSec: 0, etaSec: null, state: 'err', attempts: 1 })

    setUploadUser(6)                                           // contul B, acelaşi browser
    expect(rows()).toEqual([])                                 // ÎNAINTE: toate trei rămâneau, cu Retry
    expect(uploadStore.get('dl')?.state).toBe('err')
    expect(storage.getItem(ke)).not.toBeNull()
    expect(storage.getItem(kp)).not.toBeNull()
    // B nu moşteneşte nici orfanii lui A; A îi regăseşte la login-ul lui
    restoreOrphans(6)
    expect(rows()).toEqual([])
    setUploadUser(5)
    restoreOrphans(5)
    expect(rows().map((j) => [j.id, j.state]).sort()).toEqual([[idErr, 'orphan'], [U1, 'orphan']].sort())
  })

  it('FL-06: sesiune pierdută (authenticated=false, fără logout) → rândurile cu File dispar, feliile în zbor se taie, cheile rămân', async () => {
    setUploadUser(5)
    const f = file('r.bin', 9)
    const k = upLsKey(5, 1, '/srv/r.bin', f.size, 9)
    storage.setItem(k, metaOf(U2, '/srv/r.bin', f.size, 9))
    reply = 'hang'
    const p = startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/r.bin', file: f })
    while (!FakeXHR.inflight.length) await new Promise((r) => setTimeout(r, 1))
    expect(uploadStore.get(U2)?.state).toBe('running')
    hideUploads()
    expect(await p).toBe(U2)
    expect(aborted).toBe(1)
    expect(rows()).toEqual([])                                 // ÎNAINTE: doar `orphan` era scos
    expect(storage.getItem(k)).not.toBeNull()
    setUploadUser(5)
    restoreOrphans(5)
    expect(uploadStore.get(U2)?.state).toBe('orphan')
  })

  it('FL-06: contul se schimbă cât sonda de status e în zbor → nicio „fantomă" a lui A pentru B', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    vi.stubGlobal('fetch', () => gate.then(() => new Response(JSON.stringify({ offset: 0 }), { status: 200 })))
    setUploadUser(5)
    const f = file('g.bin')
    const p = startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/g.bin', file: f })
    await new Promise((r) => setTimeout(r, 1))                 // bucla stă în sonda de status
    setUploadUser(6)                                           // B se autentifică (alt tab / SSO)
    release()
    await p
    expect(rows()).toEqual([])                                 // ÎNAINTE: un rând `running` al lui 5 reapărea
    expect(FakeXHR.inflight).toEqual([])                       // şi nicio felie n-a plecat sub cookie-ul lui B
  })

  it('FS-01: 403 cu alt cod (rolul a pierdut files.write) fără nimic aterizat → cheia dispare; cu temp dintr-o sesiune anterioară rămâne', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })   // backoff-ul reîncercărilor (~1 min)
    try {
      const denied = JSON.stringify({ detail: 'your role does not allow this here (files.write)', code: 'authz.denied' })
      vi.stubGlobal('fetch', () => Promise.resolve(new Response(denied, { status: 403, headers: { 'X-WebTerm-Error': 'authz.denied' } })))
      reply = { status: 403, body: denied, code: 'authz.denied' }
      setUploadUser(5)
      const f = file('a.bin')
      const k = upLsKey(5, 1, '/srv/a.bin', f.size, f.lastModified)
      const p = startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/a.bin', file: f })
      await vi.advanceTimersByTimeAsync(120_000)
      const id = await p
      expect(uploadStore.get(id)).toMatchObject({ state: 'err', errorCode: 'authz.denied' })
      expect(storage.getItem(k)).toBeNull()                    // ÎNAINTE: rămânea → „orfan 0 %" după reload
      // acelaşi refuz, dar cheia spune că o sesiune anterioară a aterizat 8 octeţi (temp pe host)
      const f2 = file('b.bin', 3)
      const k2 = upLsKey(5, 1, '/srv/b.bin', f2.size, 3)
      storage.setItem(k2, JSON.stringify({ ...JSON.parse(metaOf(U2, '/srv/b.bin', f2.size, 3)), pos: 8 }))
      const p2 = startUpload({ hostId: 1, hostName: 'nas', dest: '/srv/b.bin', file: f2 })
      await vi.advanceTimersByTimeAsync(120_000)
      expect(await p2).toBe(U2)
      expect(uploadStore.get(U2)?.state).toBe('err')
      expect(storage.getItem(k2)).not.toBeNull()
    } finally { vi.useRealTimers() }
  })
})

describe('resincronizare după 409/403', () => {
  const pos = 16, end = 24
  it('serverul are deja felia → landed (doar răspunsul s-a pierdut)', () => {
    expect(resolveResync(pos, end, 24)).toEqual({ action: 'landed', pos: 24 })
  })
  it('serverul n-are nimic nou → retry pe aceeaşi felie (CRC rămâne valid)', () => {
    expect(resolveResync(pos, end, 16)).toEqual({ action: 'retry', pos: 16 })
  })
  it('aterizare parţială / alt scriitor → jump la offset-ul real', () => {
    expect(resolveResync(pos, end, 20)).toEqual({ action: 'jump', pos: 20 })
    expect(resolveResync(pos, end, 40)).toEqual({ action: 'jump', pos: 40 })
  })
})

describe('backoff', () => {
  it('1,2,4,8 s apoi plafon de 15 s', () => {
    expect([1, 2, 3, 4, 5, 6, 8].map(backoffMs)).toEqual([1000, 2000, 4000, 8000, 15000, 15000, 15000])
    expect(backoffMs(0)).toBe(1000)
    expect(BACKOFF_CAP_MS).toBe(15000)
  })
})

describe('viteză netezită + ETA', () => {
  it('ignoră eşantioanele sub 1 s şi netezeşte exponenţial', () => {
    const s = speedTracker(0.5)
    expect(s.sample(0, 0)).toBe(0)
    expect(s.sample(500, 500)).toBe(0)                 // prea devreme: nu schimbă nimic
    expect(s.sample(1000, 1000)).toBe(1000)            // prima rată = instantanee (1000 B/s)
    expect(s.sample(4000, 2000)).toBe(2000)            // inst 3000, EWMA 0.5 → 2000
  })
  it('un salt înapoi (felie reluată) reporneşte curat, fără viteză negativă', () => {
    const s = speedTracker()
    s.sample(0, 0); s.sample(8000, 1000)
    expect(s.sample(2000, 2000)).toBe(8000)            // păstrează rata veche, re-ancorează
    s.reset()
    expect(s.rate).toBe(0)
  })
  it('ETA doar când există viteză', () => {
    expect(etaSec(100, 50, 0)).toBeNull()
    expect(etaSec(100, 50, 10)).toBe(5)
    expect(etaSec(100, 100, 10)).toBe(0)
  })
})

describe('formatare', () => {
  const t = (k: string) => ({ 'time.s': 's', 'time.m': 'm', 'time.h': 'h' }[k] ?? k)
  it('octeţi', () => {
    expect(fmtBytes(512)).toBe('512 B')
    expect(fmtBytes(24 * 1024 * 1024)).toBe('24.0 MB')
    expect(fmtBytes(17 * 1024 ** 3)).toBe('17.00 GB')
  })
  it('ETA', () => {
    expect(fmtEta(null, t)).toBe('—')
    expect(fmtEta(45, t)).toBe('45s')
    expect(fmtEta(12 * 60, t)).toBe('12m')
    expect(fmtEta(3600 + 5 * 60, t)).toBe('1h 5m')
  })
  it('directorul ţintei pentru „deschide directorul"', () => {
    expect(dirName('/srv/x/y.iso')).toBe('/srv/x')
    expect(dirName('/y.iso')).toBe('/')
    expect(dirName('y.iso')).toBe('.')
  })
})

describe('felie adaptivă (nextChunkSize)', () => {
  const MB = 1024 * 1024
  it('legătură rapidă (felie sub ţinta joasă) → creşte, plafonat la MAX', () => {
    expect(nextChunkSize(UP_CHUNK, 1000, false)).toBe(UP_CHUNK * 2)      // 8→16 MiB
    expect(nextChunkSize(UP_CHUNK_MAX, 1000, false)).toBe(UP_CHUNK_MAX)  // deja la plafon
  })
  it('legătură lentă (felie peste ţinta înaltă) → scade, podea la MIN', () => {
    expect(nextChunkSize(16 * MB, 20000, false)).toBe(8 * MB)
    expect(nextChunkSize(UP_CHUNK_MIN, 20000, false)).toBe(UP_CHUNK_MIN) // deja la podea
  })
  it('instabil (stall/retry) → scade indiferent de durată', () => {
    expect(nextChunkSize(16 * MB, 500, true)).toBe(8 * MB)
  })
  it('în fereastra ţintă → neschimbat', () => {
    expect(nextChunkSize(UP_CHUNK, 5000, false)).toBe(UP_CHUNK)
  })
  it('rămâne mereu între MIN şi MAX', () => {
    for (const ms of [0, 100, 5000, 99999]) {
      for (const u of [false, true]) {
        const n = nextChunkSize(UP_CHUNK, ms, u)
        expect(n).toBeGreaterThanOrEqual(UP_CHUNK_MIN)
        expect(n).toBeLessThanOrEqual(UP_CHUNK_MAX)
      }
    }
  })
})

describe('crc32 (IEEE, identic cu zlib.crc32 din agent)', () => {
  it('vectorul standard „123456789" = 0xCBF43926, incremental pe două felii', () => {
    const bytes = new TextEncoder().encode('123456789')
    expect(crc32(0, bytes)).toBe(0xCBF43926)
    expect(crc32(crc32(0, bytes.slice(0, 4)), bytes.slice(4))).toBe(0xCBF43926)
  })
})

describe('hostJobSig (FS-05): re-render on state change, not on progress ticks', () => {
  const job = (id: string, hostId: number, state: UploadJob['state'], pct = 0): UploadJob =>
    ({ id, hostId, hostName: 'nas', dest: '/srv/' + id, name: id, size: 100,
       pos: pct, pct, bytesPerSec: 0, etaSec: null, state, attempts: 1 })
  beforeEach(() => { for (const k of [...uploadStore.snapshot().keys()]) uploadStore.remove(k) })
  afterEach(() => { for (const k of [...uploadStore.snapshot().keys()]) uploadStore.remove(k) })

  it('is stable when only progress (pct/pos/speed/eta) changes', () => {
    uploadStore.set(job('a', 1, 'running', 10))
    const s0 = hostJobSig(1)
    uploadStore.patch('a', { pct: 55, pos: 55, bytesPerSec: 1e6, etaSec: 3 })
    expect(hostJobSig(1)).toBe(s0)              // a progress tick must NOT change the signature
  })

  it('changes when a job changes state, is added, or is removed', () => {
    uploadStore.set(job('a', 1, 'running', 10))
    const s0 = hostJobSig(1)
    uploadStore.patch('a', { state: 'done' })
    const s1 = hostJobSig(1)
    expect(s1).not.toBe(s0)
    uploadStore.set(job('b', 1, 'running'))
    expect(hostJobSig(1)).not.toBe(s1)          // a new job
    uploadStore.remove('b')
    expect(hostJobSig(1)).toBe(s1)              // back to just `a:done`
  })

  it('is scoped to the host and excludes orphans', () => {
    uploadStore.set(job('a', 1, 'running'))
    const s0 = hostJobSig(1)
    uploadStore.set(job('other', 2, 'running'))  // another host
    expect(hostJobSig(1)).toBe(s0)               // does not affect host 1's signature
    uploadStore.patch('a', { state: 'orphan' })  // orphan jobs live only in the global bar
    expect(hostJobSig(1)).toBe('')
  })
})
