import { describe, expect, it } from 'vitest'
import type { Host, Snippet } from './api'
import {
  FLEET_MIGRATE_LOCK, FLEET_MIGRATE_LOCK_TTL, FLEET_SAVED_KEY, fillSnippet, hostsMatchingTags,
  migrateFleetSaved, parseLegacySaved, parseTagInput, snippetParams, sortForFleet, tagsOfHosts,
  targetsPayload,
} from './snippets'

/** localStorage în memorie (vitest rulează fără DOM) */
function mem(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init))
  return {
    m,
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => { m.set(k, v) },
    removeItem: (k: string) => { m.delete(k) },
  }
}

/** „serverul": listă de snippet-uri + create care poate eşua pe anumite corpuri */
function server(bodies: string[] = [], failOn: Set<string> = new Set()) {
  const rows = bodies.map((body, i) => ({ id: i + 1, title: 't' + i, body }))
  const created: { title: string; body: string }[] = []
  return {
    rows, created,
    list: async () => rows.map((r) => ({ ...r })),
    create: async (s: { title: string; body: string }) => {
      if (failOn.has(s.body)) throw new Error('boom')
      created.push(s)
      rows.push({ id: rows.length + 1, ...s })
      return { id: rows.length }
    },
  }
}

const legacy = (xs: { name: string; command: string }[]) => JSON.stringify(xs)

describe('migrarea comenzilor de flotă din localStorage', () => {
  it('fără cheie → nimic de făcut, serverul nici nu e întrebat', async () => {
    const st = mem()
    let asked = false
    const r = await migrateFleetSaved({ storage: st, list: async () => { asked = true; return [] }, create: async () => ({}) })
    expect(r).toEqual({ status: 'none' })
    expect(asked).toBe(false)
  })

  it('urcă tot, cu dedup pe corp (server + duplicate locale), apoi şterge cheia', async () => {
    const st = mem({ [FLEET_SAVED_KEY]: legacy([
      { name: 'disk', command: 'df -h' },              // există deja pe server (alt titlu)
      { name: 'up', command: 'uptime' },
      { name: 'up again', command: 'uptime' },         // duplicat local
      { name: '', command: 'free -m' },                // fără nume → titlul = comanda
    ]) })
    const srv = server(['df -h'])
    const r = await migrateFleetSaved({ storage: st, list: srv.list, create: srv.create })
    expect(r).toEqual({ status: 'done', uploaded: 2, skipped: 2 })
    expect(srv.created).toEqual([{ title: 'up', body: 'uptime' }, { title: 'free -m', body: 'free -m' }])
    expect(st.getItem(FLEET_SAVED_KEY)).toBeNull()
    expect(st.getItem(FLEET_MIGRATE_LOCK)).toBeNull()         // lacătul eliberat
  })

  it('eşec parţial → cheia RĂMÂNE; a doua rulare urcă doar ce lipseşte (idempotent)', async () => {
    const st = mem({ [FLEET_SAVED_KEY]: legacy([
      { name: 'a', command: 'echo a' }, { name: 'b', command: 'echo b' }, { name: 'c', command: 'echo c' },
    ]) })
    const fail = new Set(['echo b'])
    const srv = server([], fail)
    const r1 = await migrateFleetSaved({ storage: st, list: srv.list, create: srv.create })
    expect(r1).toEqual({ status: 'partial', uploaded: 2, failed: 1 })
    expect(st.getItem(FLEET_SAVED_KEY)).not.toBeNull()
    expect(st.getItem(FLEET_MIGRATE_LOCK)).toBeNull()

    fail.clear()                                               // serverul şi-a revenit
    const r2 = await migrateFleetSaved({ storage: st, list: srv.list, create: srv.create })
    expect(r2).toEqual({ status: 'done', uploaded: 1, skipped: 2 })
    expect(srv.created.map((x) => x.body)).toEqual(['echo a', 'echo c', 'echo b'])   // fără dubluri
    expect(st.getItem(FLEET_SAVED_KEY)).toBeNull()

    const r3 = await migrateFleetSaved({ storage: st, list: srv.list, create: srv.create })
    expect(r3).toEqual({ status: 'none' })
    expect(srv.created).toHaveLength(3)
  })

  it('lista de pe server indisponibilă → nimic urcat, cheia rămâne', async () => {
    const st = mem({ [FLEET_SAVED_KEY]: legacy([{ name: 'a', command: 'echo a' }]) })
    let creates = 0
    const r = await migrateFleetSaved({
      storage: st, list: async () => { throw new Error('offline') }, create: async () => { creates++ },
    })
    expect(r.status).toBe('partial')
    expect(creates).toBe(0)
    expect(st.getItem(FLEET_SAVED_KEY)).not.toBeNull()
    expect(st.getItem(FLEET_MIGRATE_LOCK)).toBeNull()
  })

  it('alt tab ţine lacătul (proaspăt) → nu ne atingem; lacăt expirat → preluăm', async () => {
    const t0 = 1_000_000
    const st = mem({
      [FLEET_SAVED_KEY]: legacy([{ name: 'a', command: 'echo a' }]),
      [FLEET_MIGRATE_LOCK]: JSON.stringify({ owner: 'tab-A', ts: t0 }),
    })
    const srv = server()
    const r1 = await migrateFleetSaved({ storage: st, list: srv.list, create: srv.create, owner: 'tab-B', now: () => t0 + 1000 })
    expect(r1).toEqual({ status: 'locked' })
    expect(srv.created).toHaveLength(0)
    expect(st.getItem(FLEET_MIGRATE_LOCK)).toContain('tab-A')   // lacătul altuia nu se şterge

    const r2 = await migrateFleetSaved({
      storage: st, list: srv.list, create: srv.create, owner: 'tab-B', now: () => t0 + FLEET_MIGRATE_LOCK_TTL + 1,
    })
    expect(r2).toEqual({ status: 'done', uploaded: 1, skipped: 0 })
    expect(st.getItem(FLEET_SAVED_KEY)).toBeNull()
  })

  it('două taburi simultan (acelaşi server) → fiecare comandă urcată o singură dată', async () => {
    const st = mem({ [FLEET_SAVED_KEY]: legacy([{ name: 'a', command: 'echo a' }, { name: 'b', command: 'echo b' }]) })
    const srv = server()
    const [r1, r2] = await Promise.all([
      migrateFleetSaved({ storage: st, list: srv.list, create: srv.create, owner: 'A' }),
      migrateFleetSaved({ storage: st, list: srv.list, create: srv.create, owner: 'B' }),
    ])
    expect([r1.status, r2.status].sort()).toEqual(['done', 'locked'])
    expect(srv.created.map((x) => x.body)).toEqual(['echo a', 'echo b'])
    expect(st.getItem(FLEET_SAVED_KEY)).toBeNull()
  })

  it('valoare coruptă / goală → cheia se şterge, nimic urcat', async () => {
    for (const raw of ['{nu-e-json', '[]', '{"a":1}', '[{"name":"x"},{"command":"  "}]']) {
      const st = mem({ [FLEET_SAVED_KEY]: raw })
      const srv = server()
      const r = await migrateFleetSaved({ storage: st, list: srv.list, create: srv.create })
      expect(r).toEqual({ status: 'done', uploaded: 0, skipped: 0 })
      expect(st.getItem(FLEET_SAVED_KEY)).toBeNull()
      expect(srv.created).toHaveLength(0)
    }
  })

  it('parseLegacySaved păstrează doar intrările cu o comandă', () => {
    expect(parseLegacySaved(null)).toBeNull()
    expect(parseLegacySaved('[{"name":"a","command":"ls"},{"name":1,"command":"pwd"},null,{"command":""}]'))
      .toEqual([{ name: 'a', command: 'ls' }, { name: '', command: 'pwd' }])
  })
})

describe('ţintele pe etichete', () => {
  const h = (id: number, tags: string[]) => ({ id, name: 'h' + id, tags } as unknown as Host)
  const hosts = [h(1, ['prod', 'web']), h(2, ['dev']), h(3, ['prod']), h(4, [])]

  it('hostsMatchingTags: ORICARE etichetă; fără etichete → niciun host', () => {
    expect(hostsMatchingTags(hosts, ['web', 'dev']).map((x) => x.id)).toEqual([1, 2])
    expect(hostsMatchingTags(hosts, ['PROD']).map((x) => x.id)).toEqual([1, 3])
    expect(hostsMatchingTags(hosts, [])).toEqual([])
    expect(hostsMatchingTags(hosts, ['nope'])).toEqual([])
  })
  it('tagsOfHosts: etichetele distincte, în ordine', () => {
    expect(tagsOfHosts([hosts[0], hosts[2], hosts[1]])).toEqual(['prod', 'web', 'dev'])
  })
  it('parseTagInput + targetsPayload', () => {
    expect(parseTagInput(' Prod, web  PROD,,')).toEqual(['prod', 'web'])
    expect(targetsPayload([])).toBeNull()
    expect(targetsPayload(['a'])).toEqual({ tags: ['a'] })
  })
  it('sortForFleet: întâi cele cu ţinte, apoi alfabetic', () => {
    const s = (title: string, tags?: string[]): Snippet => ({ id: 0, title, body: '', targets: tags ? { tags } : null })
    expect(sortForFleet([s('b'), s('z', ['prod']), s('a'), s('c', ['x'])]).map((x) => x.title))
      .toEqual(['c', 'z', 'a', 'b'])
  })
  it('parametrii {{x}} funcţionează la fel ca în terminal', () => {
    expect(snippetParams('systemctl restart {{svc}} && echo {{ svc }} {{n}}')).toEqual(['svc', 'n'])
    expect(fillSnippet('restart {{svc}}', { svc: 'nginx' })).toBe('restart nginx')
  })
})
