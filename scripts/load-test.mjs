/* Load test: găsește plafoanele REALE ale gateway-ului sub sarcină concurentă.
   Nu presupune — măsoară: latența API sub sarcină (conexiunea SQLite unică e
   suspectul principal), stabilitatea sub output masiv pe multe sesiuni, și dacă
   sesiunile rămân utilizabile după furtună.

     node load-test.mjs http://127.0.0.1:8000 <container>

   Prereq: gateway pornit cu agent conectat (ca la e2e-session.mjs). */
import { execSync } from 'node:child_process'
import { WebSocket } from 'ws'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const CONTAINER = process.argv[3] ?? 'wt-load'
const WS = BASE.replace('http', 'ws')
const EMAIL = 'e2e@example.com'
const PASSWORD = 'parola-e2e-123456'
const N_SESSIONS = Number(process.env.N ?? 30)      // MAX_SESSIONS = 32/host
const STORM_FRAC = 0.5                                // fracțiunea care produce output

let cookie = ''
const results = []
const ok = (name, cond, detail = '') => {
  results.push([name, !!cond])
  console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}${cond ? '' : '  ← ' + detail}`)
}

async function api(path, opts = {}) {
  const res = await fetch(BASE + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE, ...(opts.headers || {}) },
  })
  return res
}

/** p50/p95/max al unui set de durate (ms). */
const pct = (arr, p) => {
  if (!arr.length) return 0
  const s = [...arr].sort((a, b) => a - b)
  return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))])
}

/** latența /api/sessions măsurată de `count` ori, secvențial. */
async function measureApi(count) {
  const lat = []
  for (let i = 0; i < count; i++) {
    const t0 = performance.now()
    const r = await api('/api/sessions')
    await r.text()
    lat.push(performance.now() - t0)
  }
  return lat
}

const memMB = () => {
  try {
    const out = execSync(`docker stats --no-stream --format '{{.MemUsage}}' ${CONTAINER}`).toString()
    const m = out.match(/([\d.]+)([KMG]i?B)/)
    if (!m) return null
    const v = parseFloat(m[1])
    return m[2].startsWith('G') ? v * 1024 : m[2].startsWith('K') ? v / 1024 : v
  } catch { return null }
}

async function main() {
  // login
  const login = await fetch(BASE + '/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  })
  cookie = (login.headers.get('set-cookie') || '').split(';')[0]
  ok('login', !!cookie)

  const memBase = memMB()
  console.log(`\n▸ memorie gateway la start: ${memBase?.toFixed(0)} MiB`)

  // baseline latență API (fără sarcină)
  const latBase = await measureApi(20)
  console.log(`▸ latență /api/sessions baseline: p50=${pct(latBase, 50)}ms p95=${pct(latBase, 95)}ms`)

  // creează N sesiuni
  console.log(`\n▸ creez ${N_SESSIONS} sesiuni…`)
  const sids = []
  for (let i = 0; i < N_SESSIONS; i++) {
    const r = await api('/api/hosts/1/sessions', { method: 'POST', body: JSON.stringify({ title: `load-${i}` }) })
    if (r.ok) sids.push((await r.json()).id)
    else { console.log(`  creare sesiune ${i} eșuată: ${r.status}`); break }
  }
  ok(`${N_SESSIONS} sesiuni create`, sids.length === N_SESSIONS, `doar ${sids.length}`)
  await new Promise((r) => setTimeout(r, 2000))

  // conectează câte un browser-ws la fiecare
  console.log(`▸ deschid ${sids.length} conexiuni browser…`)
  const sockets = []
  let totalBytes = 0
  let resyncs = 0
  for (const sid of sids) {
    const ws = new WebSocket(`${WS}/ws/sessions/${sid}`, { headers: { Cookie: cookie, Origin: BASE } })
    ws.binaryType = 'arraybuffer'
    ws.on('message', (data, isBinary) => {
      if (isBinary) totalBytes += (data.byteLength ?? data.length ?? 0)
      else {
        try { const m = JSON.parse(data.toString()); if (m.type === 'resync') resyncs++; if (m.type === 'ping') ws.send(JSON.stringify({ type: 'pong', n: m.n })) } catch { /* */ }
      }
    })
    sockets.push(ws)
  }
  await new Promise((r) => setTimeout(r, 3000))
  const connected = sockets.filter((s) => s.readyState === WebSocket.OPEN).length
  ok(`${connected}/${sids.length} conexiuni deschise`, connected === sids.length, `doar ${connected}`)

  // FURTUNĂ: output masiv pe jumătate din sesiuni, simultan
  const stormN = Math.floor(sids.length * STORM_FRAC)
  console.log(`\n▸ furtună: output masiv pe ${stormN} sesiuni simultan…`)
  const memBeforeStorm = memMB()
  for (let i = 0; i < stormN; i++) {
    sockets[i].send(new TextEncoder().encode("for i in $(seq 1 2000); do echo \"linia-$i-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"; done\n"))
  }

  // în timpul furtunii: măsoară latența API (SQLite serializează?)
  const latStorm = await measureApi(30)
  const p50s = pct(latStorm, 50), p95s = pct(latStorm, 95), maxs = pct(latStorm, 100)
  console.log(`▸ latență /api/sessions ÎN furtună: p50=${p50s}ms p95=${p95s}ms max=${maxs}ms`)
  ok('API rămâne responsiv sub furtună (p95 < 2s)', p95s < 2000, `p95=${p95s}ms`)
  ok('API fără stall total sub furtună (max < 5s)', maxs < 5000, `max=${maxs}ms`)

  await new Promise((r) => setTimeout(r, 5000))
  const memPeak = memMB()
  console.log(`▸ memorie: start ${memBase?.toFixed(0)} → înainte furtună ${memBeforeStorm?.toFixed(0)} → vârf ${memPeak?.toFixed(0)} MiB`)
  console.log(`▸ total octeți primiți de clienți: ${(totalBytes / 1024 / 1024).toFixed(1)} MiB · resync-uri: ${resyncs}`)

  // după furtună: gateway-ul încă răspunde? o sesiune nouă merge?
  await new Promise((r) => setTimeout(r, 2000))
  const latAfter = await measureApi(20)
  ok('API revine la normal după furtună (p95 < 500ms)', pct(latAfter, 95) < 500, `p95=${pct(latAfter, 95)}ms`)
  console.log(`▸ latență /api/sessions după furtună: p50=${pct(latAfter, 50)}ms p95=${pct(latAfter, 95)}ms`)

  // o sesiune încă e utilizabilă (tastez o comandă, verific ecoul)
  const probe = sids[sids.length - 1]
  let echoed = false
  const pws = new WebSocket(`${WS}/ws/sessions/${probe}`, { headers: { Cookie: cookie, Origin: BASE } })
  pws.binaryType = 'arraybuffer'
  pws.on('message', (d, isB) => { if (isB && new TextDecoder().decode(d).includes('ALIVE_PROBE')) echoed = true })
  await new Promise((r) => { pws.on('open', r); setTimeout(r, 3000) })
  pws.send(new TextEncoder().encode('echo ALIVE_PROBE\n'))
  await new Promise((r) => setTimeout(r, 3000))
  ok('sesiune încă utilizabilă după furtună (ecou comandă)', echoed)

  for (const s of sockets) s.close()
  pws.close()

  const failed = results.filter(([, c]) => !c)
  console.log(`\n${results.length - failed.length}/${results.length} verificări trecute`)
  console.log(`REZUMAT: ${sids.length} sesiuni · vârf memorie ${memPeak?.toFixed(0)}MiB (Δ${(memPeak - memBase).toFixed(0)}) · API p95 sub sarcină ${p95s}ms`)
  process.exit(failed.length ? 1 : 0)
}

main().catch((e) => { console.error('EROARE:', e); process.exit(2) })
