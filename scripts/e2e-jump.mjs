/* E2E dedicat pentru ţintele „jump" (SSH-jump / Telnet-jump) + alinierea în sidebar.
   NU cere un agent real: creează host-uri de AGENT prin API (rândul e de ajuns — meniul ⋯
   „Add SSH / Telnet jump…" apare pe orice host de tip agent, online sau nu), apoi verifică UI-ul:
     - sidebar: cu DOAR host-uri de agent, niciunul NU e indentat (regresia „decalat");
     - meniul ⋯ al agentului are „Add SSH / Telnet jump…";
     - formularul jump: toggle SSH-jump/Telnet-jump, „via" fix pe agent, „Connect once" + „Save target";
     - la salvarea unei ţinte telnet-jump, ea apare CUIBĂRITĂ sub agent (indentată), iar agenţii
       rămân nealiniaţi la stânga (depth 0).

     node e2e-jump.mjs http://127.0.0.1:8099
*/
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8099'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'jump-e2e-token'
const EMAIL = 'jump@example.com'
const PASSWORD = 'parola-e2e-jump-123456'   // familia fixture din .gitleaks.toml (nu secret real)

let okN = 0, total = 0
const check = (name, cond) => { total++; if (cond) okN++; console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`) }
const fail = (m) => { console.error(`EROARE: ${m}`); process.exit(1) }

// -- cont + 2 host-uri de agent prin API --------------------------------------
let cookie = ''
const su = await fetch(`${BASE}/api/setup`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN }),
})
if (su.ok) cookie = (su.headers.get('set-cookie') ?? '').split(';')[0]
else {
  const lo = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }) })
  if (!lo.ok) fail(`setup ${su.status} + login ${lo.status}`)
  cookie = (lo.headers.get('set-cookie') ?? '').split(';')[0]
}
if (!cookie) fail('niciun cookie de sesiune')

for (const name of ['alpha-agent', 'beta-agent']) {
  const r = await fetch(`${BASE}/api/hosts`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
    body: JSON.stringify({ name, note: '', connection_type: 'agent', require_2fa: false }) })
  if (!r.ok) fail(`crearea hostului ${name} a eșuat: ${r.status}`)
}
check('2 host-uri de agent create prin API', true)

// -- UI --------------------------------------------------------------------
const browser = await chromium.launch()
const errs = []
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'en-US' })
  await page.addInitScript(() => { try { for (const k of ['wt_walkthrough_done','wt_tip_addhost_agent','wt_tip_addhost_ssh','wt_tip_terminal_paste','wt_tip_toolbar']) localStorage.setItem(k, '1') } catch { /**/ } })  // walkthrough de primă rulare OFF: nu bloca fluxul de test
  page.on('pageerror', (e) => errs.push(String(e)))
  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"]', { timeout: 10000 })
  await page.waitForTimeout(800)

  // left-offset-ul rândului de nume al unui host (buton cu numele) — indentarea se vede aici
  const leftOf = async (nameText) => {
    const b = await page.locator(`.wt-sidebar button:has-text("${nameText}")`).first().boundingBox()
    return b ? Math.round(b.x) : -1
  }

  // ── alinierea: cei doi agenţi au EXACT acelaşi left (niciunul indentat) ──
  const xa = await leftOf('alpha-agent')
  const xb = await leftOf('beta-agent')
  check('ambii agenţi sunt vizibili în sidebar', xa > 0 && xb > 0)
  check(`agenţii sunt aliniaţi la stânga (fără „decalat"): ${xa}=${xb}`, xa === xb)

  // ── meniul ⋯ al primului agent are „Add SSH / Telnet jump…" ──
  await page.locator('.wt-sidebar button[title="Host actions"]').first().click()
  await page.waitForTimeout(300)
  const addJump = page.locator('button[role="menuitem"]:has-text("Add SSH / Telnet jump")')
  check('⋯ → „Add SSH / Telnet jump…" prezent pe agent', (await addJump.count()) >= 1)
  await addJump.first().click()
  await page.waitForTimeout(500)

  // ── formularul jump: toggle protocol, via fix, Connect once + Save target ──
  check('formular: toggle SSH-jump prezent', (await page.locator('button:has-text("SSH-jump")').count()) >= 1)
  check('formular: toggle Telnet-jump prezent', (await page.locator('button:has-text("Telnet-jump")').count()) >= 1)
  const viaSel = page.locator('select:disabled')
  check('formular: „via" e fix (select dezactivat pe agent)', (await viaSel.count()) >= 1)
  check('formular: buton „Connect once"', (await page.locator('button:has-text("Connect once")').count()) >= 1)
  check('formular: buton „Save target"', (await page.locator('button:has-text("Save target")').count()) >= 1)

  // ── alege Telnet-jump, completează ţinta, salveaz-o ──
  await page.locator('button:has-text("Telnet-jump")').first().click()
  await page.waitForTimeout(200)
  await page.fill('input[placeholder*="e.g.: 192.168"]', '10.0.0.50')
  // numele ţintei (primul input required, autofocus)
  await page.fill('input[placeholder*="vps-hetzner"]', 'switch-core')
  await page.locator('button:has-text("Save target")').click()
  await page.waitForTimeout(1200)

  // ── ţinta apare CUIBĂRITĂ sub agent: left-offset mai mare decât al agentului ──
  const xt = await leftOf('switch-core')
  check('ţinta telnet-jump salvată apare în sidebar', xt > 0)
  check(`ţinta e INDENTATĂ sub agent (${xt} > ${xa})`, xt > xa)
  check('agenţii au rămas nealiniaţi/indentaţi corect (depth 0 neschimbat)',
    (await leftOf('alpha-agent')) === xa && (await leftOf('beta-agent')) === xb)

  // ── hub-ul paginii de host: bara de tab-uri + comutare ──
  // agentul e OFFLINE (host creat prin API, fără agent real), deci tab-urile prin-agent
  // (Files/Forwards/…) sunt ascunse; rămân Overview + Sessions. Validează că shell-ul se
  // randează şi comută fără să crape.
  await page.locator('.wt-sidebar button:has-text("alpha-agent")').first().click()
  await page.waitForTimeout(800)
  const tabBtn = (name) => page.locator(`button:has-text("${name}")`)
  check('hub: tab „Overview" prezent', (await tabBtn('Overview').count()) >= 1)
  check('hub: tab „Sessions" prezent', (await tabBtn('Sessions').count()) >= 1)
  check('hub: tab-uri prin-agent ascunse cât agentul e offline',
    (await tabBtn('Files').count()) === 0 && (await tabBtn('Docker').count()) === 0)
  await tabBtn('Sessions').first().click()
  await page.waitForTimeout(400)
  check('hub: tab Sessions arată „fără sesiuni"', (await page.locator('text=No sessions yet').count()) >= 1)
  await tabBtn('Overview').first().click()
  await page.waitForTimeout(400)
  // Overview pe un agent (offline): cardul Security apare mereu; Connection e doar pe non-agent
  check('hub: tab Overview arată cardul Security', (await page.locator('text=Security').count()) >= 1)
  // Tools în nav (Diagnostics pentru host de agent) + Edit host pe bară
  check('nav: secţiunea Tools cu Diagnostics', (await page.locator('nav button:has-text("Diagnostics")').count()) >= 1)
  check('bară: buton „Edit host"', (await page.locator('button:has-text("Edit host")').count()) >= 1)
  await page.locator('button:has-text("Edit host")').first().click()
  await page.waitForTimeout(500)
  check('Edit host deschide modalul de editare',
    (await page.locator('text=/Edit host alpha-agent/i').count()) >= 1)
  await page.keyboard.press('Escape')
  await page.waitForTimeout(300)
  // captură pentru verificare vizuală a layout-ului (nav stânga + carduri)
  try { await page.screenshot({ path: '/out/host-overview.png', fullPage: false }) } catch { /* best-effort */ }

  // ── toast de EROARE la conectare eşuată ──
  // ţinta telnet-jump „switch-core" merge prin alpha-agent, care e OFFLINE (fără agent real),
  // deci „New session" eşuează → trebuie să apară un toast de eroare ÎN PAGINĂ cu motivul
  // (nu o notificare de OS tăcută). Validează fix-ul cerut: „să ştim că sunt probleme şi ce anume".
  await page.locator('.wt-sidebar button:has-text("switch-core")').first().click()
  await page.waitForTimeout(600)
  // editarea unui host JUMP arată comutatorul de protocol [SSH-jump][Telnet-jump] (nu selectorul
  // generic Agent/SSH), cu Telnet-jump activ — şi câmpul „via". Fără selectorul generic.
  await page.locator('button:has-text("Edit host")').first().click()
  await page.waitForTimeout(500)
  check('edit jump: toggle SSH-jump prezent', (await page.locator('button:has-text("SSH-jump")').count()) >= 1)
  check('edit jump: toggle Telnet-jump prezent', (await page.locator('button:has-text("Telnet-jump")').count()) >= 1)
  check('edit jump: fără tab-ul generic „Agent"',
    (await page.locator('.glass button:has-text("Agent")').count()) === 0)
  check('edit jump: câmpul „Reach via" prezent', (await page.locator('text=/Reach via/i').count()) >= 1)
  await page.keyboard.press('Escape')
  await page.waitForTimeout(300)
  await page.locator('button:has-text("New session")').first().click()
  await page.waitForTimeout(1500)
  const toast = page.locator('[role="alert"]')
  check('conectare eşuată → toast de eroare în pagină', (await toast.count()) >= 1)
  check('toast-ul spune CE anume (host offline / unreachable)',
    /offline|unreachable|reach|connect/i.test((await toast.first().innerText().catch(() => '')) || ''))

  check('fără erori JS în pagină', errs.length === 0)
} finally {
  await browser.close()
}

console.log(`\n${okN}/${total} checks passed`)
if (okN !== total || errs.length) { if (errs.length) console.error('pageerrors:', errs); process.exit(1) }
