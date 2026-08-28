// Verificare focalizată: un URL lung care se RUPE pe rânduri apare întreg în meniul „Linkuri".
// Reutilizează bootstrap-ul din e2e-session.mjs (agent real în containerul smoke).
import { chromium } from 'playwright'
import { execFileSync } from 'node:child_process'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const CONTAINER = process.argv[3] ?? 'smoke'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'ci-e2e-token'
const EMAIL = 'u@e.co', PASSWORD = 'parola-de-test-1234'
const URL =
  'https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e' +
  '&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback' +
  '&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference&state=Up6x18rbBRl2-j0vQKuTrxXUnWvF1yik0_spSEfr96s'
let fails = 0
const check = (n, c) => { console.log(`  ${c ? 'PASS' : 'FAIL'} ${n}`); if (!c) fails++ }

const setupRes = await fetch(`${BASE}/api/setup`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN }),
})
const cookie = (setupRes.headers.get('set-cookie') ?? '').split(';')[0]
const hostRes = await fetch(`${BASE}/api/hosts`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
  body: JSON.stringify({ name: 'ci-local', note: '', connection_type: 'agent', require_2fa: false }),
})
const host = await hostRes.json()
const enroll = host.install_command.match(/install\/([A-Za-z0-9_-]+)\.sh/)[1]
const installSh = await (await fetch(`${BASE}/install/${enroll}.sh`)).text()
const agentToken = installSh.match(/^TOKEN="([^"]+)"/m)[1]
const cfg = JSON.stringify({ url: 'ws://127.0.0.1:8000/agent/ws', token: agentToken, insecure: true })
execFileSync('docker', ['exec', CONTAINER, 'sh', '-c',
  `mkdir -p /root/.webterm && printf '%s' '${cfg}' > /root/.webterm/agent.json`])
execFileSync('docker', ['exec', '-d', CONTAINER, 'python3', '/srv/webterm/agent/ptyd.py', 'run'])

const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 860 }, locale: 'en-US' })
  const screenText = () => page.evaluate(() => {
    const term = window.__wtTerms?.get(location.hash.replace('#/s/', ''))
    if (!term) return ''
    const b = term.buffer.active
    let out = ''
    for (let i = 0; i < b.length; i++) out += (b.getLine(i)?.translateToString(true) ?? '') + '\n'
    return out
  })
  const waitScreen = async (needle, ms = 12000) => {
    const t0 = Date.now()
    while (Date.now() - t0 < ms) { if ((await screenText()).includes(needle)) return true; await page.waitForTimeout(300) }
    return false
  }
  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"]', { timeout: 10000 })
  await page.waitForSelector('.dot-live', { timeout: 30000 })
  await page.click('button[title="Host actions"]')
  await page.click('button[title="New session"]')
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1500)

  // afişează URL-ul lung; la 1440px terminalul are ~200 coloane, deci URL-ul de ~360 se RUPE
  await page.keyboard.type(`printf '%s\\n' '${URL}'\n`)
  check('URL-ul lung a fost afişat (se rupe pe rânduri)', await waitScreen(URL.slice(0, 40)))

  // confirmăm că E rupt: nicio linie FIZICĂ nu conţine URL-ul întreg
  const physicalHasWhole = await page.evaluate((u) => {
    const term = window.__wtTerms?.get(location.hash.replace('#/s/', ''))
    const b = term.buffer.active
    for (let i = 0; i < b.length; i++) if ((b.getLine(i)?.translateToString(true) ?? '').includes(u)) return true
    return false
  }, URL)
  check('URL-ul chiar e RUPT (niciun rând fizic nu-l conţine întreg)', physicalHasWhole === false)

  // More → Links
  // desktop (1440px): butonul „Links" e în bara vizibilă (More e lg:hidden)
  await page.locator('button[title="Links on screen — open or copy, even wrapped ones"]').click()
  await page.waitForSelector('[role=dialog]', { timeout: 5000 })
  const hrefs = await page.locator('[role=dialog] a').evaluateAll((els) => els.map((e) => e.getAttribute('href')))
  check('meniul Linkuri conţine URL-ul ÎNTREG, reunit din rândurile rupte', hrefs.includes(URL))
  check('exact un link (fără fragmente duplicate)', hrefs.filter((h) => h === URL).length === 1)

  console.log(`\n${fails === 0 ? 'ALL PASS' : fails + ' FAILED'}`)
} finally {
  await browser.close()
}
process.exit(fails === 0 ? 0 : 1)
