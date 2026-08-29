// Reproduce stilul de wrap al Claude Code (Ink): aplicaţia îşi face SINGURĂ wrap-ul şi emite
// rânduri separate, INDENTATE, pline pe lăţime — nu soft-wrap-ul terminalului (isWrapped).
// Verifică că meniul „Linkuri" reuneşte totuşi URL-ul întreg.
import { chromium } from 'playwright'
import { execFileSync } from 'node:child_process'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const CONTAINER = process.argv[3] ?? 'smoke'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'ci-e2e-token'
const EMAIL = 'u@e.co', PASSWORD = 'parola-de-test-1234'
const URL =
  'https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e' +
  '&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback' +
  '&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code' +
  '+user%3Amcp_servers+user%3Afile_upload&code_challenge=UpZ7Mmgi1FbffhEZ12wMHMyyitbxjZLrQOMXv0iijhM' +
  '&code_challenge_method=S256&state=tKJXV4XrYf-9Mu-EWhnlVjTefTVRtanguQ0kFJ2Rrb0'
let fails = 0
const check = (n, c) => { console.log(`  ${c ? 'PASS' : 'FAIL'} ${n}`); if (!c) fails++ }
const dexec = (...a) => execFileSync('docker', ['exec', ...a], { encoding: 'utf8' })

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
dexec(CONTAINER, 'sh', '-c', `mkdir -p /root/.webterm && printf '%s' '${cfg}' > /root/.webterm/agent.json`)
dexec('-d', CONTAINER, 'python3', '/srv/webterm/agent/ptyd.py', 'run')

const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 }, locale: 'en-US' })
  const sid = () => page.evaluate(() => location.hash.replace('#/s/', ''))
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
  await sid()

  // lăţimea reală a terminalului, apoi tăiem URL-ul în bucăţi INDENTATE care umplu lăţimea
  // (dar sub cols, ca terminalul să NU facă el auto-wrap) — exact ce face Ink într-o casetă.
  const cols = await page.evaluate(() => window.__wtTerms?.get(location.hash.replace('#/s/', ''))?.cols ?? 80)
  const indent = '  '
  const chunkLen = cols - 4
  const chunks = []
  for (let i = 0; i < URL.length; i += chunkLen) chunks.push(indent + URL.slice(i, i + chunkLen))
  console.log(`  cols=${cols}, ${chunks.length} rânduri indentate, pline`)
  // printf '%s\n' 'r1' 'r2' ... — formatul se reaplică fiecărui argument; ghilimele simple
  // protejează caracterele speciale din URL (& % + = etc.)
  const args = chunks.map((c) => `'${c}'`).join(' ')
  await page.keyboard.type(`printf '%s\\n' ${args}\n`)
  await page.waitForTimeout(1500)

  // confirmăm că E hard-wrap (rânduri fizice separate, niciunul nu conţine URL-ul întreg)
  const physicalHasWhole = await page.evaluate((u) => {
    const term = window.__wtTerms?.get(location.hash.replace('#/s/', ''))
    const b = term.buffer.active
    for (let i = 0; i < b.length; i++) if ((b.getLine(i)?.translateToString(true) ?? '').includes(u)) return true
    return false
  }, URL)
  check('URL-ul e rupt pe rânduri fizice (hard-wrap indentat)', physicalHasWhole === false)

  await page.locator('button[title="Links on screen — open or copy, even wrapped ones"]').click()
  await page.waitForSelector('[role=dialog]', { timeout: 5000 })
  const hrefs = await page.locator('[role=dialog] a').evaluateAll((els) => els.map((e) => e.getAttribute('href')))
  check('meniul Linkuri conţine URL-ul ÎNTREG (reunit din hard-wrap + indentare)', hrefs.includes(URL))
  if (!hrefs.includes(URL)) console.log('  ce a găsit:', JSON.stringify(hrefs))

  console.log(`\n${fails === 0 ? 'ALL PASS' : fails + ' FAILED'}`)
} finally {
  await browser.close()
}
process.exit(fails === 0 ? 0 : 1)
