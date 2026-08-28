// Repro FIDEL al scenariului utilizatorului: host agent (tmux), redenumit din UI →
// sesiunile se închid? host offline? după, mai poţi scrie în terminal?
import { chromium } from 'playwright'
import { execFileSync } from 'node:child_process'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const CONTAINER = process.argv[3] ?? 'smoke'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'ci-e2e-token'
const EMAIL = 'u@e.co', PASSWORD = 'parola-de-test-1234'
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
  const page = await browser.newPage({ viewport: { width: 1440, height: 860 }, locale: 'en-US' })
  const screen = () => page.evaluate(() => {
    const term = window.__wtTerms?.get(location.hash.replace('#/s/', ''))
    if (!term) return ''
    const b = term.buffer.active; let o = ''
    for (let i = 0; i < b.length; i++) o += (b.getLine(i)?.translateToString(true) ?? '') + '\n'
    return o
  })
  const waitScreen = async (needle, ms = 15000) => {
    const t0 = Date.now()
    while (Date.now() - t0 < ms) { if ((await screen()).includes(needle)) return true; await page.waitForTimeout(300) }
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
  const theSid = await page.evaluate(() => location.hash.replace('#/s/', ''))
  await page.keyboard.type('echo HELLO1\n')
  check('înainte de redenumire: tastarea ajunge la shell', await waitScreen('HELLO1'))

  // REDENUMIRE via API (exact ce trimite UI-ul pentru un host agent: doar name/note/folder)
  console.log('  … redenumesc hostul (PATCH name)')
  const pr = await fetch(`${BASE}/api/hosts/${host.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
    body: JSON.stringify({ name: 'ci-REDENUMIT', note: '', folder: '' }),
  })
  console.log('    PATCH →', pr.status, JSON.stringify(await pr.json()))
  await page.waitForTimeout(3000)

  // host online încă?
  const hs = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
  check('hostul rămâne ONLINE după redenumire (nu pică agentul)', hs.some((h) => h.online))
  const sess = await (await fetch(`${BASE}/api/sessions`, { headers: { Cookie: cookie } })).json().catch(() => [])
  console.log('    sesiuni:', JSON.stringify((Array.isArray(sess) ? sess : []).map((s) => ({ id: (s.id||'').slice(0,8), state: s.state }))))

  // navigăm Home şi înapoi (SPA), fix ca utilizatorul: „ne ducem pe el, open terminal"
  await page.locator('button[aria-label="Home"]').evaluate((el) => el.click()).catch(() => {})
  await page.waitForTimeout(1000)
  await page.evaluate((s) => { location.hash = '#/s/' + s }, theSid)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(2000)

  await page.keyboard.type('echo HELLO2\n')
  const typed = await waitScreen('HELLO2', 10000)
  check('DUPĂ redenumire: tastarea ajunge la shell', typed)
  if (!typed) console.log('  ecran final:\n' + (await screen()).split('\n').filter((l) => l.trim()).slice(-6).join('\n'))

  console.log(`\n${fails === 0 ? 'ALL PASS' : fails + ' FAILED'}`)
} finally {
  await browser.close()
}
process.exit(fails === 0 ? 0 : 1)
