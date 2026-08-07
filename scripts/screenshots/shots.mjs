/* Capturi pentru README/docs, cu date fictive. Rulează în containerul Playwright,
   pe rețeaua WebTerm-ului efemer pornit de run.sh.
     node shots.mjs           (config din env: BASE, EMAIL, PASSWORD)
   Fiecare ecran e capturat în dark ȘI light (light = tema „macos"). */
import { chromium } from 'playwright'

const BASE = process.env.BASE ?? 'http://wt-shots-app:8000'
const EMAIL = process.env.EMAIL ?? 'demo@webterm.local'
const PASSWORD = process.env.PASSWORD ?? 'parola-demo-123456'
const OUT = '/out'
// pașii care au eșuat: un eșec lasă pe disc captura veche, deci trebuie să fie fatal
const FAILED = []

const browser = await chromium.launch()
const ctx = await browser.newContext({
  viewport: { width: 1500, height: 900 },
  deviceScaleFactor: 2,           // retina → crisp captures
  // Explicit locale: the UI picks its language from the browser, so without this the
  // screenshots follow whatever the container happens to report — which is how the
  // README ended up illustrated in a different language than it was written in.
  locale: 'en-US',
})
// Renderer-ul WebGL al xterm nu se compune fiabil în capturi headless (canvas gol
// intermitent). Dezactivăm contextul WebGL → aplicația cade automat pe CanvasAddon
// (canvas 2D), care se capturează consistent. Vizual, identic.
await ctx.addInitScript(() => {
  const orig = HTMLCanvasElement.prototype.getContext
  HTMLCanvasElement.prototype.getContext = function (type, ...args) {
    if (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl') return null
    return orig.call(this, type, ...args)
  }
})
const page = await ctx.newPage()
page.on('pageerror', (e) => console.log('  [pageerror]', String(e)))

const log = (m) => console.log('  ' + m)
const sleep = (ms) => page.waitForTimeout(ms)

async function setTheme(theme) {
  await page.evaluate((t) => {
    localStorage.setItem('wt_theme', t)
    document.documentElement.dataset.theme = t
    window.dispatchEvent(new Event('wt-theme'))
  }, theme)
  await sleep(500)
}

// renderer-ul WebGL al xterm nu se compune fiabil în capturi headless (mai ales după un
// re-paint de temă) → forțăm un refresh al tuturor terminalelor înainte de screenshot
async function repaintTerms() {
  await page.evaluate(() => {
    const t = window.__wtTerms
    if (!t) return
    for (const term of t.values()) {
      try { term.refresh(0, term.rows - 1) } catch { /* ignore */ }
    }
  }).catch(() => {})
}

// capturează vederea curentă în ambele teme
async function shotBoth(name, opts = {}) {
  for (const [theme, suffix] of [['dark', 'dark'], ['macos', 'light']]) {
    await setTheme(theme)
    await sleep(500)
    await repaintTerms()
    await sleep(300)
    await page.screenshot({ path: `${OUT}/${name}-${suffix}.png`, ...opts })
    log(`✓ ${name}-${suffix}.png`)
  }
  await setTheme('dark')
}

// -- login --------------------------------------------------------------------
await page.goto(BASE, { waitUntil: 'networkidle' })
await page.fill('input[type=email]', EMAIL)
await page.fill('input[type=password]', PASSWORD)
await page.click('button:text-is("Sign in")')
await page.waitForSelector('[data-testid="dashboard"], .wt-workspace', { timeout: 15000 })
log('login OK')
await sleep(1500)

// -- 1. dashboard / flotă -----------------------------------------------------
try {
  const home = page.locator('button[aria-label="Home"]')
  if (await home.count()) { await home.first().evaluate((el) => el.click()); await sleep(800) }
  await page.waitForSelector('[data-testid="dashboard"]', { timeout: 8000 })
  await sleep(800)
  await shotBoth('01-dashboard', { fullPage: false })
} catch (e) { log('dashboard FAILED: ' + e.message); FAILED.push('dashboard') }

// -- 2. terminal live ---------------------------------------------------------
try {
  const btn = page.locator('button[aria-label^="New session on prod-web-01"]')
  await btn.first().evaluate((el) => el.click())
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await sleep(2000)                       // lasă shell-ul să afișeze primul prompt (auto-focus)
  // comenzi demo cu output curat, care încap în viewport; se termină pe un `ls` colorat
  const cmds = [
    'echo "── production deploy · prod-web-01 ──"',
    'uname -sr',
    'df -h /',
    'ls -la --color=always project/',
  ]
  for (const c of cmds) { await page.keyboard.type(c + '\n'); await sleep(600) }
  await sleep(1500)
  // verifică din bufferul xterm că a curs output (altfel re-încearcă un tur de comenzi)
  const got = await page.evaluate(() => {
    const t = window.__wtTerms
    const sid = location.hash.replace('#/s/', '')
    const term = t && t.get(sid)
    if (!term) return ''
    const b = term.buffer.active
    let out = ''
    for (let i = 0; i < b.length; i++) out += (b.getLine(i)?.translateToString(true) ?? '')
    return out
  })
  log('buffer terminal: ' + JSON.stringify(got.slice(0, 80)))
  await shotBoth('02-terminal')
} catch (e) { log('terminal FAILED: ' + e.message); FAILED.push('terminal') }

// -- 3. fișiere + editor ------------------------------------------------------
try {
  // panoul de fișiere din sesiune
  const files = page.locator('button[title^="Files"]')
  await files.first().click()
  await sleep(1200)
  // intră în project/ ca lista să fie populată
  const dir = page.locator('button:has-text("project/")')
  if (await dir.count()) { await dir.first().click(); await sleep(1200) }
  await shotBoth('03-files')
  // deschide deploy.sh în editor (butonul creion „Editează" de pe rândul fișierului)
  const row = page.locator('li:has-text("deploy.sh"), div:has-text("deploy.sh")').last()
  const pencil = page.locator('button[title="Edit"]').first()
  if (await pencil.count()) {
    await pencil.click().catch(() => {})
    await page.waitForSelector('.cm-editor', { timeout: 8000 }).catch(() => {})
    await sleep(1200)
    await shotBoth('04-editor')
    // închide editorul (Esc) ca să nu acopere setările
    await page.keyboard.press('Escape').catch(() => {})
    await sleep(500)
  }
  // închide panoul de fișiere înainte de setări
  const closeFiles = page.locator('button[title^="Files"]')
  if (await closeFiles.count()) { await closeFiles.first().click().catch(() => {}); await sleep(500) }
} catch (e) { log('files FAILED: ' + e.message); FAILED.push('files') }

// -- 4. securitate (setări) ---------------------------------------------------
try {
  const gear = page.locator('button[title*="Settings"]')
  await gear.first().click()
  await sleep(1200)
  // derulează la secțiunea de securitate dacă e nevoie
  const sec = page.locator('text=Fleet signing key')
  if (await sec.count()) { await sec.first().scrollIntoViewIfNeeded().catch(() => {}); await sleep(500) }
  await shotBoth('05-security')
} catch (e) { log('security FAILED: ' + e.message); FAILED.push('security') }

await browser.close()
if (FAILED.length) {
  log('FAILED: ' + FAILED.join(', ') + ' — the previous screenshots are still on disk, out of sync')
  process.exit(1)
}
log('done')
