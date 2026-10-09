/* Screenshots for README/docs, with fictional data. Runs in the Playwright container, on
   the network of the ephemeral WebTerm started by run.sh.
     node shots.mjs           (config from env: BASE, EMAIL, PASSWORD, ONLY)
   Each desktop screen is captured in dark AND light (light = the "macos" theme); the
   phone capture too. ONLY=terminal,fleet runs a subset (the others keep their old PNGs).
   ONLY=copy (opt-in, never part of the default run): the "Copy to host" dialog with folders
   selected, the Transfers row while a folder copies and its end-of-copy summary, desktop and
   phone — a visual review of that feature, written to the given out_dir.

   Selectors: prefer aria-labels / roles from the English catalogue
   (frontend/src/lang/en.ts) — when a capture fails after a UI change, look there first. */
import { chromium } from 'playwright'

const BASE = process.env.BASE ?? 'http://wt-shots-app:8000'
const EMAIL = process.env.EMAIL ?? 'demo@example.com'
const PASSWORD = process.env.PASSWORD ?? 'parola-demo-123456'
const ONLY = (process.env.ONLY ?? '').split(',').map((s) => s.trim()).filter(Boolean)
const OUT = '/out'
// failed steps: a failure leaves the OLD capture on disk, so it has to be fatal
const FAILED = []
// OPT_IN steps run only when named in ONLY: they are visual checks of one feature, not README
// captures (their PNGs are looked at during review, not committed)
const OPT_IN = ['copy']
const want = (step) => (ONLY.length === 0 && !OPT_IN.includes(step)) || ONLY.includes(step)

const log = (m) => console.log('  ' + m)

// First-run walkthrough and coach tips off: they would sit on top of every capture.
const NO_TOURS = ['wt_walkthrough_done', 'wt_tip_addhost_agent', 'wt_tip_addhost_ssh',
  'wt_tip_terminal_paste', 'wt_tip_toolbar', 'wt_tip_future_feature']

async function newPage(browser, opts) {
  const ctx = await browser.newContext({
    // Explicit locale: the UI picks its language from the browser, so without this the
    // screenshots follow whatever the container happens to report.
    locale: 'en-US',
    timezoneId: 'Europe/Berlin',
    ...opts,
  })
  await ctx.addInitScript((keys) => {
    try { for (const k of keys) localStorage.setItem(k, '1') } catch { /* ignore */ }
    // xterm's WebGL renderer does not composite reliably in headless captures (blank canvas
    // now and then), so no WebGL context. The next fallback, the canvas addon, draws the
    // font at twice its size under deviceScaleFactor 2 — it is blocked below (route), which
    // leaves xterm's DOM renderer: captures consistently, right size, looks the same.
    const orig = HTMLCanvasElement.prototype.getContext
    HTMLCanvasElement.prototype.getContext = function (type, ...args) {
      if (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl') return null
      return orig.call(this, type, ...args)
    }
  }, NO_TOURS)
  await ctx.route(/\/addon-canvas-[^/]*\.js$/, (r) => r.abort())
  const page = await ctx.newPage()
  page.on('pageerror', (e) => console.log('  [pageerror]', String(e)))
  await page.goto(BASE, { waitUntil: 'networkidle' })
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:text-is("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"], .wt-workspace', { timeout: 15000 })
  await page.waitForTimeout(1500)
  return page
}

async function setTheme(page, theme) {
  await page.evaluate((t) => {
    localStorage.setItem('wt_theme', t)
    document.documentElement.dataset.theme = t
    window.dispatchEvent(new Event('wt-theme'))
  }, theme)
  await page.waitForTimeout(500)
}

// force a repaint of every terminal before the shot (a theme change re-paints the canvas)
async function repaintTerms(page) {
  await page.evaluate(() => {
    const t = window.__wtTerms
    if (!t) return
    for (const term of t.values()) {
      try { term.refresh(0, term.rows - 1) } catch { /* ignore */ }
    }
  }).catch(() => {})
}

// capture the current view in both themes
async function shotBoth(page, name, opts = {}) {
  for (const [theme, suffix] of [['dark', 'dark'], ['macos', 'light']]) {
    await setTheme(page, theme)
    await page.waitForTimeout(400)
    await repaintTerms(page)
    await page.waitForTimeout(300)
    await page.screenshot({ path: `${OUT}/${name}-${suffix}.png`, ...opts })
    log(`✓ ${name}-${suffix}.png`)
  }
  await setTheme(page, 'dark')
}

async function step(name, fn) {
  if (!want(name)) return
  try { await fn() } catch (e) { log(`${name} FAILED: ${e.message}`); FAILED.push(name) }
}

async function typeCommands(page, cmds, pause = 700) {
  for (const c of cmds) { await page.keyboard.type(c + '\n'); await page.waitForTimeout(pause) }
}

async function goHome(page) {
  const home = page.locator('button[aria-label="Home"]')
  if (await home.count()) { await home.first().click(); await page.waitForTimeout(600) }
  await page.waitForSelector('[data-testid="dashboard"]', { timeout: 8000 })
}

async function openSession(page, host) {
  await page.locator(`button[aria-label="New session on ${host}"]`).first().click()
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(2500)               // first prompt (the terminal takes focus itself)
}

// move the pointer off any button, or its tooltip / hover state ends up in the capture
const park = (page) => page.mouse.move(700, 820)

const toolbar = (page, label) => page.locator(`button[aria-label^="${label}"]:visible`).first()

const browser = await chromium.launch()
const page = await newPage(browser, { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 })
log('login OK')

// -- 1. terminal: real output + the Commands panel (shell integration) -------------------
// Runs first: its sessions then show up under "Resume a session" on the dashboard.
let inSession = false
await step('terminal', async () => {
  await goHome(page)
  await openSession(page, 'web-01')
  inSession = true
  await typeCommands(page, [
    'cd project',
    'cat config.yaml',
    './deploy.sh --dry-run',
    'grep -c " 200 " logs/*.log',
    'cat .env',                                 // fails on purpose: a red row in the panel
    'df -h / | tail -1',
  ])
  await page.waitForTimeout(800)
  await toolbar(page, 'Commands').click()
  await page.waitForTimeout(1200)
  await park(page)
  await shotBoth(page, '02-terminal')
  await toolbar(page, 'Commands').click()       // close it again
  await page.waitForTimeout(400)
})

// -- 2. files: the session's Files panel, multi-select, then the editor --------------------
await step('files', async () => {
  if (!inSession) { await goHome(page); await openSession(page, 'web-01'); inSession = true }
  await toolbar(page, 'Files').click()
  await page.waitForTimeout(1200)
  const dir = page.locator('button:text-is("project/")')
  if (await dir.count()) { await dir.first().click(); await page.waitForTimeout(1000) }
  for (const f of ['app.py', 'config.yaml', 'deploy.sh']) {
    await page.locator(`input[type=checkbox][aria-label="Select ${f}"]`).check()
  }
  await page.waitForTimeout(600)
  await park(page)
  await shotBoth(page, '03-files')
  for (const f of ['app.py', 'config.yaml', 'deploy.sh']) {
    await page.locator(`input[type=checkbox][aria-label="Select ${f}"]`).uncheck()
  }
  // the editor (Monaco) on deploy.sh
  const row = page.locator('[data-idx]', { hasText: 'deploy.sh' }).first()
  await row.hover()
  await page.locator('button[aria-label="Edit deploy.sh"]').click()
  await page.waitForSelector('.monaco-editor', { timeout: 10000 })
  await page.waitForTimeout(1500)
  await shotBoth(page, '04-editor')
  await page.keyboard.press('Escape').catch(() => {})
  await page.waitForTimeout(500)
  await toolbar(page, 'Close file panel').click().catch(() => {})
  await page.waitForTimeout(400)
})

// -- 3. dashboard: fleet + Security card + sessions to resume ------------------------------
await step('dashboard', async () => {
  await goHome(page)
  await page.waitForTimeout(1500)               // sparklines/metrics settle
  await shotBoth(page, '01-dashboard')
})

// -- 4. host page --------------------------------------------------------------------------
await step('host', async () => {
  await goHome(page)
  await page.locator('button[aria-label="Open host web-01"]').first().click()
  await page.waitForTimeout(2500)
  await shotBoth(page, '05-host')
})

// -- 5. Settings → Sign-in & 2FA ---------------------------------------------------------
await step('security', async () => {
  await page.locator('button[aria-label="Settings"]').first().click()
  await page.waitForTimeout(1000)
  // fostul tab „Security" e spart (3.5.9); poza 06-security arată acum „Sign-in & 2FA"
  await page.getByRole('button', { name: 'Sign-in & 2FA', exact: true }).first().click()
  await page.waitForTimeout(1500)
  await shotBoth(page, '06-security')
  await page.keyboard.press('Escape')
  await page.waitForTimeout(500)
})

// -- 6. Run on hosts: a saved command on four hosts, results grid --------------------------
await step('fleet', async () => {
  await goHome(page)
  await page.locator('button[aria-label="Run on hosts"]').first().click()
  await page.waitForTimeout(1200)
  const dlg = page.getByRole('dialog')
  await dlg.locator('button[aria-label="Use saved command: Deployed release"]').click()
  for (const h of ['web-01', 'web-02', 'cache-01', 'db-01']) {
    await dlg.getByRole('button', { name: h, exact: true }).click()
  }
  await dlg.getByRole('button', { name: 'Continue →' }).click()
  await page.waitForTimeout(800)
  await dlg.getByRole('button', { name: /^Run on/ }).first().click()
  await page.waitForTimeout(1000)
  // db-01 requires 2FA on connect → step-up (no passkey/TOTP on the demo account → password)
  const pw = page.locator('input[type=password]:visible')
  if (await pw.count()) {
    await pw.fill(PASSWORD)
    await page.getByRole('button', { name: 'Confirm', exact: true }).click()
  }
  await page.waitForTimeout(4000)
  await shotBoth(page, '07-run-on-hosts')
  await page.keyboard.press('Escape')
})

// -- opt-in: Copy to host (folders) — dialog, per-file progress, summary ---------------------
// The running row is a MOCKED status (a small demo folder copies in well under the 1 s poll, so
// the real one is never caught mid-flight); the summary afterwards is the server's real answer.
const COPY_RUNNING = {
  state: 'running', src_host: 0, src_host_name: 'web-01', dst_host: 0, dst_host_name: 'web-02',
  dst_dir: '/root', on_conflict: 'skip', total_bytes: 512 * 1024 * 1024, done_bytes: 203 * 1024 * 1024,
  files_total: 14, files_done: 6, files_skipped: 0, files_failed: 0, errors: [],
  folders_total: 3, folders_done: 2, modes: true, notes: [], current: ['logs/access-2026-10-05.log'],
  noted: [], noted_total: 0,
}
async function copyFlow(pg, prefix, { phone = false } = {}) {
  // the Files tab of the host page (works the same on a phone, where the session toolbar folds)
  await pg.locator('button[aria-label="Open host web-01"]').first().click()
  await pg.waitForTimeout(1500)
  await pg.getByRole('button', { name: 'Files', exact: true }).first().click()
  await pg.waitForTimeout(1500)
  const dir = pg.locator('button:text-is("project/")')
  if (await dir.count()) { await dir.first().click(); await pg.waitForTimeout(1000) }
  for (const f of ['logs', 'static', 'app.py']) {
    await pg.locator(`input[type=checkbox][aria-label="Select ${f}"]`).check()
  }
  await pg.getByRole('button', { name: 'Copy to host…' }).first().click()
  const dlg = pg.locator('[data-testid="wt-copy-dialog"]')
  await dlg.waitFor({ timeout: 8000 })
  await dlg.locator('#wt-copy-host').selectOption({ label: 'web-02' })
  await pg.waitForTimeout(1200)                 // folder listing of the destination
  await park(pg)
  await shotBoth(pg, `${prefix}-copy-dialog`)
  const startBtn = dlg.locator('button', { hasText: /^Copy \d+ item/ })
  if (phone) {
    // the bottom of the dialog (conflict rules, folder note, limits, buttons) — scrolled into view
    await startBtn.scrollIntoViewIfNeeded()
    await pg.waitForTimeout(300)
    await shotBoth(pg, `${prefix}-copy-dialog-bottom`)
  }
  await pg.evaluate(() => localStorage.setItem('wt_transfers_min', '0'))
  await pg.route((u) => /^\/api\/fs\/copy\/[0-9a-f]{32}$/.test(u.pathname), (route) => {
    if (route.request().method() !== 'GET') return route.fallback()
    const jobId = route.request().url().split('/').pop()
    return route.fulfill({ json: { ...COPY_RUNNING, job_id: jobId } })
  })
  await startBtn.click()
  await pg.waitForTimeout(2500)
  const pill = pg.locator('[data-testid="wt-transfers-pill"]')
  if (await pill.count()) { await pill.click(); await pg.waitForTimeout(400) }
  await park(pg)
  await shotBoth(pg, `${prefix}-copy-running`)
  await pg.unrouteAll({ behavior: 'ignoreErrors' })
  await pg.waitForTimeout(2500)                 // next poll → the real, finished job
  await park(pg)
  await shotBoth(pg, `${prefix}-copy-summary`)
}

await step('copy', async () => {
  await goHome(page)
  await copyFlow(page, '09')
  const phone = await newPage(browser, {
    viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true,
  })
  await copyFlow(phone, '10-phone', { phone: true })
  await phone.context().close()
})

// -- 7. phone: a session with the two-row keybar -------------------------------------------
await step('phone', async () => {
  const phone = await newPage(browser, {
    viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true,
  })
  await phone.locator('button[aria-label="New session on web-01"]').first().click()
  await phone.waitForSelector('.xterm-screen', { timeout: 15000 })
  await phone.waitForTimeout(2500)
  await phone.locator('.xterm-screen').first().tap().catch(() => {})
  await typeCommands(phone, ['cd project', 'ls', 'tail -n 4 logs/access-2026-10-06.log', 'cat ~/RELEASE'])
  await phone.waitForTimeout(1000)
  await shotBoth(phone, '08-phone')
  await phone.context().close()
})

await browser.close()
if (FAILED.length) {
  log('FAILED: ' + FAILED.join(', ') + ' — the previous screenshots are still on disk, out of sync')
  process.exit(1)
}
log('done')
