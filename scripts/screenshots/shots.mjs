/* Screenshots for README/docs, with fictional data. Runs in the Playwright container, on
   the network of the ephemeral WebTerm started by run.sh.
     node shots.mjs           (config from env: BASE, EMAIL, PASSWORD, ONLY)
   Each desktop screen is captured in dark AND light (light = the "macos" theme); the
   phone capture too. ONLY=terminal,fleet runs a subset (the others keep their old PNGs).
   ONLY=copy (opt-in, never part of the default run): the "Copy to host" dialog with folders
   selected, the Transfers row while a folder copies and its end-of-copy summary, desktop and
   phone — a visual review of that feature, written to the given out_dir.

   A failed step also writes `_failed-<step>.png` (what the page showed) to the out_dir — a
   debugging aid, delete it before committing.

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
// VIDEO=1: the captioned product tour (tour.webm); then only the steps named in ONLY run
const VIDEO = process.env.VIDEO === '1'
// CLIPS=1: short muted feature loops (clip-*.webm raw → mp4 + poster in run.sh); ONLY=clip-x,clip-y
// picks some of them. Like VIDEO, the screenshot steps then run only if named in ONLY.
const CLIPS = process.env.CLIPS === '1' || ONLY.some((s) => s.startsWith('clip-'))
const want = (step) => (ONLY.length === 0 && !VIDEO && !CLIPS && !OPT_IN.includes(step)) || ONLY.includes(step)
// SHOT_THEMES=dark,light prefs for shotBoth (lib/themeModel.ts values). 3.7.1+ ships the EverShell
// theme as default, so the website captures use `evershell:dark,evershell:light`; the default stays
// Midnight / Aurora for the README captures of older images.
const THEMES = (process.env.SHOT_THEMES || 'dark,macos').split(',').map((s) => s.trim())

const log = (m) => console.log('  ' + m)

// First-run walkthrough and coach tips off: they would sit on top of every capture.
const NO_TOURS = ['wt_walkthrough_done', 'wt_tip_addhost_agent', 'wt_tip_addhost_ssh',
  'wt_tip_terminal_paste', 'wt_tip_toolbar', 'wt_tip_future_feature']

// `opts.storageState` (the tour): an already signed-in context — no login form in the recording
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
    // …but a failed chunk import fires `vite:preloadError`, and main.tsx answers it with a full
    // reload (meant for stale chunk hashes after a deploy; throttled to one per 10 s through
    // this key). Every terminal (re)creation would reload the page mid-run (the app comes back
    // on the session route, with no dashboard) — a timestamp in the future disarms it.
    try { sessionStorage.setItem('wt_chunk_reload', String(Date.now() + 864e5)) } catch { /* ignore */ }
  }, NO_TOURS)
  await ctx.route(/\/addon-canvas-[^/]*\.js$/, (r) => r.abort())
  const page = await ctx.newPage()
  page.on('pageerror', (e) => console.log('  [pageerror]', String(e)))
  if (process.env.DBG) {
    page.on('framenavigated', (f) => { if (f === page.mainFrame()) console.log('  [nav]', f.url(), new Date().toISOString()) })
    page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') console.log('  [console]', m.type(), m.text().slice(0, 300)) })
  }
  await page.goto(BASE, { waitUntil: 'networkidle' })
  if (!opts.storageState) {
    await page.fill('input[type=email]', EMAIL)
    await page.fill('input[type=password]', PASSWORD)
    await page.click('button:text-is("Sign in")')
  }
  await page.waitForSelector('[data-testid="dashboard"], .wt-workspace', { timeout: 15000 })
  await page.waitForTimeout(1500)
  return page
}

// `pref` = the value lib/themeModel.ts stores in `wt_theme`: `dark` (Midnight), `macos` (Aurora —
// the historical id, NOT the macOS family) or `<family>:<mode>` (3.6.4+, e.g. `mac:light`)
async function setTheme(page, pref) {
  await page.evaluate((p) => {
    const m = /^([a-z]+):(light|dark)$/.exec(p)
    const family = m ? m[1] : 'webterm'
    const light = m ? m[2] === 'light' : p === 'macos'
    const variant = m ? `${family}-${m[2]}` : p
    localStorage.setItem('wt_theme', p)
    // same three attributes as lib/theme.ts paintTheme(): the light-only rules hang off data-mode
    document.documentElement.dataset.theme = variant
    document.documentElement.dataset.family = family
    document.documentElement.dataset.mode = light ? 'light' : 'dark'
    window.dispatchEvent(new Event('wt-theme'))
    window.dispatchEvent(new Event('wt-termscheme'))   // the default terminal scheme follows the family
  }, pref)
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
// The run itself raises in-app alerts ("new login", "a new device attached", backup health):
// mark them read so the bell does not carry a red count in every capture. The bell re-polls
// on visibilitychange (lib/alerts.ts).
async function clearAlerts(page) {
  await page.evaluate(async () => {
    await fetch('/api/alerts/read', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ all: true }) })
    document.dispatchEvent(new Event('visibilitychange'))
  }).catch(() => {})
  await page.waitForTimeout(400)
}

// `themes` = the [dark, light] prefs (default: WebTerm Midnight / Aurora)
async function shotBoth(page, name, opts = {}, themes = THEMES) {
  await clearAlerts(page)
  for (const [theme, suffix] of [[themes[0], 'dark'], [themes[1], 'light']]) {
    await setTheme(page, theme)
    await page.waitForTimeout(400)
    await repaintTerms(page)
    await page.waitForTimeout(300)
    await page.screenshot({ path: `${OUT}/${name}-${suffix}.png`, ...opts })
    log(`✓ ${name}-${suffix}.png`)
  }
  await setTheme(page, THEMES[0])
}

async function step(name, fn) {
  if (!want(name)) return
  try { await fn() } catch (e) {
    log(`${name} FAILED: ${e.message}`); FAILED.push(name)
    await page.screenshot({ path: `${OUT}/_failed-${name}.png` }).catch(() => {})   // what the step saw
  }
}

async function typeCommands(page, cmds, pause = 700) {
  for (const c of cmds) { await page.keyboard.type(c + '\n'); await page.waitForTimeout(pause) }
}

async function goHome(page) {
  const dash = page.locator('[data-testid="dashboard"]')
  if (!(await dash.isVisible())) {
    // the Home button lives in the tab bar, which exists only while a session tab is open
    // (ONLY=forward,updates… starts on a host page with no tabs): the empty hash is the dashboard
    const home = page.locator('button[aria-label="Home"]:visible').first()
    if (await home.count()) await home.click()
    else await page.evaluate(() => { window.location.hash = '' })
    await page.waitForTimeout(600)
  }
  await dash.waitFor({ state: 'visible', timeout: 8000 })
}

// 3.7.1+: New session on a host where you already have live sessions opens the launcher first;
// Shift+click skips it (a fresh shell, as before). `title`: rename the session right away, so the
// dashboard, the split picker and the launcher never show "Session N".
async function openSession(page, host, { title = '', shift = true, wait = 2500 } = {}) {
  const before = await page.locator('.xterm-screen').count()
  await page.locator(`button[aria-label="New session on ${host}"]`).first()
    .click(shift ? { modifiers: ['Shift'] } : {})
  // a NEW terminal (other tabs keep theirs mounted, so `.xterm-screen` alone proves nothing)
  await page.waitForFunction((n) => document.querySelectorAll('.xterm-screen').length > n, before, { timeout: 15000 })
  await page.waitForTimeout(wait)               // first prompt (the terminal takes focus itself)
  if (title) await nameSession(page, title)
}

// the session title field in the pane header (aria-label from session.sessionTitle); Enter saves
async function nameSession(page, title, delay = 0) {
  const inp = page.locator('input[aria-label="Session title"]:visible').last()
  await inp.click()
  await page.keyboard.press('Control+A')
  await page.keyboard.type(title, { delay })
  await page.keyboard.press('Enter')
  await page.waitForTimeout(300)
  await focusTerm(page)
}

// keyboard focus back into the visible terminal (after the title field, a dialog…)
async function focusTerm(page) {
  await page.evaluate(() => {
    const ta = [...document.querySelectorAll('.xterm-helper-textarea')]
      .find((el) => el.closest('.xterm')?.getClientRects().length)
    ta?.focus()
  })
}

// move the pointer off any button, or its tooltip / hover state ends up in the capture
const park = (page) => page.mouse.move(700, 820)

const toolbar = (page, label) => page.locator(`button[aria-label^="${label}"]:visible`).first()

const browser = await chromium.launch()
const page = await newPage(browser, { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 })
log('login OK')

// -- VIDEO=1: one continuous, captioned product tour (1440×900, recorded by Playwright) -----
// Runs BEFORE the screenshot steps, on a fresh fleet: the sessions it opens are then the only
// ones under "Resume a session" and the last rows of the split-view picker.
// Captions: one fixed element appended to <html>, OUTSIDE <body> — React renders into #root
// and the modals' focus traps / `inert` work on body's children, so the overlay changes no
// app state; pointer-events none, aria-hidden.
async function caption(pg, text) {
  await pg.evaluate(async (txt) => {
    let el = document.getElementById('wt-tour-caption')
    if (!el) {
      el = document.createElement('div')
      el.id = 'wt-tour-caption'
      el.setAttribute('aria-hidden', 'true')
      Object.assign(el.style, {
        position: 'fixed', left: '50%', bottom: '64px', transform: 'translateX(-50%)',
        zIndex: '2147483647', pointerEvents: 'none', padding: '16px 34px', borderRadius: '16px',
        background: 'rgba(6,8,14,0.86)', color: '#f8fafc', maxWidth: '82vw', textAlign: 'center',
        // 34 px at the tour's 1440 px; the 1280 px clips scale it down with the viewport
        font: `600 ${Math.round(34 * Math.min(1, window.innerWidth / 1440))}px/1.25 Inter, "Segoe UI", system-ui, -apple-system, sans-serif`,
        letterSpacing: '-0.01em', boxShadow: '0 12px 48px rgba(0,0,0,0.5)',
        border: '1px solid rgba(255,255,255,0.08)', transition: 'opacity 0.3s ease', opacity: '0',
      })
      document.documentElement.appendChild(el)
    }
    if (el.style.opacity !== '0') { el.style.opacity = '0'; await new Promise((r) => setTimeout(r, 320)) }
    el.textContent = txt
    if (txt) el.style.opacity = '1'
  }, text)
}

// the first frames of a recording are the page loading: everything is timed from `start` (the
// fleet on screen) and run.sh cuts the video there, so chapters and poster line up with the mp4
async function recorded(name, size) {
  const state = await page.context().storageState()
  const ctx0 = Date.now()
  const pg = await newPage(browser, {
    viewport: size, deviceScaleFactor: 1, storageState: state,
    recordVideo: { dir: `${OUT}/.${name}-raw`, size },
  })
  await setTheme(pg, 'evershell:dark')         // the 3.7.1 default, explicit (storageState may carry a pick)
  const at = () => (Date.now() - ctx0) / 1000
  return { pg, at }
}

async function saveRecording(pg, name) {
  const video = pg.video()
  await pg.context().close()
  await video.saveAs(`${OUT}/.${name}.raw.webm`)
  await video.delete()
}

// live sessions still on their default title ("Session N", given by the gateway; a Shift+click in
// a clip) are closed again, so the next clip's launcher / split picker shows only named ones
async function tidySessions(pg) {
  const list = await apiCall(pg, 'GET', '/api/sessions').catch(() => [])
  for (const s of (Array.isArray(list) ? list : (list.sessions ?? []))) {
    if (s.state !== 'closed' && /^(Session \d+)?$/.test((s.title || '').trim())) await apiCall(pg, 'POST', `/api/sessions/${s.id}/kill`).catch(() => {})
  }
}

// a split view of the sessions with these titles (pick order = pane order), host list folded
async function splitPick(pg, name, titles, pause = 0) {
  await pg.getByRole('button', { name: 'New split view', exact: true }).click()
  const dlg = pg.getByRole('dialog', { name: 'New split view' })
  await dlg.waitFor({ timeout: 8000 })
  await dlg.locator('input:not([type=checkbox])').first().fill(name)
  const rows = dlg.locator('label:has(input[type=checkbox])')
  const n = await rows.count()
  for (let i = 0; i < n; i++) {
    const cb = rows.nth(i).locator('input[type=checkbox]')
    if (await cb.isChecked()) await cb.uncheck()
  }
  for (const title of titles) {
    await rows.filter({ hasText: title }).first().locator('input[type=checkbox]').check()
    await pg.waitForTimeout(pause / titles.length)
  }
  await dlg.getByRole('button', { name: 'Show side by side', exact: true }).click()
  await pg.waitForTimeout(1500)
  await pg.getByRole('button', { name: 'Hide the host list', exact: true }).click()
  await pg.waitForTimeout(1500)
}

const LOOP = `n=0; while sleep 1; do n=$((n+137)); printf '%s  batch %3d  %6d rows imported\\n' "$(date +%T)" $((n/137)) $n; done\n`

async function tour() {
  const { pg, at } = await recorded('tour', { width: 1440, height: 900 })
  const beat = (ms) => pg.waitForTimeout(ms)
  const type = (txt, delay = 22) => pg.keyboard.type(txt, { delay })
  const chapters = []
  let start = 0
  const chapter = (label) => chapters.push({ t: +(at() - start).toFixed(1), label })
  let posterAt = 0

  await goHome(pg)
  await clearAlerts(pg)
  start = at()

  // 1. the fleet
  chapter('Your fleet')
  await caption(pg, 'Your whole fleet, in one browser tab.')
  await beat(3200)

  // 2. a named, long-running job on web-01
  chapter('Persistent sessions')
  await caption(pg, 'Open a shell on web-01.')
  await openSession(pg, 'web-01', { wait: 1600 })
  await caption(pg, 'Name your sessions.')
  await beat(500)
  await nameSession(pg, 'import-job', 70)
  await beat(900)
  await caption(pg, 'Start a long job…')
  await type(LOOP, 12)
  await beat(3200)

  // 3. close the tab (the session stays alive on the host)
  await caption(pg, '…close the tab. The shell keeps running.')
  await beat(1000)
  await pg.locator('button[aria-label="Close the tab"]:visible').first().click()
  await beat(800)
  await goHome(pg)
  await pg.locator('#dash-active-sessions').scrollIntoViewIfNeeded().catch(() => {})
  await beat(2600)

  // 4. the launcher: New session on a host where you have live sessions
  chapter('New session launcher')
  await caption(pg, 'Continue where you left off — or start fresh.')
  await pg.locator('button[aria-label="New session on web-01"]').first().click()
  await pg.locator('[data-testid="launcher"]').waitFor({ timeout: 10000 })
  await beat(2400)
  const card = pg.locator('[data-testid="launcher"] [data-card]', { hasText: 'import-job' }).first()
  await card.hover()
  await beat(700)
  await card.click()
  await pg.waitForSelector('.xterm-screen', { timeout: 15000 })
  await caption(pg, 'Same process, same scrollback.')
  await beat(4000)
  await pg.keyboard.press('Control+C')
  await beat(400)

  // 5. Files panel on the same host
  chapter('Files')
  await caption(pg, 'Browse, upload and edit files.')
  await toolbar(pg, 'Files').click()
  await beat(1000)
  const dir = pg.locator('button:text-is("project/")')
  if (await dir.count()) { await dir.first().click() }
  await beat(2800)
  await toolbar(pg, 'Close file panel').click().catch(() => {})
  await beat(300)

  // 6. Shift+click: a fresh shell without the launcher, then two more hosts → a split view
  chapter('Split view')
  await goHome(pg)
  await caption(pg, 'Shift+click New session skips the launcher.')
  await beat(1300)
  await openSession(pg, 'web-01', { wait: 1400 })
  await nameSession(pg, 'deploy', 40)
  await type('cd project && ./deploy.sh --dry-run\n')
  await beat(900)
  await caption(pg, 'Several hosts, side by side.')
  for (const [host, title, cmds] of [['web-02', 'top', ['top -d 2']], ['cache-01', 'health check', ['uptime', 'free -h']]]) {
    await goHome(pg)
    await openSession(pg, host, { wait: 1300 })
    await nameSession(pg, title, 30)
    for (const c of cmds) { await type(c + '\n'); await beat(350) }
  }
  await splitPick(pg, 'prod-tour', ['top', 'deploy', 'health check'], 600)
  await pg.evaluate(() => document.activeElement?.blur())
  posterAt = at() - start
  await beat(3800)
  await pg.locator('button[aria-label^="Open host list"]:visible').first().click()
  await beat(400)

  // 7. Run on hosts
  chapter('Run on hosts')
  await caption(pg, 'One command, many hosts.')
  await fleetRun(pg, 450)
  await beat(1800)
  await pg.keyboard.press('Escape')
  await beat(400)

  // 8. a read-only share link that expires
  chapter('Share link')
  await goHome(pg)
  await pg.locator('#dash-active-sessions button', { hasText: 'import-job' }).first().click()
  await pg.waitForSelector('.xterm-screen', { timeout: 15000 })
  await caption(pg, 'Share a read-only link that expires.')
  await beat(900)
  await toolbar(pg, 'Share link').click()
  await beat(900)
  await pg.locator('select[aria-label="Share link expiry"]').selectOption('60')
  await beat(600)
  await pg.getByRole('button', { name: 'Generate link', exact: true }).click()
  await beat(3200)
  await pg.keyboard.press('Escape')
  await beat(300)

  // 9. Settings: one search box over every section
  chapter('Settings search')
  await goHome(pg)
  await caption(pg, 'Every setting, one search away.')
  await pg.locator('button[aria-label="Settings"]').first().click()
  const search = pg.locator('input[aria-label="Search settings"]')
  await search.waitFor({ timeout: 8000 })
  await beat(700)
  await search.click()
  await type('smtp', 140)
  await beat(1500)
  await pg.locator('[data-setting-result="smtp"]').click()
  await beat(3000)
  await caption(pg, '')
  await beat(700)
  const total = at() - start

  await saveRecording(pg, 'tour')
  const { writeFileSync } = await import('node:fs')
  writeFileSync(`${OUT}/.tour-cut`, JSON.stringify({ start: +start.toFixed(2), poster: +posterAt.toFixed(2), end: +total.toFixed(2) }))
  writeFileSync(`${OUT}/tour-chapters.json`, JSON.stringify(chapters, null, 2) + '\n')
  log(`✓ tour (${total.toFixed(1)} s after the cut at ${start.toFixed(1)} s, poster at ${posterAt.toFixed(1)} s)`)
  for (const c of chapters) log(`   ${c.t.toFixed(1).padStart(5)}  ${c.label}`)
}

// -- CLIPS=1: one short muted loop per feature (1440×900), each in its own recorded context.
// `mark()` sets where the clip starts (setup before it is cut away), `poster()` the still.
// 1440×900 like the tour: at 1280 the session toolbar folds Share link into its ⋯ menu
const CLIP_SIZE = { width: 1440, height: 900 }
const CLIP_META = {}
async function clip(name, fn) {
  if (ONLY.length && !ONLY.includes(name)) return
  const { pg, at } = await recorded(name, CLIP_SIZE)
  const m = { start: 0, poster: null, end: 0 }
  try {
    await goHome(pg)
    await clearAlerts(pg)
    await fn(pg, {
      mark: () => { m.start = at() },
      poster: () => { m.poster = at() },
      beat: (ms) => pg.waitForTimeout(ms),
      type: (txt, delay = 30) => pg.keyboard.type(txt, { delay }),
    })
    await caption(pg, '')
    await pg.waitForTimeout(400)
    m.end = at()
    await tidySessions(pg)
    await saveRecording(pg, name)
    if (m.poster == null) m.poster = (m.start + m.end) / 2
    CLIP_META[name] = { start: +m.start.toFixed(2), end: +m.end.toFixed(2), poster: +m.poster.toFixed(2) }
    log(`✓ ${name} (${(m.end - m.start).toFixed(1)} s)`)
  } catch (e) {
    log(`${name} FAILED: ${e.message}`); FAILED.push(name)
    await pg.screenshot({ path: `${OUT}/_failed-${name}.png` }).catch(() => {})
    await pg.context().close().catch(() => {})
  }
}

async function clips() {
  // the named sessions every clip relies on (the tour leaves the same ones when it ran first)
  const ensure = async (pg, host, title, cmds) => {
    const list = await apiCall(pg, 'GET', '/api/sessions').catch(() => [])
    if ((Array.isArray(list) ? list : []).some((s) => s.title === title)) return
    await goHome(pg)
    await openSession(pg, host, { title })
    for (const c of cmds) { await pg.keyboard.type(c + '\n'); await pg.waitForTimeout(400) }
  }
  {
    const { pg } = await recorded('setup', CLIP_SIZE)
    await tidySessions(pg)
    await ensure(pg, 'web-01', 'import-job', [LOOP.trimEnd()])
    await ensure(pg, 'web-01', 'deploy', ['cd /root/project && ./deploy.sh --dry-run'])
    await ensure(pg, 'web-02', 'top', ['top -d 2'])
    await ensure(pg, 'cache-01', 'health check', ['uptime', 'free -h'])
    await pg.context().close()
    const { rmSync } = await import('node:fs')
    rmSync(`${OUT}/.setup-raw`, { recursive: true, force: true })
  }

  await clip('clip-rename', async (pg, c) => {
    c.mark()
    await c.beat(600)
    await openSession(pg, 'worker-03', { wait: 1300 })
    await caption(pg, 'Name your sessions.')
    await c.beat(500)
    await nameSession(pg, 'nightly-report', 90)
    c.poster()
    await c.beat(1200)
    await caption(pg, 'The name shows everywhere you pick a session.')
    await goHome(pg)
    await pg.locator('#dash-active-sessions').scrollIntoViewIfNeeded().catch(() => {})
    await c.beat(3000)
  })

  await clip('clip-launcher', async (pg, c) => {
    c.mark()
    await caption(pg, 'Continue where you left off — or start fresh.')
    await c.beat(900)
    await pg.locator('button[aria-label="New session on web-01"]').first().click()
    await pg.locator('[data-testid="launcher"]').waitFor({ timeout: 10000 })
    c.poster()
    await c.beat(2200)
    const card = pg.locator('[data-testid="launcher"] [data-card]', { hasText: 'import-job' }).first()
    await card.hover()
    await c.beat(600)
    await card.click()
    await pg.waitForSelector('.xterm-screen', { timeout: 15000 })
    await c.beat(2200)
    await goHome(pg)
    await caption(pg, 'Shift+click New session skips it.')
    await c.beat(1400)
    await openSession(pg, 'web-01', { wait: 1000, title: 'scratch' })
    await c.beat(1200)
  })

  await clip('clip-settings-search', async (pg, c) => {
    c.mark()
    await caption(pg, 'Every setting, one search away.')
    await pg.locator('button[aria-label="Settings"]').first().click()
    const search = pg.locator('input[aria-label="Search settings"]')
    await search.waitFor({ timeout: 8000 })
    await c.beat(1000)
    await search.click()
    await c.type('backup', 140)
    c.poster()
    await c.beat(1600)
    await pg.locator('[data-setting-result="backupAuto"]').click()
    await c.beat(2600)
    await search.click()
    await c.type('smtp', 140)
    await c.beat(1200)
    await pg.keyboard.press('Enter')
    await c.beat(2600)
  })

  await clip('clip-split', async (pg, c) => {
    // the "New split view" button lives in the tab bar (two tabs or more), and picks among open tabs
    for (const title of ['deploy', 'top', 'health check']) {
      await goHome(pg)
      await pg.locator('#dash-active-sessions button', { hasText: title }).first().click()
      await pg.waitForSelector('.xterm-screen', { timeout: 15000 })
    }
    await pg.waitForTimeout(1200)
    c.mark()
    await caption(pg, 'Several hosts, side by side.')
    await c.beat(600)
    await splitPick(pg, 'prod-debug', ['top', 'deploy', 'health check'], 900)
    await pg.evaluate(() => document.activeElement?.blur())
    c.poster()
    await c.beat(4500)
  })

  await clip('clip-run', async (pg, c) => {
    c.mark()
    await caption(pg, 'One command, many hosts.')
    await fleetRun(pg, 500)
    c.poster()
    await c.beat(2500)
  })

  await clip('clip-share', async (pg, c) => {
    // not import-job: the tour shared that one already (its toolbar then offers Revoke); and a
    // re-run (REUSE=1) starts from an unshared session again
    for (const s of await apiCall(pg, 'GET', '/api/sessions').catch(() => [])) {
      if (s.title === 'health check' && s.state !== 'closed') await apiCall(pg, 'DELETE', `/api/sessions/${s.id}/share`).catch(() => {})
    }
    await pg.locator('#dash-active-sessions button', { hasText: 'health check' }).first().click()
    await pg.waitForSelector('.xterm-screen', { timeout: 15000 })
    await pg.waitForTimeout(1200)
    c.mark()
    await caption(pg, 'Share a read-only link that expires.')
    await c.beat(1200)
    await toolbar(pg, 'Share link').click()
    await c.beat(1000)
    await pg.locator('select[aria-label="Share link expiry"]').selectOption('60')
    await c.beat(700)
    await pg.getByRole('button', { name: 'Generate link', exact: true }).click()
    await pg.locator('[data-testid="share-expires"]').waitFor({ timeout: 8000 })
    c.poster()
    await c.beat(3500)
  })

  await clip('clip-files', async (pg, c) => {
    await pg.locator('#dash-active-sessions button', { hasText: 'deploy' }).first().click()
    await pg.waitForSelector('.xterm-screen', { timeout: 15000 })
    await pg.waitForTimeout(1200)
    c.mark()
    await caption(pg, 'Browse, upload and edit files.')
    await toolbar(pg, 'Files').click()
    await c.beat(1200)
    const dir = pg.locator('button:text-is("project/")')
    if (await dir.count()) { await dir.first().click() }
    await c.beat(1500)
    for (const f of ['app.py', 'config.yaml']) {
      await pg.locator(`input[type=checkbox][aria-label="Select ${f}"]`).check()
      await c.beat(350)
    }
    await c.beat(900)
    for (const f of ['app.py', 'config.yaml']) await pg.locator(`input[type=checkbox][aria-label="Select ${f}"]`).uncheck()
    const row = pg.locator('[data-idx]', { hasText: 'deploy.sh' }).first()
    await row.hover()
    await pg.locator('button[aria-label="Edit deploy.sh"]').click()
    await pg.waitForSelector('.monaco-editor', { timeout: 10000 })
    c.poster()
    await c.beat(3200)
  })

  // merged with an earlier run's (ONLY=clip-x re-records one clip; run.sh encodes them all)
  const { writeFileSync, readFileSync } = await import('node:fs')
  let prev = {}
  try { prev = JSON.parse(readFileSync(`${OUT}/.clips.json`, 'utf8')) } catch { /* first run */ }
  writeFileSync(`${OUT}/.clips.json`, JSON.stringify({ ...prev, ...CLIP_META }))
}

if (VIDEO) {
  try { await tour() } catch (e) {
    log(`tour FAILED: ${e.message}`); FAILED.push('tour')
  }
}
if (CLIPS) await clips()

// -- 1. terminal: real output + the Commands panel (shell integration) -------------------
// Runs first: its sessions then show up under "Resume a session" on the dashboard.
let inSession = false
await step('terminal', async () => {
  await goHome(page)
  await openSession(page, 'web-01', { title: 'release check' })
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
  if (!inSession) { await goHome(page); await openSession(page, 'web-01', { title: 'release check' }); inSession = true }
  await toolbar(page, 'Files').click()
  await page.waitForTimeout(1200)
  const dir = page.locator('button:text-is("project/")')
  if (await dir.count()) { await dir.first().click(); await page.waitForTimeout(1000) }
  for (const f of ['app.py', 'config.yaml', 'deploy.sh']) {
    await page.locator(`input[type=checkbox][aria-label="Select ${f}"]`).check()
  }
  await page.waitForTimeout(600)
  // the last checkbox keeps the focus, and its row shows the hover actions instead of size/date
  await page.evaluate(() => document.activeElement?.blur())
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
  // Escape stays inside Monaco (it has the focus) — the editor's own Close button
  await page.getByRole('dialog', { name: 'Edit deploy.sh' }).getByRole('button', { name: 'Close', exact: true }).click()
  await page.waitForSelector('.monaco-editor', { state: 'detached', timeout: 8000 })
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
  // over the dashboard: the modal is translucent in light mode, and a terminal preview behind
  // it (the host page) shows through as a dark smudge
  await goHome(page)
  await page.locator('button[aria-label="Settings"]').first().click()
  await page.waitForTimeout(1000)
  // the old "Security" tab was split up in 3.5.9; 06-security now shows "Sign-in & 2FA"
  // …and 3.7.1 folded "Sign-in & 2FA" into "Account & security"
  await page.getByRole('button', { name: /^(Account & security|Sign-in & 2FA)$/ }).first().click()
  await page.waitForTimeout(1500)
  await shotBoth(page, '06-security')
  await page.keyboard.press('Escape')
  await page.waitForTimeout(500)
})

// -- 6. Run on hosts: a saved command on four hosts, results grid --------------------------
// `pause` = extra time between the clicks (the tour paces them for a human viewer)
async function fleetRun(pg, pause = 0) {
  await goHome(pg)
  await pg.locator('button[aria-label="Run on hosts"]').first().click()
  await pg.waitForTimeout(1200 + pause)
  const dlg = pg.getByRole('dialog')
  await dlg.locator('button[aria-label="Use saved command: Deployed release"]').click()
  await pg.waitForTimeout(pause)
  // not db-01: it requires 2FA on connect, and since 3.5.13 the password alone is no step-up
  // (the demo account has no passkey/TOTP) — worker-03 is the fourth agent instead
  for (const h of ['web-01', 'web-02', 'cache-01', 'worker-03']) {
    await dlg.getByRole('button', { name: h, exact: true }).click()
    await pg.waitForTimeout(pause / 4)
  }
  await dlg.getByRole('button', { name: 'Continue →' }).click()
  await pg.waitForTimeout(800 + pause)
  await dlg.getByRole('button', { name: /^Run on/ }).first().click()
  await pg.waitForTimeout(4000)
}

await step('fleet', async () => {
  await fleetRun(page)
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
  await phone.locator('button[aria-label="New session on web-01"]').first().click({ modifiers: ['Shift'] })
  await phone.waitForSelector('.xterm-screen', { timeout: 15000 })
  await phone.waitForTimeout(2500)
  // the title field is hidden on a phone: named through the API (the sid is in the route)
  const sid = (await phone.evaluate(() => location.hash)).match(/[0-9a-f]{32}/)?.[0]
  if (sid) await apiCall(phone, 'PATCH', `/api/sessions/${sid}`, { title: 'on the go' }).catch(() => {})
  await phone.locator('.xterm-screen').first().tap().catch(() => {})
  await typeCommands(phone, ['cd project', 'ls', 'tail -n 4 logs/access-2026-10-06.log', 'cat ~/RELEASE'])
  await phone.waitForTimeout(1000)
  await shotBoth(phone, '08-phone')
  await phone.context().close()
})

// -- 8. split view (3.6.12): three sessions, "one big on the left, two stacked" -------------
// Runs after the phone: from here on the tab bar carries the split view.
// a split view of the LAST three sessions opened (pick order = pane order), host list folded
async function splitLastThree(pg, name, pause = 0) {
  await pg.getByRole('button', { name: 'New split view', exact: true }).click()
  const dlg = pg.getByRole('dialog', { name: 'New split view' })
  await dlg.waitFor({ timeout: 8000 })
  await dlg.locator('input:not([type=checkbox])').first().fill(name)
  // the three sessions just opened are the last three rows
  const rows = dlg.locator('label:has(input[type=checkbox])')
  const n = await rows.count()
  for (let i = 0; i < n; i++) {
    const cb = rows.nth(i).locator('input[type=checkbox]')
    if (await cb.isChecked()) await cb.uncheck()
  }
  for (let i = n - 3; i < n; i++) {
    await rows.nth(i).locator('input[type=checkbox]').check()
    await pg.waitForTimeout(pause / 3)
  }
  await dlg.getByRole('button', { name: 'Show side by side', exact: true }).click()
  await pg.waitForTimeout(2000)
  // three panes open as "main-left" by default (lib/splitLayout.ts) — no layout pick needed.
  // The host list folds away for this one: three terminals need the width.
  await pg.getByRole('button', { name: 'Hide the host list', exact: true }).click()
  await pg.waitForTimeout(2500)                 // panes re-fit; top ticks
}

await step('split', async () => {
  await goHome(page)
  // web-01 (big pane): a fresh session running top; web-02 + cache-01 stacked on the right
  const panes = [
    ['web-01', 'top', ['top -d 2']],
    ['web-02', 'deploy', ['cd /root/project', './deploy.sh --dry-run']],
    ['cache-01', 'health check', ['uptime', 'free -h', 'df -h / | tail -1']],
  ]
  for (const [host, title, cmds] of panes) {
    await goHome(page)
    await openSession(page, host, { title })
    await typeCommands(page, cmds, 900)
  }
  await splitLastThree(page, 'prod-debug')
  await page.evaluate(() => document.activeElement?.blur())
  await park(page)
  await shotBoth(page, '09-split')
  await page.locator('button[aria-label^="Open host list"]:visible').first().click()
  await page.waitForTimeout(800)
})

// -- 9. Settings → Appearance, the app in the macOS-style theme (3.6.4) --------------------
await step('themes', async () => {
  await page.locator('button[aria-label="Settings"]').first().click()
  await page.waitForTimeout(1000)
  await page.getByRole('button', { name: 'Appearance', exact: true }).first().click()
  await page.waitForTimeout(1200)
  await park(page)
  // the README shows the macOS family; with SHOT_THEMES (the website) the EverShell theme itself
  await shotBoth(page, '10-themes', {}, process.env.SHOT_THEMES ? THEMES : ['mac:dark', 'mac:light'])
  await page.keyboard.press('Escape')
  await page.waitForTimeout(500)
})

// ── website captures (11–16). They run after the README ones, so the README PNGs above keep
// showing the fleet exactly as before (no extra forwards, host, badge or share link yet).

// a same-origin call from the signed-in page (the browser adds the Origin csrf_guard wants)
async function apiCall(pg, method, path, body) {
  return pg.evaluate(async ([m, p, b]) => {
    const r = await fetch(p, { method: m, headers: b ? { 'Content-Type': 'application/json' } : {},
      body: b ? JSON.stringify(b) : undefined })
    const txt = await r.text()
    if (!r.ok) throw new Error(`${m} ${p} → ${r.status} ${txt.slice(0, 200)}`)
    return txt ? JSON.parse(txt) : null
  }, [method, path, body ?? null])
}
const hostId = async (pg, name) =>
  (await apiCall(pg, 'GET', '/api/hosts')).find((h) => h.name === name).id

async function openHostPage(pg, name) {
  await goHome(pg)
  await pg.locator(`button[aria-label="Open host ${name}"]`).first().click()
  await pg.waitForTimeout(1500)
}

// -- 12. Port forwards: the demo API (a real http.server on web-01:8080, started by run.sh) is
// started and answers; a second one is defined but stopped. Host page → Forwards tab.
await step('forward', async () => {
  const id = await hostId(page, 'web-01')
  const have = await apiCall(page, 'GET', `/api/hosts/${id}/forwards`)
  const list = Array.isArray(have) ? have : (have.forwards ?? [])
  if (!list.some((f) => f.label === 'demo-api')) {
    await apiCall(page, 'POST', `/api/hosts/${id}/forwards`, {
      label: 'demo-api', target_host: '127.0.0.1', target_port: 8080, scheme: 'http',
      description: 'internal API docs (staging)', enabled: true })
    await apiCall(page, 'POST', `/api/hosts/${id}/forwards`, {
      label: 'metrics', target_host: '127.0.0.1', target_port: 9100, scheme: 'http',
      description: 'node exporter — off until needed', enabled: false })
  }
  await openHostPage(page, 'web-01')
  await page.getByRole('button', { name: 'Forwards', exact: true }).first().click()
  await page.waitForTimeout(3000)               // the reachability probe answers
  await park(page)
  await shotBoth(page, '12-forward')
})

// -- 13. OS updates: run.sh (re)downgraded three packages, so web-01 really has 3 pending (2 of
// them security). The other agents checked before that and cache the answer for 6 h; web-01 is
// asked for a fresh snapshot (the host page's Refresh does the same), then the badge → dialog.
await step('updates', async () => {
  const id = await hostId(page, 'web-01')
  await apiCall(page, 'POST', `/api/hosts/${id}/diagnostics/refresh`)
  await goHome(page)
  await page.reload({ waitUntil: 'networkidle' })
  await page.waitForSelector('[data-testid="dashboard"]', { timeout: 15000 })
  await page.waitForTimeout(1500)
  await page.locator('button[aria-label*="OS updates pending"]:visible').first().click()
  await page.getByRole('dialog', { name: 'Updates on web-01' }).waitFor({ timeout: 8000 })
  await page.waitForTimeout(600)
  await park(page)
  await shotBoth(page, '13-updates')
  await page.keyboard.press('Escape')
  await page.waitForTimeout(400)
})

// -- 14. Diagnostics of web-01, Ports tab: the listening sockets (the gateway, the demo API).
// Not the Overview tab: in this container it reports the BUILD machine's kernel, CPU, RAM and
// uptime — real data that is neither fictional nor ours to publish.
await step('diagnostics', async () => {
  await openHostPage(page, 'web-01')
  await page.getByRole('button', { name: 'Diagnostics', exact: true }).first().click()
  const diag = page.getByRole('dialog', { name: 'Connection diagnostics' })
  await diag.waitFor({ timeout: 8000 })
  await diag.getByRole('button', { name: 'Ports', exact: true }).click()
  await page.waitForTimeout(3000)
  await park(page)
  await shotBoth(page, '14-diagnostics')
  await page.getByRole('dialog', { name: 'Connection diagnostics' })
    .getByRole('button', { name: 'Close', exact: true }).first().click().catch(() => {})
  await page.waitForTimeout(400)
})

// -- 15. Transfers: a real 20 MB upload (generated in memory) into web-01:~/project. The first
// 8 MB chunk goes through; the next one is held until both themes are captured, so the widget
// shows it mid-flight — then it is released and the upload finishes normally.
await step('upload', async () => {
  await goHome(page)
  await openSession(page, 'web-01', { title: 'dataset upload' })
  await toolbar(page, 'Files').click()
  await page.waitForTimeout(1200)
  const dir = page.locator('button:text-is("project/")')
  if (await dir.count()) { await dir.first().click(); await page.waitForTimeout(1000) }
  await page.evaluate(() => localStorage.setItem('wt_transfers_min', '0'))
  const held = []
  const hold = (route) => {
    const u = new URL(route.request().url())
    if (route.request().method() === 'POST' && Number(u.searchParams.get('offset') || 0) > 0) held.push(route)
    else route.continue()
  }
  await page.route(/\/api\/hosts\/\d+\/fs\/upload\?/, hold)
  await page.locator('input[type=file]').first().setInputFiles({
    name: 'dataset-2026-10.tar.gz', mimeType: 'application/gzip',
    buffer: Buffer.alloc(20 * 1024 * 1024, 0x5a) })
  // REUSE=1: the file is there from the last run → "1 file already exists here. Overwrite?"
  const over = page.getByRole('button', { name: 'Overwrite', exact: true })
  await over.waitFor({ timeout: 1500 }).then(() => over.click()).catch(() => {})
  for (let i = 0; i < 40 && !held.length; i++) await page.waitForTimeout(250)
  if (!held.length) throw new Error('the upload never reached its second chunk')
  await page.waitForTimeout(800)
  const pill = page.locator('[data-testid="wt-transfers-pill"]')
  if (await pill.isVisible().catch(() => false)) { await pill.click(); await page.waitForTimeout(400) }
  await page.evaluate(() => document.activeElement?.blur())
  await park(page)
  await shotBoth(page, '15-upload')
  await page.unroute(/\/api\/hosts\/\d+\/fs\/upload\?/, hold)
  for (const r of held.splice(0)) await r.continue().catch(() => {})
  await page.waitForTimeout(3000)               // the rest goes through; the job completes
  // finished rows out of the widget, or the next captures carry a "Done" card
  await page.getByRole('button', { name: 'Clear finished', exact: true }).click().catch(() => {})
  await toolbar(page, 'Close file panel').click().catch(() => {})
  await page.waitForTimeout(400)
})

// -- 16. Share link: a read-only link with a 1-hour expiry for a live session ----------------
await step('share', async () => {
  await goHome(page)
  await openSession(page, 'web-01', { title: 'access log' })
  await typeCommands(page, ['cd project', 'tail -n 6 logs/access-2026-10-06.log'])
  await toolbar(page, 'Share link').click()
  await page.waitForTimeout(600)
  await page.locator('select[aria-label="Share link expiry"]').selectOption('60')
  await page.getByRole('button', { name: 'Generate link', exact: true }).click()
  await page.locator('[data-testid="share-expires"]').waitFor({ timeout: 8000 })
  await page.waitForTimeout(800)
  await page.evaluate(() => document.activeElement?.blur())
  await park(page)
  await shotBoth(page, '16-share')
})

// -- 17. Settings on a phone (3.7.1): the grouped list (Personal / Administration / Operations)
// with the search box on top, the screen a phone opens on.
await step('settingsphone', async () => {
  const phone = await newPage(browser, {
    viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true,
  })
  // on a phone the Settings button sits in the host list, a drawer behind "Open host list"
  const drawer = phone.locator('button[aria-label^="Open host list"]:visible').first()
  if (await drawer.count()) { await drawer.click(); await phone.waitForTimeout(600) }
  try {
    await phone.getByRole('button', { name: /^Settings/ }).filter({ visible: true }).first().click({ timeout: 8000 })
    await phone.locator('input[aria-label="Search settings"]').waitFor({ timeout: 8000 })
  } catch (e) {
    await phone.screenshot({ path: `${OUT}/_failed-settingsphone-phone.png` }).catch(() => {})
    throw e
  }
  await phone.waitForTimeout(1000)
  await phone.evaluate(() => document.activeElement?.blur())
  await shotBoth(phone, '17-settings-phone')
  await phone.context().close()
})

// -- 11. Add host: the agent install step (enrolment command + "waiting for the agent").
// Last, because it really adds a host (offline) to the fleet.
await step('addhost', async () => {
  await goHome(page)
  // the sidebar's "+" (the dashboard's own "Add a host" button shows only on an empty fleet)
  await page.locator('button[aria-label="Add host"]:visible').first().click()
  const dlg = page.getByRole('dialog', { name: 'Add a host' })
  await dlg.waitFor({ timeout: 8000 })
  await dlg.getByPlaceholder('e.g.: vps-hetzner, homelab').fill('web-03')
  await dlg.getByPlaceholder('comma-separated, e.g.: prod, debian, web').fill('web, prod')
  await dlg.getByRole('button', { name: /^(Continue|Add)$/ }).click()
  await page.getByText('Install the agent on "web-03"').waitFor({ timeout: 10000 })
  await page.waitForTimeout(1000)
  await page.evaluate(() => document.activeElement?.blur())
  await park(page)
  await shotBoth(page, '11-addhost')
  await page.keyboard.press('Escape')
  await page.waitForTimeout(400)
})

await browser.close()
if (FAILED.length) {
  log('FAILED: ' + FAILED.join(', ') + ' — the previous screenshots are still on disk, out of sync')
  process.exit(1)
}
log('done')
