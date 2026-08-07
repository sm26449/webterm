/* Audit responsive pe o matrice de device-uri reale (Playwright device presets).
   Nu ghicim din CSS — MĂSURĂM în browser: overflow orizontal, elemente care ies
   din ecran, suprapuneri peste zone interactive, ținte tactile sub 44px,
   dimensiunea utilă a terminalului. Plus screenshots pentru inspecție vizuală.

     node mobile-audit.mjs http://127.0.0.1:8000 /out/dir

   Prereq: gateway pornit cu agent conectat (ca la e2e-session.mjs). */
import { mkdirSync, writeFileSync } from 'node:fs'
import { chromium, devices, webkit } from 'playwright'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const OUT = process.argv[3] ?? '/tmp/wt-mobile'
const EMAIL = 'e2e@example.com'
const PASSWORD = 'parola-e2e-123456'
// Numele hostului pe care se face auditul. Era hardcodat 'mobil-test', dar CI-ul creează
// 'ci-local' (scripts/e2e-session.mjs), deci cardul nu se găsea niciodată, click-ul era
// înghiţit de `.catch(() => {})` şi TOT blocul de sesiune se sărea tăcut: 10 device-uri
// raportau „ok" după ce măsuraseră doar login-ul şi dashboard-ul. Vezi COVERAGE mai jos —
// acum lipsa unei etape e ea însăşi un bug, nu o tăcere.
const HOST = process.env.MOBILE_HOST ?? 'ci-local'
// filtru pentru iterat local pe un singur device (CI le rulează pe toate)
const ONLY = (process.env.MOBILE_DEVICES ?? '').split(',').map((s) => s.trim()).filter(Boolean)

mkdirSync(OUT, { recursive: true })

// matrice: telefoane mici/mari, tablete, iOS (WebKit) și Android (Chromium),
// portret și peisaj pentru cele mai relevante
const MATRIX = [
  { name: 'iphone-se', device: devices['iPhone SE'], engine: 'webkit' },
  { name: 'iphone-13', device: devices['iPhone 13'], engine: 'webkit' },
  { name: 'iphone-15-max', device: devices['iPhone 15 Pro Max'], engine: 'webkit' },
  { name: 'iphone-13-landscape', device: devices['iPhone 13 landscape'], engine: 'webkit' },
  { name: 'ipad-mini', device: devices['iPad Mini'], engine: 'webkit' },
  { name: 'ipad-pro-11', device: devices['iPad Pro 11'], engine: 'webkit' },
  { name: 'ipad-pro-11-landscape', device: devices['iPad Pro 11 landscape'], engine: 'webkit' },
  { name: 'galaxy-s9', device: devices['Galaxy S9+'], engine: 'chromium' },
  { name: 'pixel-7', device: devices['Pixel 7'], engine: 'chromium' },
  { name: 'galaxy-tab-s4', device: devices['Galaxy Tab S4'], engine: 'chromium' },
]

const problems = []
const note = (dev, screen, severity, msg, extra) =>
  problems.push({ dev, screen, severity, msg, ...(extra ? { extra } : {}) })

// Etapele pe care auditul TREBUIE să le atingă pe fiecare device. Fără asta, orice selector
// derapat transformă poarta într-un no-op verde: nu se măsoară nimic şi nimeni nu află.
const REQUIRED = ['login', 'dashboard', 'pagina-host', 'session', 'tastare']

/** Măsurători în pagină: overflow, elemente în afara viewportului, ținte mici. */
const MEASURE = () => {
  const vw = window.innerWidth
  const vh = window.innerHeight
  const out = {
    vw, vh,
    docScrollW: document.documentElement.scrollWidth,
    bodyScrollW: document.body.scrollWidth,
    overflowX: document.documentElement.scrollWidth > window.innerWidth + 1,
    offscreen: [],
    smallTargets: [],
    covered: [],
    term: null,
  }
  const label = (el) =>
    `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}` +
    `${el.getAttribute('aria-label') ? `[${el.getAttribute('aria-label')}]` : ''}` +
    `${el.className && typeof el.className === 'string' ? '.' + el.className.split(' ').slice(0, 2).join('.') : ''}`

  // elemente vizibile care ies pe orizontală din viewport
  for (const el of document.querySelectorAll('body *')) {
    const s = getComputedStyle(el)
    if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') continue
    const r = el.getBoundingClientRect()
    if (r.width === 0 || r.height === 0) continue
    if (r.right > vw + 2 || r.left < -2) {
      // ignoră containere care scrollează intenționat pe orizontală
      const scrolls = s.overflowX === 'auto' || s.overflowX === 'scroll'
      const parentScrolls = el.parentElement && ['auto', 'scroll'].includes(getComputedStyle(el.parentElement).overflowX)
      // ignoră elementele CLIPATE de un strămoș cu overflow:hidden (truncate):
      // depășesc pe hârtie, dar utilizatorul nu vede nimic ieșind din ecran
      let clipped = false
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        const ps = getComputedStyle(p)
        if (ps.overflow === 'hidden' || ps.overflowX === 'hidden' || ps.textOverflow === 'ellipsis') {
          const pr = p.getBoundingClientRect()
          if (pr.right <= vw + 2) { clipped = true; break }
        }
      }
      if (!scrolls && !parentScrolls && !clipped && out.offscreen.length < 12) {
        out.offscreen.push({ el: label(el), left: Math.round(r.left), right: Math.round(r.right) })
      }
    }
  }

  // ținte tactile sub 44px (doar cele vizibile, interactive)
  for (const el of document.querySelectorAll('button, a[href], input[type=checkbox], [role=button]')) {
    const r = el.getBoundingClientRect()
    if (r.width === 0 || r.height === 0) continue
    if (r.top > vh || r.bottom < 0) continue
    if ((r.width < 40 || r.height < 40) && out.smallTargets.length < 15) {
      out.smallTargets.push({ el: label(el), w: Math.round(r.width), h: Math.round(r.height) })
    }
  }

  // Un modal/drawer deschis acoperă LEGITIM tot ce e în spatele lui (scrim pe tot ecranul).
  // Fără excepţia asta, prima ecranizare cu drawer deschis raportează fiecare buton al
  // aplicaţiei drept „acoperit" — 10 false pozitive care ar bloca release-ul degeaba.
  const scrim = [...document.querySelectorAll('div, section, aside')].find((e) => {
    const s = getComputedStyle(e)
    if (s.position !== 'fixed' || s.display === 'none' || s.visibility === 'hidden') return false
    const r = e.getBoundingClientRect()
    return r.width >= vw * 0.95 && r.height >= vh * 0.95
  })
  out.modalOpen = !!scrim

  // elemente fixe care ACOPERĂ butoane (suprapunere reală: elementul de la
  // punctul central al butonului nu e butonul și nici copilul lui)
  for (const el of scrim ? [] : document.querySelectorAll('header button, nav button, [role=dialog] button')) {
    const r = el.getBoundingClientRect()
    if (r.width === 0 || r.height === 0) continue
    const cx = r.left + r.width / 2
    const cy = r.top + r.height / 2
    if (cx < 0 || cy < 0 || cx > vw || cy > vh) continue
    const top = document.elementFromPoint(cx, cy)
    if (top && top !== el && !el.contains(top) && !top.contains(el) && out.covered.length < 10) {
      out.covered.push({ el: label(el), acoperit_de: label(top) })
    }
  }

  // dimensiunea utilă a terminalului
  const screen = document.querySelector('.xterm-screen')
  if (screen) {
    // Numărul de rânduri se citea din `.xterm-rows`.children — gol sub renderer-ul WebGL,
    // deci ar fi raportat 0 pe orice device („terminal prea mic"), un fals pozitiv care ar fi
    // blocat release-ul degeaba. xterm ştie singur câte rânduri are.
    const terms = window.__wtTerms
    const term = terms && terms.size
      ? (terms.get(location.hash.replace('#/s/', '')) ?? [...terms.values()][0])
      : null
    const domRows = document.querySelector('.xterm-rows')
    out.term = {
      w: Math.round(screen.clientWidth),
      h: Math.round(screen.clientHeight),
      rows: term ? term.rows : (domRows ? domRows.children.length : 0),
    }
  }
  return out
}

async function auditDevice(cfg) {
  const browserType = cfg.engine === 'webkit' ? webkit : chromium
  const browser = await browserType.launch()
  const ctx = await browser.newContext({ ...cfg.device, locale: 'en-US' })   // UI i18n → limbă RO fixă
  const page = await ctx.newPage()
  const errors = []
  const reached = new Set()
  let blocker = ''            // de ce s-a oprit fluxul, raportat o singură dată
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)))

  const shot = (n) => page.screenshot({ path: `${OUT}/${cfg.name}-${n}.png`, fullPage: false })
  const check = async (screen) => {
    const m = await page.evaluate(MEASURE)
    if (m.overflowX) note(cfg.name, screen, 'bug', `scroll orizontal (${m.docScrollW}px > ${m.vw}px)`)
    for (const o of m.offscreen) note(cfg.name, screen, 'bug', `element în afara ecranului: ${o.el}`, o)
    for (const c of m.covered) note(cfg.name, screen, 'bug', `buton acoperit: ${c.el} ← ${c.acoperit_de}`)
    // fără plafoane tăcute: spunem când o verificare a fost sărită, nu o trecem drept „ok"
    if (m.modalOpen) note(cfg.name, screen, 'info', 'modal deschis → verificarea „buton acoperit" sărită')
    for (const t of m.smallTargets) note(cfg.name, screen, 'ux', `țintă tactilă mică: ${t.el} (${t.w}×${t.h})`)
    return m
  }

  try {
    // login
    await page.goto(BASE)
    await page.fill('input[type=email]', EMAIL)
    await page.fill('input[type=password]', PASSWORD)
    await shot('01-login')
    await check('login')
    reached.add('login')
    await page.click('button:has-text("Sign in")')
    await page.waitForSelector('[data-testid="dashboard"]', { timeout: 15000 })
    await page.waitForTimeout(1500)

    // dashboard
    await shot('02-dashboard')
    await check('dashboard')
    reached.add('dashboard')

    // sidebar (drawer pe mobil — pe tablete e permanent vizibil)
    const menu = page.locator('button[aria-label="Open host list"]').first()
    if (await menu.isVisible().catch(() => false)) {
      await menu.click()
      await page.waitForTimeout(700)
      await shot('03-sidebar')
      await check('sidebar')
      await page.keyboard.press('Escape').catch(() => {})
      await page.mouse.click(5, 5).catch(() => {})
      await page.waitForTimeout(500)
    }

    // Calea REALĂ a unui om pe telefon: tap pe cardul hostului → pagina hostului
    // → „Sesiune nouă". (Butonul „+" de pe card e hover-only, deci pe touch e
    // invizibil — problemă în sine, raportată separat.)
    const cards = page.locator('[data-testid="dashboard"] div').filter({ hasText: HOST })
    if ((await cards.count()) === 0) {
      blocker = `cardul hostului "${HOST}" nu există pe dashboard (setează MOBILE_HOST?)`
    } else {
      await cards.last().click({ timeout: 10000 })
      await page.waitForTimeout(1200)
      await shot('04-pagina-host')
      await check('pagina-host')
      reached.add('pagina-host')
    }

    const newSession = page.locator('button:has-text("New session"):visible').first()
    if (!reached.has('pagina-host')) {
      /* deja raportat mai sus */
    } else if (!(await newSession.isVisible().catch(() => false))) {
      blocker = 'butonul de sesiune nouă nu e vizibil pe pagina hostului'
    } else {
      await newSession.click()
      await page.waitForSelector('.xterm-screen', { timeout: 20000 })
      await page.waitForTimeout(2500)
      const m = await check('session')
      reached.add('session')
      await shot('05-sesiune')
      if (m.term) {
        if (m.term.rows < 10) note(cfg.name, 'session', 'bug', `terminal prea mic: doar ${m.term.rows} rânduri`)
        note(cfg.name, 'session', 'info', `terminal ${m.term.w}×${m.term.h}px, ${m.term.rows} rânduri`)
      } else {
        note(cfg.name, 'session', 'bug', 'terminalul nu s-a randat')
      }

      // tastare (verifică și keybar-ul mobil)
      await page.locator('.xterm-screen').click()
      await page.keyboard.type('echo MOBIL_OK\n')
      // Se citea din `.xterm-rows` — gol de la trecerea pe renderer WebGL, deci verificarea
      // ar fi picat pe toate device-urile din motivul greşit. Sursa de adevăr e bufferul xterm.
      let txt = ''
      for (let i = 0; i < 20 && !txt.includes('MOBIL_OK'); i++) {
        await page.waitForTimeout(400)
        txt = await page.evaluate(() => {
          const terms = window.__wtTerms
          if (!terms || terms.size === 0) return ''
          const term = terms.get(location.hash.replace('#/s/', '')) ?? [...terms.values()][0]
          const b = term.buffer.active
          let out = ''
          for (let j = 0; j < b.length; j++) out += (b.getLine(j)?.translateToString(true) ?? '') + '\n'
          return out
        })
      }
      if (txt.includes('MOBIL_OK')) reached.add('tastare')
      else note(cfg.name, 'session', 'bug', 'comanda tastată nu a produs output')
      await shot('06-sesiune-output')

      // panoul de comenzi (OSC 133) — pe mobil ocupă 256px din lățime!
      const cmdBtn = page.locator('button[title*="Commands —"]:visible, button[title*="Commands:"]:visible').first()
      if (await cmdBtn.isVisible().catch(() => false)) {
        await cmdBtn.click()
        await page.waitForTimeout(600)
        await shot('07-panou-comenzi')
        await check('panou-comenzi')
        await cmdBtn.click().catch(() => {})
        await page.waitForTimeout(300)
      }
    }

    // setări (modal lung)
    await page.evaluate(() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true })))
    await page.waitForTimeout(600)
    await page.keyboard.press('Escape').catch(() => {})

    if (errors.length) note(cfg.name, 'global', 'bug', `erori JS: ${errors.join(' | ')}`)
  } catch (e) {
    note(cfg.name, 'flux', 'bug', `auditul s-a oprit: ${String(e).slice(0, 140)}`)
    await shot('99-eroare').catch(() => {})
  } finally {
    // Poarta trebuie să fie onestă şi când NU a măsurat: prima etapă neatinsă e un bug.
    // Fără asta, „0 probleme” a însemnat „nu am apucat să testez sesiunea”, luni în şir.
    // Raportăm doar punctul de rupere, nu toată cascada de după el.
    const missing = REQUIRED.find((s) => !reached.has(s))
    if (missing) {
      note(cfg.name, missing, 'bug',
        `etapa "${missing}" nu s-a rulat, deci nu a fost auditată${blocker ? ` — ${blocker}` : ''}`)
    }
    await browser.close()
  }
}

for (const cfg of MATRIX.filter((c) => !ONLY.length || ONLY.includes(c.name))) {
  process.stdout.write(`▸ ${cfg.name} (${cfg.engine}) … `)
  await auditDevice(cfg)
  const n = problems.filter((p) => p.dev === cfg.name && p.severity === 'bug').length
  console.log(n ? `${n} probleme` : 'ok')
}

writeFileSync(`${OUT}/raport.json`, JSON.stringify(problems, null, 2))

console.log('\n=== PROBLEME (bug) ===')
const bugs = problems.filter((p) => p.severity === 'bug')
for (const p of bugs) console.log(`  [${p.dev}/${p.screen}] ${p.msg}`)
console.log(`\n=== ȚINTE TACTILE MICI: ${problems.filter((p) => p.severity === 'ux').length} ===`)
const byTarget = {}
for (const p of problems.filter((p) => p.severity === 'ux')) byTarget[p.msg] = (byTarget[p.msg] ?? 0) + 1
for (const [k, v] of Object.entries(byTarget).slice(0, 12)) console.log(`  ${v}× ${k}`)
console.log(`\n=== INFO ===`)
for (const p of problems.filter((p) => p.severity === 'info')) console.log(`  [${p.dev}] ${p.msg}`)
console.log(`\ntotal bug: ${bugs.length} · screenshots în ${OUT}`)

// CI: orice problemă de layout oprește publicarea imaginii
process.exit(bugs.length ? 1 : 0)
