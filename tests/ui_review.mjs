/* Captură completă a suprafeței UI + audit de accesibilitate (axe-core).

   Rulează DUPĂ `scripts/e2e-session.mjs`, pe acelaşi stack: are nevoie de contul şi de
   hostul create acolo (aşteaptă butonul „Host actions", care apare doar dacă există un host).
   Cel mai simplu: `scripts/ci-local.sh e2e a11y`.

   Cere `@axe-core/playwright` pe lângă `playwright` — vezi scripts/ci-local.sh.
   Screenshot-uri în /tmp/webterm-review. */
import { chromium, devices } from 'playwright'
import { AxeBuilder } from '@axe-core/playwright'

// Default-ul era `localhost:8010` — adică exact configuraţia care strică testele:
// `navigator.clipboard` cere context securizat (127.0.0.1 e sigur, un port arbitrar pe
// alt hostname nu), iar curl-ul de shell-integration rulează ÎN container şi are nevoie
// de aceeaşi adresă. CI-ul foloseşte 127.0.0.1:8000; default-ul îl urmează acum.
const BASE = process.env.BASE ?? 'http://127.0.0.1:8000'
// credenţiale din mediu: în CI refolosim contul creat de e2e-session.mjs (are deja un agent
// online), ca să nu pornim un al doilea stack doar pentru scanarea de accesibilitate
const EMAIL = process.env.A11Y_EMAIL ?? 'admin@example.com'
const PASSWORD = process.env.A11Y_PASSWORD ?? 'parola-buna-123'
const OUT = '/tmp/webterm-review'
const a11y = []
const skipped = []
// Câte scanări TREBUIE să iasă dintr-o rulare completă: login, empty state, session view,
// settings modal, file browser, add host modal, mobile session. Dacă un selector derapează,
// pasul e sărit, scanarea lui nu mai are loc — şi fără pragul ăsta poarta rămâne verde
// fiindcă „0 violări" din 0 ecrane scanate arată identic cu 0 violări din 7.
// 6 suprafeţe × 2 teme + Status × 2 + mobil. Numărul e o gardă: dacă o suprafaţă nu se
// deschide (selector schimbat), scanarea nu mai rulează şi poarta trebuie să CADĂ, nu să
// raporteze „0 violări" pentru că n-a scanat nimic.
const EXPECTED_SCANS = 15

/** Pas tolerant: dacă un selector a derapat, notăm şi mergem mai departe.
    Un instrument de recenzie care moare la primul buton mutat nu recenzează nimic. */
async function step(label, fn, page) {
  try {
    await fn()
  } catch (e) {
    skipped.push(`${label}: ${String(e).split('\n')[0].slice(0, 90)}`)
    // curăţăm după eşec: un modal rămas deschis ar bloca TOŢI paşii următori şi
    // ar face să pară că restul suprafeţei nu există (exact ce s-a întâmplat)
    try { await page?.keyboard.press('Escape') } catch { /* ignorăm */ }
  }
}

async function scan(page, label) {
  try {
    const r = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze()
    const serious = r.violations.filter((v) => ['serious', 'critical'].includes(v.impact))
    a11y.push({ label, violations: r.violations.length, serious: serious.length,
      top: serious.slice(0, 6).map((v) => `${v.impact}: ${v.id} (${v.nodes.length}) — ${v.help}`) })
  } catch (e) {
    a11y.push({ label, error: String(e).slice(0, 80) })
  }
}

const browser = await chromium.launch()
async function login(page) {
  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  // „Sesiune nouă" s-a mutat în meniul ⋯ al hostului, deci nu mai e un selector vizibil
  // la încărcare. Semnalul că există un host e chiar butonul de meniu.
  await page.waitForSelector('button[title="Host actions"]', { timeout: 8000 })
}
async function openSession(page) {
  await page.click('button[title="Host actions"]')
  await page.click('button[title="New session"]')
  await page.waitForSelector('.xterm-screen', { timeout: 10000 })
  await page.waitForTimeout(1500)
}

try {
  // ---- DESKTOP, ambele teme ----
  for (const theme of ['macos', 'dark']) {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, locale: 'en-US' })
    const page = await ctx.newPage()
    page.on('dialog', (d) => d.accept())

    // login page
    await page.goto(BASE)
    await page.evaluate((t) => localStorage.setItem('wt_theme', t), theme)
    await page.reload()
    await page.waitForSelector('input[type=email]')
    await page.screenshot({ path: `${OUT}/${theme}-01-login.png` })
    await scan(page, `${theme} login`)

    await login(page)
    await page.screenshot({ path: `${OUT}/${theme}-02-empty.png` })
    await scan(page, `${theme} empty state`)

    await step('deschide sesiune', async () => {
      await openSession(page)
      await page.keyboard.type('ls -la /etc | head -20\n')
      await page.waitForTimeout(1000)
    })
    await page.screenshot({ path: `${OUT}/${theme}-03-session.png` })
    await scan(page, `${theme} session view`)

    // toolbar bars: note + search open
    await step('bare de unelte', async () => {
      await page.locator('button[title*="Note"]').first().click()
      await page.locator('button[title*="scrollback"], button[title*="auth"]').first().click()
      await page.screenshot({ path: `${OUT}/${theme}-04-bars.png` })
      await page.locator('button[title*="Note"]').first().click()
    }, page)

    // settings
    await step('setări', async () => {
    await page.click('button[aria-label="Settings"]')
    await page.waitForSelector('[role=dialog][aria-modal="true"]')
    await page.screenshot({ path: `${OUT}/${theme}-05-settings.png` })
    await scan(page, `${theme} settings modal`)
    await page.keyboard.press('Escape')
    }, page)

    // file browser
    await step('manager de fişiere', async () => {
    await page.locator('.group button[title="Host actions"]').first().click()
    await page.click('text=Files')
    await page.waitForSelector('text=Upload to:')
    await page.waitForTimeout(800)
    await page.screenshot({ path: `${OUT}/${theme}-06-files.png` })
    await scan(page, `${theme} file browser`)
    await page.locator('.fixed.z-50 button', { hasText: '✕' }).first().click()
    }, page)

    // Panoul de Status: suprafaţă pe care poarta n-o atingea deloc, deşi e unde se uită
    // operatorul când ceva nu merge. Auditul a găsit acolo violări de contrast.
    await step('status', async () => {
      await page.click('button[aria-label="Status"], button[title*="Status"]')
      await page.waitForSelector('text=/Gateway|Storage|Hosts/', { timeout: 8000 })
      await page.screenshot({ path: `${OUT}/${theme}-08-status.png` })
      await scan(page, `${theme} status`)
      await page.keyboard.press('Escape').catch(() => {})
    }, page)

    // add-host modal
    await step('adaugă host', async () => {
      await page.click('button[aria-label="Add host"]')
      await page.waitForSelector('text=Add a host')
      await page.screenshot({ path: `${OUT}/${theme}-07-addhost.png` })
      await scan(page, `${theme} add host modal`)
      await page.keyboard.press('Escape').catch(() => {})
    }, page)
    await ctx.close()
  }

  // ---- MOBIL (iPhone) ----
  const mctx = await browser.newContext({ ...devices['iPhone 13'], locale: 'en-US' })
  const m = await mctx.newPage()
  m.on('dialog', (d) => d.accept())
  await m.goto(BASE)
  await m.waitForSelector('input[type=email]')
  await m.screenshot({ path: `${OUT}/m-01-login.png` })
  await m.fill('input[type=email]', EMAIL)
  await m.fill('input[type=password]', PASSWORD)
  await m.click('button:has-text("Sign in")')
  await m.waitForTimeout(1500)
  await m.screenshot({ path: `${OUT}/m-02-empty.png` })
  await m.click('button:has-text("Open host list")')
  await m.waitForTimeout(500)
  await m.screenshot({ path: `${OUT}/m-03-drawer.png` })
  // scopat la drawer-ul vizibil — altfel `.last()` prinde un buton din
  // dashboard-ul din spatele scrim-ului, care interceptează click-ul
  await m.locator('.wt-sidebar button[title="Host actions"] >> visible=true').last().click()
  await m.locator('.wt-sidebar button[title="New session"] >> visible=true').last().click()
  await m.waitForSelector('.xterm-screen')
  await m.waitForTimeout(1500)
  await m.keyboard.type('uptime\n')
  await m.waitForTimeout(800)
  await m.screenshot({ path: `${OUT}/m-04-session.png` })
  await scan(m, 'mobile session')
  await mctx.close()
} finally {
  await browser.close()
}

console.log('\n=== ACCESIBILITATE (axe-core, WCAG 2.1 AA) ===')
for (const r of a11y) {
  if (r.error) { console.log(`  ${r.label}: EROARE ${r.error}`); continue }
  console.log(`  ${r.label}: ${r.violations} violări (${r.serious} serioase)`)
  for (const t of r.top) console.log(`     - ${t}`)
}
if (skipped.length) {
  console.log('\n=== PAŞI SĂRIŢI (selectoare derapate — reparaţi-i, altfel suprafaţa nu e scanată) ===')
  for (const x of skipped) console.log('  -', x)
}
const serious = a11y.reduce((n, r) => n + (r.serious ?? 0), 0)
const total = a11y.reduce((n, r) => n + (r.violations ?? 0), 0)
console.log(`\nTOTAL: ${total} violări, din care ${serious} serioase/critice`)
console.log('Screenshot-uri în', OUT)
// prag: dacă e dat, ieşim cu 1 peste el (aşa devine poartă de CI)
// Poarta se dezarma singură dacă variabila lipsea (redenumire, greşeală de tastare): tipărea
// raportul şi ieşea cu 0. Implicit e acum ARMATĂ; rularea locală de recenzie cere un opt-out
// explicit, ca dezarmarea să fie o decizie, nu un accident.
const max = process.env.A11Y_REPORT_ONLY === '1' ? undefined : (process.env.A11Y_MAX_SERIOUS ?? '0')
if (max !== undefined) {
  const errored = a11y.filter((r) => r.error)
  const reasons = []
  if (serious > Number(max)) reasons.push(`${serious} violări serioase > pragul ${max}`)
  // O scanare care a crăpat contribuia cu `serious ?? 0` = 0 la total, deci o eroare axe
  // TRECEA poarta. La fel şi paşii săriţi: se tipăreau şi atât.
  if (errored.length) reasons.push(`${errored.length} scanări axe au eşuat (${errored.map((r) => r.label).join(', ')})`)
  if (skipped.length) reasons.push(`${skipped.length} paşi săriţi — suprafaţa nu a fost scanată integral`)
  if (a11y.length < EXPECTED_SCANS) reasons.push(`doar ${a11y.length} scanări din ${EXPECTED_SCANS} aşteptate`)
  if (reasons.length) {
    for (const r of reasons) console.error(`EŞEC: ${r}`)
    process.exit(1)
  }
}
