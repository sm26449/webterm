/* E2E Playwright pentru UI-ul funcţiilor 2.1.0 pe care tsc/eslint/vitest nu-l EXECUTĂ:
   - token de înrolare DE GRUP (Settings → Security): creare → one-liner reutilizabil afişat;
   - ETICHETE pe host (Add-host): input → salvate (verificat prin API) → chip în sidebar.
   (Helper-ele de chei SSH şi comenzile fleet salvate sunt acoperite de testele de backend /
   localStorage + smoke; aici prindem cele două fluxuri de UI noi cele mai valoroase.)
   Rulează contra unei instanţe efemere, fără agent/fixture-uri. Nu atinge prod. */
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8795'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'e2e-features-token'
const EMAIL = 'e2e-feat@example.com'
const PASSWORD = 'parola-e2e-feat-123456'

const results = []
const check = (name, cond) => { results.push([name, !!cond]); console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`) }
const fail = (msg) => { console.error(`EROARE: ${msg}`); process.exit(1) }

const su = await fetch(`${BASE}/api/setup`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN }),
})
if (!su.ok) fail(`setup: ${su.status} ${await su.text()}`)
check('setup cont prin API', true)

const pageErrors = []
const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'en-US' })
  page.on('pageerror', (e) => pageErrors.push(String(e)))
  const waitText = (re, ms = 15000) => page.waitForFunction(
    (r) => new RegExp(r).test(document.body.innerText), re, { timeout: ms })

  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('button[aria-label="Settings"]', { timeout: 15000 })
  check('login în UI', true)

  // ── Token de înrolare DE GRUP (Settings → Security) ──
  await page.click('button[aria-label="Settings"]')
  await page.getByRole('button', { name: 'Security', exact: true }).click()
  const form = page.locator('[data-testid="enroll-group-form"]')
  await form.locator('[aria-label="Token name"]').fill('prod-rollout')
  await form.locator('[aria-label="Current password"]').fill(PASSWORD)
  await form.getByRole('button', { name: 'Create group token' }).click()
  await waitText('/install/group/', 15000)
  check('token de grup creat → one-liner reutilizabil afişat',
    /\/install\/group\//.test(await page.locator('body').innerText()))
  check('tokenul apare în listă', await page.locator('text=prod-rollout').first().isVisible())

  // închide Settings (focus-trap închide pe Escape)
  await page.keyboard.press('Escape')
  await page.waitForSelector('[data-testid="enroll-group-form"]', { state: 'detached', timeout: 5000 }).catch(() => {})

  // ── ETICHETE pe host (Add-host) ──
  await page.getByRole('button', { name: 'Add a host' }).first().click()
  await page.getByPlaceholder('e.g.: vps-hetzner, homelab').fill('tagged-box')
  await page.getByPlaceholder('comma-separated, e.g.: prod, debian, web').fill('Prod, Web')
  // host cu agent (implicit): butonul de submit e „Continue" (SSH/Telnet ar fi „Add")
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  // create → apare vederea cu comanda de install; hostul EXISTĂ deja. Verificăm prin API.
  await waitText('tagged-box', 10000)
  const hosts = await page.evaluate(async () => (await fetch('/api/hosts', { credentials: 'same-origin' })).json())
  const h = hosts.find((x) => x.name === 'tagged-box')
  check('hostul s-a creat cu etichetele normalizate',
    !!h && JSON.stringify(h.tags) === JSON.stringify(['prod', 'web']))

  // închide modalul (Done) → sidebar-ul arată chip-ul de etichetă
  await page.getByRole('button', { name: 'Done', exact: true }).click().catch(() => page.keyboard.press('Escape'))
  await waitText('tagged-box', 8000).catch(() => {})
  check('sidebar-ul arată hostul etichetat', /tagged-box/.test(await page.locator('body').innerText()))
  const prodChip = page.locator('button[title="Filter by tag: prod"]')
  await prodChip.first().waitFor({ state: 'visible', timeout: 8000 }).catch(() => {})
  check('chip de etichetă „prod" prezent (clicabil pentru filtrare)', await prodChip.count() > 0)

  check('nicio eroare de pagină (React/JS)', pageErrors.length === 0)
  if (pageErrors.length) console.error('pageerrors:', pageErrors)
} finally {
  await browser.close()
}

const failed = results.filter(([, ok]) => !ok)
console.log(`\n${results.length - failed.length}/${results.length} treceri`)
process.exit(failed.length ? 1 : 0)
