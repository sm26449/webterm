// Gardul de frontend pentru SSO/OIDC: verifică CONTRACTUL pe care se bazează pagina de login
// când SSO e activ. Backend-ul (schimb de cod, validare id_token, provizionare, grup) e acoperit
// hermetic de tests/oidc_test.py; ce lipsea era partea de UI, unde regresiile chiar au apărut:
//   1. butonul „Sign in with <provider>" apare DOAR după ce există un cont (logica setupRequired
//      ascunde toate metodele federate cât timp adminul break-glass nu e creat) — subtil, uşor de
//      stricat la un refactor;
//   2. butonul linkează la /api/oidc/login (nu la un URL derivat din request — anti open-redirect).
// NU driveuim un round-trip complet prin IdP aici (ar cere un provider real + rezolvare de hostname
// consistentă browser↔container = flaky în CI); asta o face oidc_test.py la nivel de API.
//
//   node scripts/sso-login.mjs [http://127.0.0.1:8000]
//   env: SSO_SETUP_TOKEN (default ci-e2e-token), SSO_PROVIDER (numele aşteptat pe buton)
import { chromium } from 'playwright'

const url = process.argv[2] ?? 'http://127.0.0.1:8000'
const SETUP_TOKEN = process.env.SSO_SETUP_TOKEN ?? 'ci-e2e-token'
const PROVIDER = process.env.SSO_PROVIDER ?? 'TestSSO'
const SSO_LINK = 'a[href="/api/oidc/login"]'

let failed = null
const fail = (m) => { if (!failed) failed = m }

const browser = await chromium.launch()
const page = await browser.newPage({ locale: 'en-US' })
const pageErrors = []
page.on('pageerror', (e) => pageErrors.push(e.message))

try {
  // status endpoint — contractul backend pe care-l citeşte butonul
  const st = await page.request.get(url + '/api/oidc/status').then((r) => r.json())
  if (st.enabled !== true) fail(`/api/oidc/status nu e enabled (SSO env lipsă pe container?): ${JSON.stringify(st)}`)

  // 1. stare PROASPĂTĂ (setupRequired): niciun buton SSO — doar formularul de setup
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 })
  await page.waitForSelector('html[data-wt-booted]', { state: 'attached', timeout: 30_000 })
  if (await page.locator(SSO_LINK).count() > 0)
    fail('butonul SSO apare pe un WebTerm fără cont (ar trebui ascuns până se creează adminul break-glass)')

  // 2. creăm adminul break-glass (ca prima logare reală), apoi butonul TREBUIE să apară
  const setup = await page.request.post(url + '/api/setup', {
    data: { email: 'sso-ui@example.com', password: 'parola-e2e-123456', setup_token: SETUP_TOKEN },
  })
  if (!setup.ok()) fail(`/api/setup a picat (${setup.status()}) — nu pot verifica starea post-setup`)
  // /api/setup logează (setează sesiunea) — o ştergem ca să vedem PAGINA DE LOGIN cu contul deja
  // existent (adică exact starea în care apare butonul SSO), nu aplicaţia autentificată.
  await page.context().clearCookies()

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 })
  await page.waitForSelector('html[data-wt-booted]', { state: 'attached', timeout: 30_000 })
  const btn = page.locator(SSO_LINK)
  if (await btn.count() === 0) fail('butonul SSO NU apare după crearea contului (regresie pe logica setupRequired?)')
  else {
    if (!(await btn.first().isVisible())) fail('butonul SSO există dar nu e vizibil')
    const text = (await btn.first().innerText()).trim()
    if (!text.includes(PROVIDER)) fail(`eticheta butonului nu conţine providerul „${PROVIDER}": „${text}"`)
  }
  // formularul de parolă (break-glass) rămâne şi cu SSO activ
  if (await page.locator('input[type="password"]').count() === 0)
    fail('formularul de parolă break-glass a dispărut când SSO e activ')

  if (pageErrors.length) fail('erori JS neprinse: ' + pageErrors.join(' | '))
} catch (e) {
  fail(e.message)
}

if (failed) {
  console.error(`✗ SSO LOGIN TEST EȘUAT: ${failed}`)
  await page.screenshot({ path: 'sso-login-fail.png', fullPage: true }).catch(() => {})
  await browser.close(); process.exit(1)
}
console.log('✓ SSO login UI OK — butonul apare doar după cont, linkează la /api/oidc/login, break-glass păstrat')
await browser.close()
