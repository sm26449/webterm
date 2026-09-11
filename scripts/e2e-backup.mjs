/* E2E Playwright pentru UI-ul de backup off-host (Settings → Backup): destinaţiile DIRECTE
   SFTP + FTPS scrise din UI. Conduce browserul REAL contra unei instanţe WebTerm efemere şi a
   unor servere SFTP/FTPS reale (sftp-eval / ftps-eval, pe aceeaşi reţea docker):

   - SFTP: completează formularul, apasă „Test & fetch fingerprint", confirmă că apare amprenta
     SHA256 + indicatorul de host-key pinuit (fluxul TOFU anti-MITM), salvează, „Upload now".
   - FTPS: completează + lipeşte CA-ul self-signed, salvează, „Upload now".

   Nu atinge prod. Aserţiunile pe aterizarea arhivelor se fac din afară (docker exec), aici
   validăm strict wiring-ul de frontend pe care tsc/eslint/vitest nu-l EXECUTĂ.

     node e2e-backup.mjs http://127.0.0.1:8791     (CA_PEM în mediu pentru FTPS) */
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8791'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'e2e-backup-token'
const CA_PEM = process.env.CA_PEM ?? ''
// numele serverelor-fixture pe reţeaua docker (CI le poate redenumi prin env)
const SFTP_HOST = process.env.SFTP_HOST ?? 'sftp-eval'
const FTPS_HOST = process.env.FTPS_HOST ?? 'ftps-eval'
const EMAIL = 'e2e-backup@example.com'
const PASSWORD = 'parola-e2e-backup-123456'
const PASSPHRASE = 'passphrase-eval-arhiva-123'

const results = []
const check = (name, cond) => { results.push([name, !!cond]); console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`) }
const fail = (msg) => { console.error(`EROARE: ${msg}`); process.exit(1) }

// -- cont prin API (setup) ----------------------------------------------------
const setupRes = await fetch(`${BASE}/api/setup`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN }),
})
if (!setupRes.ok) fail(`setup a eșuat: ${setupRes.status} ${await setupRes.text()}`)
check('setup cont prin API', true)

const pageErrors = []
const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'en-US' })
  page.on('pageerror', (e) => pageErrors.push(String(e)))

  // -- login în UI --
  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('button[aria-label="Settings"]', { timeout: 15000 })
  check('login în UI', true)

  // -- Settings → Backup --
  await page.click('button[aria-label="Settings"]')
  await page.getByRole('button', { name: 'Backup', exact: true }).click()
  await page.waitForTimeout(300)
  check('Settings → Backup deschis', await page.locator('text=SFTP').first().isVisible())

  // toate câmpurile/butoanele formularului sunt ancorate la formularul direct (data-testid), ca
  // să nu se ciocnească cu câmpurile de download/restore care au aceleaşi etichete
  const form = page.locator('[data-testid="direct-backup-form"]')
  const fLabel = (l) => form.locator(`[aria-label="${l}"]`)
  const fBtn = (name) => form.getByRole('button', { name, exact: true })
  const hasText = async (re) => new RegExp(re).test(await page.locator('[role="dialog"], body').first().innerText())
  const waitText = (re, ms = 15000) => page.waitForFunction(
    (r) => new RegExp(r).test(document.body.innerText), re, { timeout: ms })

  // ── SFTP: probe (TOFU) → confirmă amprenta → save → upload ──
  await page.getByRole('button', { name: 'SFTP', exact: true }).click()
  await fLabel('Host (e.g. backup.example.com)').fill(SFTP_HOST)
  await fLabel('Username').fill('backup')
  await fLabel('Remote path (e.g. /backups/webterm)').fill('backups')
  // metoda de auth: Parolă (cheia SSH ar cere o cheie de pus; parola e mai simplă pentru test)
  await fBtn('Password').click()
  await fLabel('Password').fill('backup-pass-eval')
  await fLabel('Account password (confirm)').fill(PASSWORD)

  // înainte de probe: NU se poate salva (host-key neconfirmat) — butonul Save e dezactivat
  const saveBtn = fBtn('Save configuration')
  check('SFTP: Save dezactivat până confirmi amprenta', await saveBtn.isDisabled())

  await fBtn('Test & fetch fingerprint').click()
  await waitText('SHA256:', 20000)
  check('SFTP: probe a întors amprenta SHA256', await hasText('SHA256:'))
  check('SFTP: indicator host-key pinuit', await hasText('Host key pinned'))

  await fLabel('Encryption passphrase for uploaded archives').fill(PASSPHRASE)
  check('SFTP: Save activat după confirmarea amprentei', await saveBtn.isEnabled())
  await saveBtn.click()
  await waitText('Configuration saved\\.')
  check('SFTP: configurare salvată', true)
  await waitText(`Connected:\\s*backup@${SFTP_HOST}`, 10000)
  check(`SFTP: status „Connected: backup@${SFTP_HOST}"`, true)

  await fBtn('Upload now').click()
  await waitText('Backup uploaded', 30000)
  check('SFTP: „Upload now" a raportat succes', true)

  // ── FTPS: completează + CA self-signed → save → upload ──
  await page.getByRole('button', { name: 'FTPS', exact: true }).click()
  await fLabel('Host (e.g. backup.example.com)').fill(FTPS_HOST)
  await fLabel('Username').fill('backup')
  await fLabel('Remote path (e.g. /backups/webterm)').fill('backups')
  await fLabel('Password').fill('backup-pass-eval')
  if (CA_PEM) await fLabel('CA / certificate PEM (optional, for self-signed servers)').fill(CA_PEM)
  await fLabel('Encryption passphrase for uploaded archives').fill(PASSPHRASE)
  await fLabel('Account password (confirm)').fill(PASSWORD)
  await fBtn('Save configuration').click()
  await waitText('Configuration saved\\.')
  check('FTPS: configurare salvată', true)
  await waitText(`Connected:\\s*backup@${FTPS_HOST}`, 10000)
  check(`FTPS: status „Connected: backup@${FTPS_HOST}"`, true)

  await fBtn('Upload now').click()
  await waitText('Backup uploaded', 30000)
  check('FTPS: „Upload now" a raportat succes', true)

  check('nicio eroare de pagină (React/JS)', pageErrors.length === 0)
  if (pageErrors.length) console.error('pageerrors:', pageErrors)
} finally {
  await browser.close()
}

const failed = results.filter(([, ok]) => !ok)
console.log(`\n${results.length - failed.length}/${results.length} treceri`)
process.exit(failed.length ? 1 : 0)
