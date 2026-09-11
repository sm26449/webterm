/* E2E Playwright: round-trip de BACKUP → RESTORE. Dovedeşte că restore chiar înlocuieşte starea
   instanţei cu cea din arhivă:

     1. cont + host „marker-before-backup"            (intră în snapshot)
     2. descarcă backup criptat (.wtbk) prin API
     3. adaugă host „added-after-backup"              (mutaţie DUPĂ snapshot)
     4. restore prin UI: alege fişierul, passphrase + re-auth, „Restore and restart"
        (backend-ul validează, apoi os._exit → containerul reporneşte şi aplică la boot)
     5. după repornire: re-login şi verifică — marker-before-backup PREZENT,
        added-after-backup ABSENT (starea = snapshotul, nu ce era live înainte de restore).

   Instanţa trebuie pornită cu `--restart unless-stopped` ca să revină după os._exit.
   Nu atinge prod.

     node e2e-restore.mjs http://127.0.0.1:8791 */
import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8791'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'e2e-restore-token'
const EMAIL = 'e2e-restore@example.com'
const PASSWORD = 'parola-e2e-restore-123456'
const BK_PASS = 'restore-passphrase-eval-123'

const results = []
const check = (name, cond) => { results.push([name, !!cond]); console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`) }
const fail = (msg) => { console.error(`EROARE: ${msg}`); process.exit(1) }

async function api(path, { method = 'GET', cookie = '', body } = {}) {
  const h = { 'Content-Type': 'application/json', Origin: BASE }
  if (cookie) h.Cookie = cookie
  return fetch(`${BASE}${path}`, { method, headers: h, body: body ? JSON.stringify(body) : undefined })
}
const hostNames = async (cookie) => (await (await api('/api/hosts', { cookie })).json()).map((h) => h.name)

// 1. cont + host marker (în snapshot) -----------------------------------------
const su = await api('/api/setup', { method: 'POST', body: { email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN } })
if (!su.ok) fail(`setup: ${su.status} ${await su.text()}`)
let cookie = (su.headers.get('set-cookie') ?? '').split(';')[0]
check('setup cont', !!cookie)

const mk = await api('/api/hosts', { method: 'POST', cookie, body: { name: 'marker-before-backup', note: '', connection_type: 'agent', require_2fa: false } })
check('host „marker-before-backup" creat', mk.ok)

// 2. descarcă backup criptat --------------------------------------------------
const dl = await fetch(`${BASE}/api/backup/download`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
  body: JSON.stringify({ passphrase: BK_PASS, include_transcripts: false, current_password: PASSWORD }),
})
if (!dl.ok) fail(`download: ${dl.status} ${await dl.text()}`)
const buf = Buffer.from(await dl.arrayBuffer())
writeFileSync('/tmp/restore-backup.wtbk', buf)
check('backup descărcat şi criptat (magic WTBK1)', buf.length > 0 && buf.subarray(0, 5).toString() === 'WTBK1')

// 3. mutaţie DUPĂ snapshot ----------------------------------------------------
const af = await api('/api/hosts', { method: 'POST', cookie, body: { name: 'added-after-backup', note: '', connection_type: 'agent', require_2fa: false } })
check('host „added-after-backup" creat (post-snapshot)', af.ok)
const before = await hostNames(cookie)
check('înainte de restore: ambele hosturi există',
  before.includes('marker-before-backup') && before.includes('added-after-backup'))

// 4. restore prin UI ----------------------------------------------------------
const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'en-US' })
  page.on('dialog', (d) => d.accept())     // confirm() „RESTORE replaces ALL current data…"
  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('button[aria-label="Settings"]', { timeout: 15000 })
  await page.click('button[aria-label="Settings"]')
  await page.getByRole('button', { name: 'Backup', exact: true }).click()
  await page.setInputFiles('input[type=file]', '/tmp/restore-backup.wtbk')
  await page.locator('[aria-label="Backup passphrase"]').fill(BK_PASS)
  await page.getByPlaceholder('your account password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Restore and restart' }).click()
  await page.waitForSelector('text=Backup validated', { timeout: 20000 })
  check('UI restore: „Backup validated" (repornire iniţiată)', true)
} finally {
  await browser.close()
}

// 5. aşteaptă repornirea + aplicarea restore ----------------------------------
let back = false
for (let i = 0; i < 45; i++) {
  await new Promise((r) => setTimeout(r, 2000))
  try { if ((await fetch(`${BASE}/`, { signal: AbortSignal.timeout(3000) })).ok) { back = true; break } } catch { /* încă repornește */ }
}
check('app a revenit după repornire', back)

// 6. re-login + starea === snapshot -------------------------------------------
const lg = await api('/api/login', { method: 'POST', body: { email: EMAIL, password: PASSWORD } })
if (!lg.ok) fail(`re-login după restore: ${lg.status} ${await lg.text()}`)
cookie = (lg.headers.get('set-cookie') ?? '').split(';')[0]
check('re-login după restore', !!cookie)

const after = await hostNames(cookie)
check('restore: „marker-before-backup" PREZENT (snapshotul a revenit)', after.includes('marker-before-backup'))
check('restore: „added-after-backup" ABSENT (mutaţia post-snapshot a dispărut)', !after.includes('added-after-backup'))

const failed = results.filter(([, ok]) => !ok)
console.log(`\n${results.length - failed.length}/${results.length} treceri`)
process.exit(failed.length ? 1 : 0)
