// Smoke test de boot (gardul care lipsea când v1.0.11 a livrat un ecran alb):
// deschide UI-ul într-un Chromium headless și verifică că aplicația chiar
// ajunge la un ecran funcțional — window.__WT_BOOTED, setat de <BootReady/>
// pe login/app — fără nicio eroare JS neprinsă. Rulează în CI înaintea
// publicării imaginii; o imagine care nu trece nu ajunge în ghcr.
//
//   node scripts/smoke-boot.mjs [http://127.0.0.1:8000]
//
// Cere pachetul `playwright` cu Chromium instalat (vezi pasul din
// .github/workflows/docker-publish.yml).
import { chromium } from 'playwright'

const url = process.argv[2] ?? 'http://127.0.0.1:8000'
const browser = await chromium.launch()
const page = await browser.newPage({ locale: 'en-US' })   // UI i18n → fixăm limba RO în test

const pageErrors = []
page.on('pageerror', (err) => pageErrors.push(err.message))
// console.error singur nu pică testul (poate fi zgomot benign), dar îl vedem în log
page.on('console', (msg) => {
  if (msg.type() === 'error') console.warn('[console.error]', msg.text())
})

let failed = null
try {
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 })
  // atribut DOM, nu waitForFunction: CSP-ul aplicației (script-src fără
  // unsafe-eval) blochează predicatele eval-uite de Playwright — și NU vrem
  // bypassCSP, ca smoke test-ul să prindă și regresiile de CSP
  await page.waitForSelector('html[data-wt-booted]', { state: 'attached', timeout: 30_000 })
} catch (err) {
  failed = `UI-ul nu a ajuns la boot (data-wt-booted): ${err.message}`
}
if (!failed && pageErrors.length > 0) {
  failed = 'erori JS neprinse în timpul boot-ului'
}

if (failed) {
  console.error(`✗ SMOKE TEST EȘUAT: ${failed}`)
  if (pageErrors.length > 0) console.error('Erori JS:\n' + pageErrors.join('\n'))
  await page.screenshot({ path: 'smoke-fail.png', fullPage: true }).catch(() => {})
  await browser.close()
  process.exit(1)
}

console.log('✓ smoke boot OK — UI-ul pornește fără erori JS')
await browser.close()
