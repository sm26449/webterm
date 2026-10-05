/* Captură completă a suprafeței UI + audit de accesibilitate (axe-core) + teste de TASTATURĂ.

   Rulează DUPĂ `scripts/e2e-session.mjs`, pe acelaşi stack: are nevoie de contul şi de
   hostul create acolo (hostul `A11Y_HOST`, implicit `ci-local`, cu agent ONLINE — sesiunea,
   tab-urile Files/Forwards/Services/Docker/Toolbox şi toast-ul de eroare se obţin pe el).
   Cel mai simplu: `scripts/ci-local.sh e2e a11y`.

   Cere `@axe-core/playwright` pe lângă `playwright` — vezi scripts/ci-local.sh.
   Screenshot-uri în /tmp/webterm-review.

   P3 (auditul 2026-10-04, §8): tag-urile includ `wcag22aa` (target-size) şi `best-practice`;
   pe lângă pragul serious/critical, ORICE `target-size` sau `color-contrast` blochează; +15
   suprafeţe pe temă (pagina hostului online/offline cu toate tab-urile, Toolbox, Settings × 7,
   FleetRun, Add host × 3 formulare, `?`, paleta, ConfirmModal, toast de eroare, Monaco cu
   WT_AGENT=1) — toate în AMBELE teme (`wt_theme`: `dark` = Midnight, `macos` = Aurora/light;
   theme.ts scrie valoarea în `data-theme`); plus teste de tastatură (ordinea Tab, Escape +
   restaurarea focusului, ciclul Tab în ConfirmModal, paleta cu săgeţi+Enter, reordonarea
   tab-urilor cu Alt+Shift+←/→). */
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
// hostul cu agent online (creat de e2e-session.mjs); pe el se deschid sesiunile şi tab-urile
// care cer agent. Scriptul îşi creează singur un host de agent OFFLINE (`a11y-offline`) pentru
// pagina de host fără agent şi pentru ConfirmModal-ul de ştergere.
const HOST = process.env.A11Y_HOST ?? 'ci-local'
const OFFLINE_HOST = 'a11y-offline'
// Editorul Monaco cere un fişier real pe un agent online; CI-ul GitHub nu setează (încă)
// variabila, deci pasul e sărit VIZIBIL (linie SKIP), nu tăcut.
const HAS_AGENT = process.env.WT_AGENT === '1'
const OUT = '/tmp/webterm-review'
const a11y = []
const skipped = []
const checks = []
// Reguli care blochează indiferent de impactul raportat de axe: sunt primele două puncte ale
// auditului (ţinte < 24 px, contrast pe tema Aurora) şi NU vrem să le pierdem într-un total.
const BLOCKING_RULES = ['target-size', 'color-contrast']
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']

// Câte scanări TREBUIE să iasă dintr-o rulare completă. Numărul e o gardă: dacă o suprafaţă
// nu se deschide (selector schimbat), scanarea nu mai rulează şi poarta trebuie să CADĂ, nu să
// raporteze „0 violări" pentru că n-a scanat nimic.
// Pe temă (× 2 teme): login, dashboard, sesiune, host online × (Overview, Sessions, Files,
// Forwards, Services, Docker, Toolbox/Connections, Toolbox/SSH keys) = 8, host offline ×
// (Overview, Sessions) = 2, toast de eroare, Settings × 7, file browser, Status, Add host × 3,
// FleetRun, `?`, walkthrough, paleta, ConfirmModal = 31 (+ Monaco cu WT_AGENT=1). Mobil: sesiune dark + light.
const PER_THEME = 31 + (HAS_AGENT ? 1 : 0)
const EXPECTED_SCANS = 2 * PER_THEME + 2

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
    try { await page?.unrouteAll({ behavior: 'ignoreErrors' }) } catch { /* ignorăm */ }
  }
}

/** Verificare de comportament (tastatură): tipăreşte PASS/FAIL ca scripturile e2e.
    `expected: true` = ştim că lipseşte încă (ex. o scurtătură în lucru); se tipăreşte
    EXPECTED-FAIL şi NU blochează poarta — dar rămâne vizibil în log, ca să nu uităm de el. */
function check(name, cond, opts = {}) {
  const ok = !!cond
  checks.push({ name, ok, expected: !!opts.expected })
  const tag = ok ? 'PASS' : opts.expected ? 'EXPECTED-FAIL' : 'FAIL'
  console.log(`  ${tag} ${name}${!ok && opts.note ? ` — ${opts.note}` : ''}`)
}

async function scan(page, label) {
  try {
    const r = await new AxeBuilder({ page }).withTags(TAGS).analyze()
    const serious = r.violations.filter((v) => ['serious', 'critical'].includes(v.impact))
    const named = r.violations.filter((v) => BLOCKING_RULES.includes(v.id))
    const moderate = r.violations.filter((v) => ['moderate', 'minor'].includes(v.impact))
    const shown = [...new Set([...serious, ...named])]
    a11y.push({
      label, violations: r.violations.length, serious: serious.length, moderate: moderate.length,
      named: named.map((v) => `${v.id}(${v.nodes.length})`),
      top: shown.slice(0, 8).map((v) => `${v.impact}: ${v.id} (${v.nodes.length}) — ${v.help} @ ${v.nodes.slice(0, 2).map((n) => n.target.join(' ')).join(' | ')}`),
    })
  } catch (e) {
    a11y.push({ label, error: String(e).slice(0, 80) })
  }
}

/** fetch din pagină (cookie-ul de sesiune vine singur; api.ts nu pune antete speciale) */
const api = (page, path, init = {}) => page.evaluate(async ([p, i]) => {
  const r = await fetch(p, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, ...i })
  let body = null
  try { body = await r.json() } catch { /* fără corp */ }
  return { ok: r.ok, status: r.status, body }
}, [path, init])

/** descriptor scurt al elementului focusat — pentru testele de ordine Tab / restaurare */
const focused = (page) => page.evaluate(() => {
  const el = document.activeElement
  if (!el || el === document.body) return { tag: 'body', zone: 'body' }
  const zone =
    el.matches('input[aria-label="Search hosts, sessions or history"]') ? 'search'
    : el.closest('nav[aria-label="Open sessions"]') ? 'tabbar'
    : el.closest('.xterm') ? 'terminal'
    : el.closest('.wt-statusbar') ? 'statusbar'
    : el.closest('.wt-sidebar') && el.closest('.group') ? 'hostlist'
    : el.closest('.wt-sidebar') ? 'sidebar'
    : el.closest('[role=dialog],[role=alertdialog]') ? 'dialog'
    : 'main'
  return {
    tag: el.tagName.toLowerCase(), zone,
    label: el.getAttribute('aria-label') || el.getAttribute('title') || (el.textContent || '').trim().slice(0, 40),
  }
})

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
/** meniul ⋯ al UNUI host anume din sidebar (rândul = cel mai adânc `.group` care conţine numele) */
const hostMenu = (page, name) =>
  page.locator('.wt-sidebar .group', { hasText: name }).last().locator('button[title="Host actions"]')
async function openSession(page) {
  await hostMenu(page, HOST).click()
  await page.click('button[title="New session"]')
  await page.waitForSelector('.xterm-screen', { timeout: 10000 })
  await page.waitForTimeout(1500)
}
async function openHostPage(page, name) {
  const id = hostIds[name]
  if (!id) throw new Error(`hostul ${name} nu există în /api/hosts`)
  await page.evaluate((h) => { window.location.hash = `/h/${h}` }, id)
  await page.waitForSelector('nav[aria-label="Host sections"]', { timeout: 8000 })
  await page.waitForTimeout(500)
}
async function hostTab(page, label) {
  await page.locator('nav[aria-label="Host sections"] button', { hasText: label }).first().click()
  await page.waitForTimeout(900)
}
async function openSettings(page) {
  await page.click('button[aria-label="Settings"]')
  await page.waitForSelector('[role=dialog][aria-modal="true"]')
}
async function settingsTab(page, label) {
  await page.locator('nav[aria-label="Settings categories"] button', { hasText: label }).first().click()
  await page.waitForTimeout(600)
}
/** Escape închide dialogul deschis şi focusul se întoarce pe deschizător (useFocusTrap). */
async function escapeRestores(page, openerSel, what) {
  const dlg = page.locator('[role=dialog][aria-modal="true"], [role=alertdialog][aria-modal="true"]').last()
  const wasOpen = await dlg.isVisible().catch(() => false)
  await page.keyboard.press('Escape')
  await page.waitForTimeout(400)
  const stillOpen = await dlg.isVisible().catch(() => false)
  const back = openerSel
    ? await page.evaluate((s) => document.activeElement === document.querySelector(s), openerSel)
    : await page.evaluate(() => document.activeElement !== document.body)
  check(`Escape închide ${what} şi focusul revine pe deschizător`, wasOpen && !stillOpen && back,
    { note: `deschis=${wasOpen} rămas=${stillOpen} focus=${JSON.stringify(await focused(page))}` })
}

const hostIds = {}
async function loadHosts(page) {
  const r = await api(page, '/api/hosts')
  for (const h of r.body ?? []) hostIds[h.name] = h.id
}

try {
  // ---- DESKTOP, ambele teme ----
  for (const theme of ['macos', 'dark']) {
    console.log(`\n--- tema ${theme === 'macos' ? 'Aurora (light)' : 'Midnight (dark)'} ---`)
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, locale: 'en-US' })
    const page = await ctx.newPage()
    page.on('dialog', (d) => d.accept())
    // presetăm `wt_walkthrough_done`: walkthrough-ul de primă rulare s-ar deschide singur după
    // login şi ar acoperi dashboard-ul, derutând scanarea. Îl redeschidem explicit mai jos.
    await page.addInitScript(() => { try { for (const k of ['wt_walkthrough_done','wt_tip_addhost_agent','wt_tip_addhost_ssh','wt_tip_terminal_paste','wt_tip_toolbar']) localStorage.setItem(k, '1') } catch { /**/ } })

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

    // hostul offline de test (idempotent: dacă a rămas de la o rulare anterioară, îl refolosim)
    await step('host offline de test', async () => {
      await loadHosts(page)
      if (!hostIds[OFFLINE_HOST]) {
        const r = await api(page, '/api/hosts', { method: 'POST',
          body: JSON.stringify({ name: OFFLINE_HOST, note: '', connection_type: 'agent', require_2fa: false }) })
        if (!r.ok) throw new Error(`POST /api/hosts ${r.status}`)
        await loadHosts(page)
      }
      await page.waitForSelector(`.wt-sidebar button:has-text("${OFFLINE_HOST}")`, { timeout: 8000 })
    }, page)

    await step('deschide sesiune', async () => {
      await openSession(page)
      await page.keyboard.type('ls -la /etc | head -20\n')
      if (HAS_AGENT) await page.keyboard.type('printf "a11y\\n" > ~/a11y-monaco.txt\n')
      await page.waitForTimeout(1000)
    }, page)
    await page.screenshot({ path: `${OUT}/${theme}-03-session.png` })
    await scan(page, `${theme} session view`)

    // ── TASTATURĂ: ordinea Tab de la încărcarea paginii (sesiune deschisă) ──
    // Reîncărcăm pe ruta sesiunii ca focusul să pornească de pe <body>, apoi parcurgem cu Tab.
    // Ctrl+M = „tab focus mode" al terminalului (Tab iese din xterm în loc să ajungă în shell).
    await step('ordinea Tab', async () => {
      await page.reload()
      await page.waitForSelector('.xterm-screen', { timeout: 10000 })
      await page.waitForTimeout(800)
      // aplicaţia focusează terminalul activ la încărcare (corect pentru un terminal); testul
      // măsoară ordinea DOM de la începutul paginii. Un simplu `blur()` NU ajunge: Chromium
      // păstrează „punctul de pornire al navigării secvenţiale" pe ultimul element focusat, deci
      // Tab continua din terminal (→ bara de stare). Focusăm explicit <body> (tabindex temporar):
      // asta mută punctul de pornire la începutul documentului.
      await page.evaluate(() => {
        const b = document.body
        b.setAttribute('tabindex', '-1'); b.focus(); b.removeAttribute('tabindex')
      })
      await page.waitForTimeout(100)
      const seen = {}
      const trail = []
      for (let i = 0; i < 80; i++) {
        await page.keyboard.press('Tab')
        const f = await focused(page)
        trail.push(f.zone)
        if (!(f.zone in seen)) seen[f.zone] = i
        if (f.zone === 'terminal' && !seen.escaped) {
          seen.escaped = i
          await page.keyboard.press('Control+m')   // tab focus mode: următorul Tab părăseşte terminalul
        }
        if (f.zone === 'statusbar') break
        if (f.zone === 'body' && i > 5) break      // am ieşit din pagină: oprim
      }
      const order = ['search', 'hostlist', 'tabbar', 'terminal']
      const idx = order.map((z) => seen[z])
      const ordered = idx.every((v, i) => v !== undefined && (i === 0 || v > idx[i - 1]))
      check(`Tab de la încărcare: căutare → listă hosturi → bara de taburi → terminal, în ordine (${idx.join(' < ')})`, ordered,
        { note: `traseu: ${trail.join(',')}` })
      // bara de stare are control focusabil doar când există comanda de attach (tmux pe host);
      // dacă nu există, nu e o regresie de tastatură — spunem şi mergem mai departe
      const sbHasFocusable = await page.locator('.wt-statusbar button, .wt-statusbar a[href], .wt-statusbar [tabindex="0"]').count()
      if (sbHasFocusable) check('Tab după terminal (Ctrl+M) ajunge în bara de stare', seen.statusbar !== undefined && seen.statusbar > seen.terminal)
      else console.log('  SKIP bara de stare nu are control focusabil în acest context (fără comanda de attach)')
    }, page)

    // toolbar bars: note + search open
    await step('bare de unelte', async () => {
      await page.locator('button[title*="Note"]').first().click()
      await page.locator('button[title*="scrollback"], button[title*="auth"]').first().click()
      await page.screenshot({ path: `${OUT}/${theme}-04-bars.png` })
      await page.locator('button[title*="Note"]').first().click()
    }, page)

    // ── TASTATURĂ: reordonarea tab-urilor cu Alt+Shift+←/→ (a doua sesiune e necesară) ──
    await step('reordonare taburi din tastatură', async () => {
      await openSession(page)
      const tabs = page.locator('nav[aria-label="Open sessions"] button[data-tab]')
      const before = await tabs.allInnerTexts()
      if (before.length < 2) throw new Error(`doar ${before.length} taburi deschise`)
      await tabs.last().focus()
      await page.keyboard.press('Alt+Shift+ArrowLeft')
      await page.waitForTimeout(300)
      const after = await tabs.allInnerTexts()
      // scurtătura e în lucru (auditul 1.1): până apare, raportăm EXPECTED-FAIL, nu blocăm
      check('Alt+Shift+← pe tabul focusat îl mută cu o poziţie la stânga',
        after.length === before.length && after[after.length - 2] === before[before.length - 1],
        { expected: true, note: `înainte=${JSON.stringify(before)} după=${JSON.stringify(after)}` })
      if (after[after.length - 2] === before[before.length - 1]) {
        await page.keyboard.press('Alt+Shift+ArrowRight')     // revenim la ordinea iniţială
        await page.waitForTimeout(200)
      }
    }, page)

    // ── pagina hostului ONLINE: Overview, Sessions, apoi tab-urile care cer agent ──
    await step('pagina hostului (online)', async () => {
      await openHostPage(page, HOST)
      await page.screenshot({ path: `${OUT}/${theme}-09-host-overview.png` })
      await scan(page, `${theme} host page: overview`)
      await hostTab(page, 'Sessions')
      await scan(page, `${theme} host page: sessions`)
    }, page)
    for (const [label, wait] of [['Files', 'button[title="New file"]'], ['Forwards', null], ['Services', null], ['Docker', null]]) {
      await step(`tab ${label}`, async () => {
        await hostTab(page, label)
        if (wait) await page.waitForSelector(wait, { timeout: 8000 })
        await page.screenshot({ path: `${OUT}/${theme}-10-host-${label.toLowerCase()}.png` })
        await scan(page, `${theme} host page: ${label.toLowerCase()} panel`)
      }, page)
    }
    await step('tab Toolbox', async () => {
      // tab-ul care găzduieşte ToolboxPanel (Connections/SSH keys/Library/History); eticheta lui
      // e în tranziţie pe ramura asta (Toolbox ↔ Databases), acceptăm ambele
      await hostTab(page, /^(Toolbox|Databases)/)
      await page.waitForSelector('aside[aria-label="Toolbox"]', { timeout: 8000 })
      await page.locator('aside[aria-label="Toolbox"] button[aria-pressed]', { hasText: 'Connections' }).click()
      await page.waitForTimeout(400)
      await scan(page, `${theme} toolbox: connections`)
      await page.locator('aside[aria-label="Toolbox"] button[aria-pressed]', { hasText: 'SSH keys' }).click()
      await page.waitForTimeout(400)
      await page.screenshot({ path: `${OUT}/${theme}-11-toolbox.png` })
      await scan(page, `${theme} toolbox: ssh keys`)
    }, page)

    // ── editorul Monaco (doar cu agent declarat: WT_AGENT=1) ──
    if (HAS_AGENT) {
      await step('editor Monaco', async () => {
        await hostTab(page, 'Files')
        await page.waitForSelector('button[title="New file"]', { timeout: 8000 })
        const row = page.locator('button[title="Edit"]').first()
        await row.waitFor({ state: 'attached', timeout: 8000 })
        await row.dispatchEvent('click')          // butonul e display:none până la hover (auditul 1.4)
        await page.waitForSelector('.monaco-editor', { timeout: 15000 })
        await page.waitForTimeout(1200)
        await page.screenshot({ path: `${OUT}/${theme}-12-monaco.png` })
        await scan(page, `${theme} file editor (monaco)`)
        await escapeRestores(page, null, 'editorul de fişiere')
      }, page)
    } else {
      console.log('  SKIP editor Monaco: cere un agent online — setează WT_AGENT=1 ca să fie scanat')
    }

    // ── toast de eroare: cerere eşuată (POST /api/hosts/*/sessions → 500) ──
    await step('toast de eroare', async () => {
      await hostTab(page, 'Overview')
      await page.route('**/api/hosts/*/sessions', (route) => route.request().method() === 'POST'
        ? route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ detail: 'a11y: simulated failure' }) })
        : route.continue())
      await page.locator('button:has-text("New session"):visible').first().click()
      await page.waitForSelector('[role=alert]', { timeout: 5000 })
      await page.screenshot({ path: `${OUT}/${theme}-13-toast.png` })
      await scan(page, `${theme} error toast`)
      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await page.locator('[role=alert] button').first().click().catch(() => {})
    }, page)

    // ── pagina hostului OFFLINE (fără agent: gauge-uri goale, CTA-uri dezactivate) ──
    await step('pagina hostului (offline)', async () => {
      await openHostPage(page, OFFLINE_HOST)
      await page.screenshot({ path: `${OUT}/${theme}-14-host-offline.png` })
      await scan(page, `${theme} host page offline: overview`)
      await hostTab(page, 'Sessions')
      await scan(page, `${theme} host page offline: sessions`)
    }, page)

    // ── Settings: TOATE tab-urile ──
    await step('setări', async () => {
      await openSettings(page)
      for (const tab of ['Account', 'Security', 'Audit', 'Appearance', 'Notifications', 'Backup', 'Preferences']) {
        await settingsTab(page, tab)
        await page.screenshot({ path: `${OUT}/${theme}-05-settings-${tab.toLowerCase()}.png` })
        await scan(page, `${theme} settings: ${tab.toLowerCase()}`)
      }
      await escapeRestores(page, 'button[aria-label="Settings"]', 'Settings')
    }, page)

    // file browser (overlay-ul din meniul ⋯, altă suprafaţă decât tab-ul Files al hostului)
    await step('manager de fişiere', async () => {
      await hostMenu(page, HOST).click()
      await page.locator('button[role="menuitem"]', { hasText: 'Files' }).first().click()
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
      await escapeRestores(page, 'button[aria-label="Status"]', 'Status')
    }, page)

    // add-host modal: formularul de agent, formularul SSH (host direct), „Many machines"
    await step('adaugă host', async () => {
      await page.click('button[aria-label="Add host"]')
      await page.waitForSelector('text=Add a host')
      await page.screenshot({ path: `${OUT}/${theme}-07-addhost.png` })
      await scan(page, `${theme} add host: agent form`)
      await page.getByRole('button', { name: 'SSH', exact: true }).click()
      await page.waitForTimeout(300)
      await page.screenshot({ path: `${OUT}/${theme}-07-addhost-ssh.png` })
      await scan(page, `${theme} add host: ssh form`)
      await page.getByRole('button', { name: 'Many machines', exact: true }).click()
      await page.waitForTimeout(300)
      await page.screenshot({ path: `${OUT}/${theme}-07-addhost-many.png` })
      await scan(page, `${theme} add host: many machines`)
      await escapeRestores(page, 'button[aria-label="Add host"]', 'Add host')
    }, page)

    // FleetRun
    await step('fleet run', async () => {
      await page.click('button[aria-label="Run across multiple hosts"]')
      await page.waitForSelector('[role=dialog][aria-label="Run across multiple hosts"]', { timeout: 8000 })
      await page.waitForTimeout(400)
      await page.screenshot({ path: `${OUT}/${theme}-15-fleetrun.png` })
      await scan(page, `${theme} fleet run modal`)
      await escapeRestores(page, 'button[aria-label="Run across multiple hosts"]', 'FleetRun')
    }, page)

    // `?` — ajutorul de scurtături (din afara unui câmp / terminal); focusul revine unde era
    await step('ajutor tastatură (?)', async () => {
      await page.focus('button[aria-label="Settings"]')
      await page.keyboard.press('?')
      await page.waitForSelector('[role=dialog][aria-label="Keyboard shortcuts"]', { timeout: 5000 })
      await page.screenshot({ path: `${OUT}/${theme}-16-help.png` })
      await scan(page, `${theme} keyboard help`)
      await escapeRestores(page, 'button[aria-label="Settings"]', 'ajutorul `?`')
    }, page)

    // walkthrough de bun venit (modal, ambele teme): redeschis din „?" → scanăm ţinte/contrast/keyboard
    await step('walkthrough de bun venit', async () => {
      await page.focus('button[aria-label="Settings"]')
      await page.keyboard.press('?')
      await page.waitForSelector('[role=dialog][aria-label="Keyboard shortcuts"]', { timeout: 5000 })
      await page.click('button:has-text("Replay the welcome walkthrough")')
      await page.waitForSelector('[data-testid="walkthrough"]', { timeout: 5000 })
      await page.waitForTimeout(300)
      await page.screenshot({ path: `${OUT}/${theme}-16b-walkthrough.png` })
      await scan(page, `${theme} walkthrough`)
      check('walkthrough: → avansează la tastatură', await (async () => {
        const before = await page.locator('[data-testid="walkthrough"] h2').textContent()
        await page.keyboard.press('ArrowRight')
        await page.waitForTimeout(250)
        const after = await page.locator('[data-testid="walkthrough"] h2').textContent()
        return before !== after
      })())
      await page.keyboard.press('Escape')   // = Skip for now (nu bifăm → nu schimbă starea)
      await page.waitForTimeout(300)
    }, page)

    // paleta de comenzi: scanare + operabilă cu săgeţi şi Enter
    await step('paleta de comenzi', async () => {
      await page.focus('button[aria-label="Settings"]')
      await page.keyboard.press('Control+k')
      await page.waitForSelector('[role=dialog][aria-label="Commands"]', { timeout: 5000 })
      await page.waitForTimeout(300)
      await page.screenshot({ path: `${OUT}/${theme}-17-palette.png` })
      await scan(page, `${theme} command palette`)
      check('paleta: câmpul de căutare primeşte focus la deschidere',
        await page.evaluate(() => document.activeElement?.getAttribute('aria-label') === 'Search commands'))
      const selIdx = () => page.evaluate(() => document.querySelector('[data-idx].bg-sky-500\\/15')?.getAttribute('data-idx') ?? null)
      await page.keyboard.press('ArrowDown'); await page.keyboard.press('ArrowDown')
      const down2 = await selIdx()
      await page.keyboard.press('ArrowUp')
      const up1 = await selIdx()
      check(`paleta: ↓↓ selectează al 3-lea rezultat, ↑ revine la al 2-lea (${down2} → ${up1})`, down2 === '2' && up1 === '1')
      await page.keyboard.type('Status')
      await page.waitForTimeout(300)
      for (let i = 0; i < 3; i++) await page.keyboard.press('ArrowUp')   // sigur pe primul rezultat
      await page.keyboard.press('Enter')
      await page.waitForSelector('text=/Gateway|Storage|Hosts/', { timeout: 8000 })
      const paletteGone = (await page.locator('[role=dialog][aria-label="Commands"]').count()) === 0
      check('paleta: Enter execută comanda selectată şi închide paleta', paletteGone)
      await page.keyboard.press('Escape')
      await page.waitForTimeout(300)
    }, page)

    // ConfirmModal: ştergerea hostului offline — scanăm cu dialogul deschis, apoi Tab ciclează
    // DOAR între butoanele lui, apoi Escape = anulare (hostul rămâne; îl ştergem prin API la final)
    await step('confirmare ştergere host', async () => {
      await hostMenu(page, OFFLINE_HOST).click()
      await page.locator('button[role="menuitem"]', { hasText: /Remove from WebTerm|Delete host/ }).first().click()
      await page.waitForSelector('[role=alertdialog][aria-modal="true"]', { timeout: 5000 })
      await page.waitForTimeout(300)
      await page.screenshot({ path: `${OUT}/${theme}-18-confirm.png` })
      await scan(page, `${theme} confirm modal (delete host)`)
      const start = await focused(page)
      check('ConfirmModal (danger): focusul iniţial e pe Anulează, nu pe acţiunea distructivă',
        start.tag === 'button' && /cancel/i.test(start.label), { note: JSON.stringify(start) })
      const visited = []
      for (let i = 0; i < 4; i++) {
        await page.keyboard.press('Tab')
        visited.push(await page.evaluate(() => {
          const el = document.activeElement
          return { inDialog: !!el?.closest('[role=alertdialog]'), tag: el?.tagName, label: (el?.textContent || '').trim() }
        }))
      }
      const onlyButtons = visited.every((v) => v.inDialog && v.tag === 'BUTTON')
      const distinct = new Set(visited.map((v) => v.label)).size
      check(`Tab în ConfirmModal ciclează doar între cele 2 butoane (${distinct} distincte, toate în dialog: ${onlyButtons})`,
        onlyButtons && distinct === 2, { note: JSON.stringify(visited) })
      await page.keyboard.press('Escape')
      await page.waitForTimeout(400)
      const closed = (await page.locator('[role=alertdialog]').count()) === 0
      const f = await focused(page)
      check('Escape anulează ConfirmModal şi focusul rămâne în sidebar (pe rândul hostului)',
        closed && (f.zone === 'hostlist' || f.zone === 'sidebar'), { note: JSON.stringify(f) })
      const still = await api(page, '/api/hosts')
      check('Escape = anulare: hostul NU a fost şters', (still.body ?? []).some((h) => h.name === OFFLINE_HOST))
    }, page)

    await ctx.close()
  }

  // ---- MOBIL (iPhone): sesiune pe tema dark, apoi aceeaşi sesiune pe Aurora ----
  const mctx = await browser.newContext({ ...devices['iPhone 13'], locale: 'en-US' })
  const m = await mctx.newPage()
  m.on('dialog', (d) => d.accept())
  // context NOU = localStorage gol → walkthrough-ul de primă rulare s-ar auto-deschide după login
  // şi ar intercepta click-urile din drawer-ul mobil. Îl presetăm, ca în contextele desktop.
  await m.addInitScript(() => { try { for (const k of ['wt_walkthrough_done','wt_tip_addhost_agent','wt_tip_addhost_ssh','wt_tip_terminal_paste','wt_tip_toolbar']) localStorage.setItem(k, '1') } catch { /**/ } })
  await m.goto(BASE)
  await m.evaluate(() => localStorage.setItem('wt_theme', 'dark'))
  await m.reload()
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
  await m.locator('.wt-sidebar .group', { hasText: HOST }).last().locator('button[title="Host actions"] >> visible=true').last().click()
  await m.locator('.wt-sidebar button[title="New session"] >> visible=true').last().click()
  await m.waitForSelector('.xterm-screen')
  await m.waitForTimeout(1500)
  await m.keyboard.type('uptime\n')
  await m.waitForTimeout(800)
  await m.screenshot({ path: `${OUT}/m-04-session.png` })
  await scan(m, 'mobile session')
  // aceeaşi sesiune (ruta rămâne în hash) pe tema Aurora
  await m.evaluate(() => localStorage.setItem('wt_theme', 'macos'))
  await m.reload()
  await m.waitForSelector('.xterm-screen', { timeout: 10000 })
  await m.waitForTimeout(1200)
  await m.screenshot({ path: `${OUT}/m-05-session-light.png` })
  await scan(m, 'mobile session (light)')
  await mctx.close()
} finally {
  // curăţenie: hostul offline de test, ca următoarele porţi (mobile, fs) să vadă flota ca înainte
  try {
    if (hostIds[OFFLINE_HOST]) {
      const ctx = await browser.newContext({ locale: 'en-US' })
      const p = await ctx.newPage()
      await login(p)
      await api(p, `/api/hosts/${hostIds[OFFLINE_HOST]}`, { method: 'DELETE' })
      await ctx.close()
    }
  } catch { /* best-effort */ }
  await browser.close()
}

console.log('\n=== ACCESIBILITATE (axe-core, WCAG 2.2 AA + best-practice) ===')
for (const r of a11y) {
  if (r.error) { console.log(`  ${r.label}: EROARE ${r.error}`); continue }
  const named = r.named.length ? `, blocante: ${r.named.join(' ')}` : ''
  console.log(`  ${r.label}: ${r.violations} violări (${r.serious} serioase, ${r.moderate} moderate/minore${named})`)
  for (const t of r.top) console.log(`     - ${t}`)
}
if (skipped.length) {
  console.log('\n=== PAŞI SĂRIŢI (selectoare derapate — reparaţi-i, altfel suprafaţa nu e scanată) ===')
  for (const x of skipped) console.log('  -', x)
}
const serious = a11y.reduce((n, r) => n + (r.serious ?? 0), 0)
const moderate = a11y.reduce((n, r) => n + (r.moderate ?? 0), 0)
const named = a11y.reduce((n, r) => n + (r.named?.length ?? 0), 0)
const total = a11y.reduce((n, r) => n + (r.violations ?? 0), 0)
const failedChecks = checks.filter((c) => !c.ok && !c.expected)
const expectedFails = checks.filter((c) => !c.ok && c.expected)
console.log(`\nTOTAL: ${total} violări în ${a11y.length} scanări, din care ${serious} serioase/critice, ` +
  `${moderate} moderate/minore (trend, neblocante), ${named} pe regulile blocante (${BLOCKING_RULES.join(', ')})`)
console.log(`TASTATURĂ: ${checks.length - failedChecks.length - expectedFails.length}/${checks.length} verificări trecute` +
  (expectedFails.length ? `, ${expectedFails.length} eşec(uri) aşteptat(e): ${expectedFails.map((c) => c.name).join('; ')}` : ''))
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
  // target-size şi color-contrast blochează la ORICE impact — sunt primele puncte ale auditului
  if (named > 0) reasons.push(`${named} violări pe regulile blocante (${BLOCKING_RULES.join(', ')})`)
  // O scanare care a crăpat contribuia cu `serious ?? 0` = 0 la total, deci o eroare axe
  // TRECEA poarta. La fel şi paşii săriţi: se tipăreau şi atât.
  if (errored.length) reasons.push(`${errored.length} scanări axe au eşuat (${errored.map((r) => r.label).join(', ')})`)
  if (skipped.length) reasons.push(`${skipped.length} paşi săriţi — suprafaţa nu a fost scanată integral`)
  if (a11y.length < EXPECTED_SCANS) reasons.push(`doar ${a11y.length} scanări din ${EXPECTED_SCANS} aşteptate`)
  if (failedChecks.length) reasons.push(`${failedChecks.length} verificări de tastatură picate: ${failedChecks.map((c) => c.name).join('; ')}`)
  if (reasons.length) {
    for (const r of reasons) console.error(`EŞEC: ${r}`)
    process.exit(1)
  }
}
