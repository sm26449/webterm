/* E2E în CI: pornește un agent REAL în containerul de smoke, apoi conduce
   aplicația prin Playwright și verifică fluxurile critice de sesiune:
   - login + host online + sesiune nouă + output la comandă tastată
   - comutarea de tab-uri NU lasă panoul activ gol (incidentul v1.0.15)
   - un tab pauzat (fundal) se re-sincronizează la revenire și fluxul curge
   Rulează de lângă node_modules (rezolvarea ESM): cp în /tmp/wt-smoke întâi.

     node e2e-session.mjs http://127.0.0.1:8000 smoke

   Prereq: containerul <smoke> pornit cu WEBTERM_SETUP_TOKEN=$E2E_SETUP_TOKEN,
   WEBTERM_PUBLIC_URL=http://127.0.0.1:8000, WEBTERM_AGENT_INSECURE=1. */
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const CONTAINER = process.argv[3] ?? 'smoke'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'ci-e2e-token'
const EMAIL = 'e2e@example.com'
const PASSWORD = 'parola-e2e-123456'

const results = []
const check = (name, cond) => {
  results.push([name, !!cond])
  console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`)
}
/* Clipboard-ul se scrie ASINCRON faţă de click-ul care declanşează copierea. Aşteptările
   fixe (300-500 ms) au ţinut până când un runner încărcat a întârziat scrierea: citirea a
   prins conţinutul ANTERIOR, iar testul a picat pe un cod nemodificat — acelaşi commit a
   trecut pe run-ul de tag şi a picat pe cel de main. Aşteptăm activ până se potriveşte, cu
   plafon. Aserţiunea rămâne pe conţinut, deci un regres real tot pică; ce nu mai măsurăm e
   viteza runnerului. */
const clipboardUntil = async (page, pred, ms = 5000) => {
  const t0 = Date.now()
  for (;;) {
    const text = await page.evaluate(() => navigator.clipboard.readText())
    if (pred(text) || Date.now() - t0 > ms) return text
    await page.waitForTimeout(100)
  }
}
/* „Sesiune nouă" a fost mutat din rândul hostului în meniul ⋯ al acestuia, cu un separator
   după el. Testul nu mai poate da un singur click, deci deschide meniul întâi. Butonul de pe
   PAGINA hostului (HostOverview) a rămas neschimbat — acela n-are `title`, doar text, şi de
   aceea auditul mobil nu e afectat. */
const newSession = async (page) => {
  await page.click('button[title="Host actions"]')
  await page.click('button[title="New session"]')
}
/* Sub încărcare (runner CI ocupat) agentul de test poate pierde scurt conexiunea şi reveni.
   Verificările care cer agentul (upload cu pauză, fs/cwd) picau atunci cu „host offline" (409),
   fără legătură cu ce testează. Înainte de ele aşteptăm agentul online şi NOTĂM cât a lipsit:
   o deconectare care se repetă e un semnal real, pe care log-ul trebuie să-l arate. */
const waitAgentOnline = async (hostId, label, ms = 45000) => {
  const t0 = Date.now()
  let online = false
  while (Date.now() - t0 < ms) {
    try {
      const hs = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
      online = hs.some((h) => h.id === hostId && h.online)
    } catch { online = false }
    if (online) break
    await new Promise((r) => setTimeout(r, 500))
  }
  const waited = Date.now() - t0
  if (waited > 600 || !online) console.error(`  [diag] ${label}: agentul ${online ? 'a revenit după' : 'tot offline după'} ${Math.round(waited / 100) / 10}s`)
  return online
}
/* Oprirea / repornirea agentului din MIJLOCUL testului (overlay-ul „host offline"). Pe calea
   AGENT_TOKEN_FILE (CI + ci-local: Playwright rulează fără docker CLI) scriem comanda în
   `agent-ctl`, lângă fişierul de token; watcher-ul din afară o execută cu ACEEAŞI configuraţie
   (agent.json rămâne, deci acelaşi token) şi şterge fişierul = confirmare. Altfel, docker exec. */
const agentCtl = async (cmd) => {
  if (process.env.AGENT_TOKEN_FILE) {
    const { writeFileSync, existsSync } = await import('node:fs')
    const { dirname, join } = await import('node:path')
    const f = join(dirname(process.env.AGENT_TOKEN_FILE), 'agent-ctl')
    writeFileSync(f, cmd)
    const t0 = Date.now()
    while (existsSync(f) && Date.now() - t0 < 40000) await new Promise((r) => setTimeout(r, 300))
    return !existsSync(f)
  }
  try {
    if (cmd === 'stop') {
      execFileSync('docker', ['exec', '-e', 'HOME=/root', CONTAINER, 'python3', '/srv/webterm/agent/ptyd.py', 'stop'],
        { stdio: 'ignore', timeout: 25000 })
    } else {
      execFileSync('docker', ['exec', '-d', '-e', 'HOME=/root', CONTAINER, 'sh', '-c',
        'exec python3 /srv/webterm/agent/ptyd.py run >>/tmp/wt-agent.log 2>&1'])
    }
    return true
  } catch { return false }
}
const waitAgentOffline = async (hostId, ms = 30000) => {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) {
    try {
      const hs = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
      if (hs.some((h) => h.id === hostId && !h.online)) return true
    } catch { /* reîncearcă */ }
    await new Promise((r) => setTimeout(r, 500))
  }
  return false
}
const fail = (msg) => {
  console.error(`EROARE: ${msg}`)
  process.exit(1)
}

// -- 1. cont + host prin API (node fetch; cookie-ul se poartă manual) --------
// Setup SAU login: `E2E sessions` e sensibil la timing (agent real + tmux) şi CI îl re-rulează
// o dată la un flake. Pe a doua rulare contul există deja, iar `/api/setup` întoarce 409 —
// atunci ne LOGĂM în loc să eşuăm, ca retry-ul să nu fie blocat de „account already exists".
let cookie = ''
const setupRes = await fetch(`${BASE}/api/setup`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN }),
})
if (setupRes.ok) {
  cookie = (setupRes.headers.get('set-cookie') ?? '').split(';')[0]
  check('setup cont prin API', true)
} else {
  const loginRes = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  })
  if (!loginRes.ok) fail(`setup ${setupRes.status} + login ${loginRes.status} au eșuat`)
  cookie = (loginRes.headers.get('set-cookie') ?? '').split(';')[0]
  check('login pe contul existent (re-rulare după flake)', true)
}
if (!cookie) fail('nici setup, nici login n-au întors un cookie de sesiune')

const hostRes = await fetch(`${BASE}/api/hosts`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
  // eticheta `e2e-fleet`: o foloseşte pasul de comenzi salvate cu ţinte (consola de flotă)
  body: JSON.stringify({ name: 'ci-local', note: '', connection_type: 'agent', require_2fa: false, tags: 'e2e-fleet' }),
})
if (!hostRes.ok) fail(`crearea hostului a eșuat: ${hostRes.status}`)
const host = await hostRes.json()
const enroll = host.install_command?.match(/install\/([A-Za-z0-9_-]+)\.sh/)?.[1]
if (!enroll) fail(`nu am găsit tokenul de enroll în: ${host.install_command}`)

const installSh = await (await fetch(`${BASE}/install/${enroll}.sh`)).text()
const agentToken = installSh.match(/^TOKEN="([^"]+)"/m)?.[1]
if (!agentToken) fail('nu am găsit TOKEN în scriptul de instalare')
check('host creat + token de agent obținut', true)

// -- 2. agentul real, în interiorul containerului (pty backend, fără tmux) ---
const agentCfg = JSON.stringify({
  url: 'ws://127.0.0.1:8000/agent/ws',
  token: agentToken,
  insecure: true,
})
// AGENT_TOKEN_FILE: mediul rulează Playwright într-un container fără docker CLI
// (dev local) — atunci scriem tokenul pe disc și agentul e pornit din afară.
if (process.env.AGENT_TOKEN_FILE) {
  const { writeFileSync } = await import('node:fs')
  writeFileSync(process.env.AGENT_TOKEN_FILE, agentToken)
  const t0 = Date.now()
  while (Date.now() - t0 < 60000) {
    const hosts = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
    if (hosts.some((h) => h.id === host.id && h.online)) break   // AL NOSTRU, nu orice host online
    await new Promise((r) => setTimeout(r, 1000))
  }
  check('agent pornit extern și online', true)
} else {
  // O REÎNCERCARE (CI rulează scriptul de 2 ori la eşec) găsea agentul rulării anterioare încă viu.
  // Agentul are lock de instanţă unică, deci cel nou ieşea pe loc („already running"), iar cel vechi
  // rămânea legat de hostul VECHI: UI-ul mergea (alegea hostul vechi, online), dar apelurile API pe
  // `host.id` (fs/cwd, upload cu pauză) dădeau „host offline" 45 s. A doua încercare nu putea trece
  // niciodată — nu era flake. Oprim explicit agentul anterior înainte să-l pornim pe cel nou.
  try {
    execFileSync('docker', ['exec', '-e', 'HOME=/root', CONTAINER, 'python3', '/srv/webterm/agent/ptyd.py', 'stop'],
      { stdio: 'ignore', timeout: 25000 })
  } catch { /* nu rula niciunul */ }
  execFileSync('docker', ['exec', CONTAINER, 'sh', '-c',
    `mkdir -p /root/.webterm && printf '%s' '${agentCfg}' > /root/.webterm/agent.json`])
  // logul agentului într-un fişier din container: cu `exec -d` simplu se pierdea, iar „agentul a
  // fost offline 45 s" (adnotare CI, 3.5.2) nu spunea DE CE. CI-ul îl citeşte la eşec.
  execFileSync('docker', ['exec', '-d', '-e', 'HOME=/root', CONTAINER, 'sh', '-c',
    'exec python3 /srv/webterm/agent/ptyd.py run >>/tmp/wt-agent.log 2>&1'])
  check('agent pornit în container', true)
}
// Aşteptăm ca EXACT hostul acestei rulări să fie online — `.dot-live` de mai jos se mulţumea cu
// ORICE host online, deci un agent vechi rămas viu masca faptul că al nostru nu se conectase.
await waitAgentOnline(host.id, 'start', 60000)

// -- 3. UI prin Playwright ----------------------------------------------------
const pageErrors = []
const browser = await chromium.launch()
try {
  // locale RO: UI-ul are i18n (auto-detect din navigator.language); testele selectează după
  // textul RO de referință, deci fixăm limba ca headless-ul (default EN) să nu comute pe engleză.
  const page = await browser.newPage({ viewport: { width: 1440, height: 860 }, locale: 'en-US' })
  page.on('pageerror', (e) => pageErrors.push(String(e)))
  // violări CSP (worker blocat, script/stil refuzat) — apar doar în consolă, nu ca pageerror.
  // Le citeşte verificarea editorului Monaco (workerul trebuie să pornească sub CSP-ul real).
  const cspErrors = []
  page.on('console', (m) => {
    if (m.type() === 'error' && /Content Security Policy|Refused to (create|load|execute)/i.test(m.text())) cspErrors.push(m.text())
  })
  // Presetăm `wt_walkthrough_done`: altfel walkthrough-ul de primă rulare s-ar deschide singur
  // după login şi ar acoperi dashboard-ul, blocând restul fluxului. Redeschiderea manuală din
  // „?" o testăm explicit la final (acolo e DORIT să apară).
  await page.addInitScript(() => { try { for (const k of ['wt_walkthrough_done','wt_tip_addhost_agent','wt_tip_addhost_ssh','wt_tip_terminal_paste','wt_tip_toolbar']) localStorage.setItem(k, '1') } catch { /**/ } })

  const screenText = () =>
    page.evaluate(() => {
      // renderer-ul WebGL/Canvas nu ține textul în DOM → citim din BUFFERUL xterm
      // al sesiunii active (expus pe window.__wtTerms de SessionView)
      const terms = window.__wtTerms
      const sid = location.hash.replace('#/s/', '')
      const term = terms && terms.get(sid)
      if (!term) return ''
      const b = term.buffer.active
      let out = ''
      for (let i = 0; i < b.length; i++) out += (b.getLine(i)?.translateToString(true) ?? '') + '\n'
      return out
    })
  const waitScreen = async (needle, ms = 12000) => {
    const t0 = Date.now()
    while (Date.now() - t0 < ms) {
      if ((await screenText()).includes(needle)) return true
      await page.waitForTimeout(300)
    }
    return false
  }
  // Navigare la dashboard robustă: `el.click()` invocă direct handler-ul React,
  // deci nu depinde de coordonate/stabilitate/acoperiri (bug-ul de layout care a
  // acoperit „Acasă" e reparat, dar păstrăm navigarea deterministă în test).
  const goHome = async () => {
    await page.locator('button[aria-label="Home"]').evaluate((el) => el.click())
    await page.waitForSelector('[data-testid="dashboard"]', { timeout: 10000 })
  }

  await page.goto(BASE)
  await page.fill('input[type=email]', EMAIL)
  await page.fill('input[type=password]', PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"]', { timeout: 10000 })
  check('login în UI', true)

  await page.waitForSelector('.dot-live', { timeout: 30000 })
  check('host online (agentul s-a conectat)', true)

  // sesiunea A
  await newSession(page)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1500)
  const sidA = await page.evaluate(() => location.hash.replace('#/s/', ''))
  await page.keyboard.type('echo A_$((40+2))\n')
  check('sesiunea A: output la comandă', await waitScreen('A_42'))

  // renderer accelerat (WebGL/Canvas) activ — creează un <canvas>; renderer-ul DOM
  // folosește doar div-uri. Fără accelerare, TUI-urile grele (Claude Code) pierdeau
  // rânduri (chenarul input-ului dispărea).
  const renderer = await page.evaluate(() => {
    const xt = document.querySelector('.xterm')
    return xt?.querySelector('canvas') ? 'accelerat' : 'dom'
  })
  check('renderer accelerat activ (WebGL/Canvas, nu DOM)', renderer === 'accelerat', `renderer=${renderer}`)

  // A− de 2× nu trebuie să golească terminalul / să arunce erori. Cu WebGL,
  // schimbarea fontului lăsa ecranul gol → recreăm renderer-ul la noua dimensiune.
  const errBefore = pageErrors.length
  const aMinus = page.locator('button[title="Smaller font"]').last()
  await aMinus.click(); await aMinus.click()
  await page.waitForTimeout(600)
  check('A− ×2: conținutul rămâne (nu se golește)', (await screenText()).includes('A_42'))
  check('A− ×2: fără erori JS (recreare renderer ok)', pageErrors.length === errBefore)
  const aPlus = page.locator('button[title="Larger font"]').last()
  await aPlus.click(); await aPlus.click()   // restaurează fontul pt. restul testelor
  await page.waitForTimeout(400)

  // sesiunea B, cu flux continuu (ticker) — testează pauza + resync-ul.
  await goHome()
  await newSession(page)
  await page.waitForTimeout(1500)
  await page.keyboard.type('i=0; while true; do i=$((i+1)); echo TICK_$i; sleep 1; done\n')
  check('sesiunea B: ticker pornit', await waitScreen('TICK_2'))

  // comută pe A: panoul activ NU are voie să fie gol (regresia v1.0.15).
  // evaluate(el.click()): click determinist pe tab (nu depinde de coordonate);
  // waitScreen generos: la switch xterm-ul se poate recrea, iar re-sync-ul
  // scrollback-ului (care aduce A_42 înapoi) variază ca durată sub CI.
  const tabs = page.locator('button[data-tab]')
  await tabs.nth(0).evaluate((el) => el.click())
  check('tab switch: panoul A vizibil și cu conținut', await waitScreen('A_42', 15000))

  // B rulează în fundal (pauzat) 4s, apoi revenim: trebuie să fie la zi și viu
  await page.waitForTimeout(4000)
  await tabs.nth(1).evaluate((el) => el.click())
  check('tab switch înapoi: B re-sincronizat (ticks noi)', await waitScreen('TICK_5', 15000))
  const t1 = await screenText()
  await page.waitForTimeout(2500)
  const t2 = await screenText()
  check('fluxul lui B curge după resume', t1 !== t2)

  // ── Valul 2: scurtături, cheatsheet, teme, snippets ──
  // helper: „a apărut / a dispărut?" cu așteptare (fără el, verificarea rulează
  // înaintea re-randării React și pică nedeterminist — exact ce a prins CI-ul)
  const visible = (loc, ms = 5000) =>
    loc.waitFor({ state: 'visible', timeout: ms }).then(() => true).catch(() => false)
  const hidden = (loc, ms = 5000) =>
    loc.waitFor({ state: 'hidden', timeout: ms }).then(() => true).catch(() => false)
  // Polling mărginit pe o valoare citită din pagină: un singur read putea rula ÎNAINTE ca React să
  // re-randeze panoul sau ca listarea FS / cwd-ul (OSC 7) să se propage — cursa clasică de pe un
  // loopback rapid (+ runner încărcat). Re-citim până se potriveşte, cu plafon; aserţiunea de după
  // rămâne pe valoare, deci un regres real tot pică — ce nu mai măsurăm e viteza de randare.
  const pollValue = async (read, pred, ms = 10000) => {
    const t0 = Date.now()
    for (;;) {
      const v = await read()
      if (pred(v) || Date.now() - t0 > ms) return v
      await page.waitForTimeout(200)
    }
  }

  // Ctrl/Cmd+Shift+F deschide căutarea în scrollback
  const searchBox = page.locator('input[placeholder="Search…"]')
  await page.keyboard.press('Control+Shift+F')
  check('scurtătură: căutare în scrollback', await visible(searchBox))
  await page.keyboard.press('Escape')
  await hidden(searchBox, 2000)

  // „?" deschide cheatsheet-ul (nu în terminal — mai întâi scoatem focusul)
  await page.locator('button[aria-label="Home"]').focus()
  await page.keyboard.press('?')
  const help = page.locator('[role=dialog][aria-label="Keyboard shortcuts"]')
  check('overlay „?" cu scurtături', await visible(help))
  check('cheatsheet listează scurtături reale', (await help.textContent())?.includes('Close the tab'))
  await page.keyboard.press('Escape')
  // overlay-ul ARE scrim `fixed inset-0` — dacă rămâne deschis, blochează orice
  // click de mai jos; verificăm explicit că s-a închis (regresia prinsă în CI)
  check('overlay „?" se închide cu Escape', await hidden(help))

  // Alt+←/→ navighează între tab-uri
  await tabs.nth(0).click()
  await page.waitForTimeout(400)
  await page.keyboard.press('Alt+ArrowRight')
  await page.waitForTimeout(600)
  check('scurtătură: Alt+→ trece la tab-ul următor', await waitScreen('TICK_', 5000))

  // snippet parametrizat: creat prin API, rulat din paletă
  await page.evaluate(() =>
    fetch('/api/snippets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ title: 'Salut param', body: 'echo SNIP_{{nume}}' }),
    }))
  await page.keyboard.press('Control+Shift+K')
  await page.waitForTimeout(400)
  await page.keyboard.type('Salut param')
  await page.waitForTimeout(400)
  await page.keyboard.press('Enter')
  const dlg = page.locator('[role=dialog][aria-label*="Parameters"]')
  check('snippet cu {{parametri}} cere completare', await visible(dlg))
  await dlg.locator('input').first().fill('E2E')
  check('previzualizarea comenzii finale', (await dlg.textContent())?.includes('echo SNIP_E2E'))
  await dlg.locator('button:has-text("Insert")').click()
  await page.waitForTimeout(500)
  await page.keyboard.press('Enter')
  check('snippet parametrizat rulat în sesiune', await waitScreen('SNIP_E2E', 8000))

  // ── Valul 3: metrice, praguri, player de transcript ──
  // pragurile de alertă se salvează și se citesc înapoi
  const thr = await page.evaluate(async () => {
    await fetch('/api/settings/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ cpu: 85, mem: 80, disk: 75 }),
    })
    return (await fetch('/api/settings/alerts', { credentials: 'same-origin' })).json()
  })
  check('praguri de alertă salvate și citite', thr.cpu === 85 && thr.mem === 80 && thr.disk === 75)

  // Sparkline-ul apare pe dashboard după câteva poll-uri de metrice, iar acum agentul
  // rulează pe tmux (ca în producţie), deci pornirea sesiunilor e mai lentă decât pe pty:
  // 20s ajungeau uneori la limită şi testul cădea intermitent în CI, fără vreo regresie.
  // Aşteptăm mai mult ŞI reîmprospătăm o dată — poll-ul de dashboard e la câteva secunde.
  await goHome()
  const spark = page.locator('svg[role=img][aria-label^="CPU on"]').first()
  let sparkOk = await visible(spark, 30000)
  if (!sparkOk) {
    await page.reload({ waitUntil: 'domcontentloaded' })
    await page.waitForSelector('[data-testid="dashboard"]', { timeout: 15000 })
    sparkOk = await visible(spark, 30000)
  }
  check('sparkline CPU pe cardul de host', sparkOk)

  // ── Securitate (3.5.4): cardul de pe dashboard, inventarul de share-uri, „Revoke all" ──
  // Cardul se încarcă asincron (GET /api/security/summary) — aşteptăm rândul, nu doar secţiunea.
  const secCard = page.locator('[data-testid="security-card"]')
  const sharesRow = secCard.locator('li[data-check="shares"]')
  const secOk = await sharesRow.waitFor({ state: 'attached', timeout: 15000 }).then(() => true).catch(() => false)
  check('cardul Securitate pe dashboard, cu rândul „Share links"', secOk && (await sharesRow.count()) === 1)
  // un link de share pe o sesiune LIVE (A sau B), creat prin API din pagină (cookie-ul browserului)
  const shareSid = await page.evaluate(async () => {
    const ss = await (await fetch('/api/sessions', { credentials: 'same-origin' })).json()
    const live = ss.find((s) => s.state === 'live')
    if (!live) return null
    const r = await fetch(`/api/sessions/${live.id}/share`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify({ writable: false, expires_minutes: 30 }),
    })
    return r.ok ? live.id : null
  })
  // cardul e deschis singur când ceva cere atenţie (aici: 2FA-ul contului); dacă nu, îl deschidem
  const secToggle = secCard.locator('button[aria-expanded]').first()
  if ((await secToggle.getAttribute('aria-expanded')) === 'false') await secToggle.click()
  await sharesRow.locator('button').click()
  const sharesDlg = page.locator('[role=dialog][aria-labelledby="wt-shares-title"]')
  check('inventarul de share-uri arată linkul abia creat',
    !!shareSid && await visible(sharesDlg.locator(`li[data-share="${shareSid}"]`), 10000))
  // „Revoke all": confirmare de pericol, apoi parola CONTULUI (askSecret, mascat)
  await sharesDlg.locator('button:has-text("Revoke all")').click()
  await page.locator('[role=alertdialog]').locator('button:has-text("Revoke all")').click()
  const pwDlg = page.locator('[role=dialog][aria-label^="Your account password (revoking all"]')
  await visible(pwDlg)
  await pwDlg.locator('input').fill(PASSWORD)
  await pwDlg.locator('button[type=submit]').click()
  const emptyOk = await visible(sharesDlg.locator('[data-testid="shares-empty"]'), 10000)
  const left = await page.evaluate(async () =>
    (await (await fetch('/api/shares', { credentials: 'same-origin' })).json()).shares.length)
  check('„Revoke all" (cu parola) goleşte inventarul — UI şi API', emptyOk && left === 0)
  await page.keyboard.press('Escape')
  await hidden(sharesDlg, 3000)
  // rândul din card se reîmprospătează după revocare (semnal de la inventar, nu poll-ul de 60 s)
  const sharesStatus = await pollValue(() => sharesRow.getAttribute('data-status'), (v) => v === 'ok', 8000)
  check('cardul Securitate: rândul „Share links" revine la OK', sharesStatus === 'ok')

  // player de transcript pe o sesiune închisă: închidem sesiunea A și o redăm
  await page.evaluate((sid) =>
    fetch(`/api/sessions/${sid}/kill`, { method: 'POST', credentials: 'same-origin' }), sidA)
  await page.waitForTimeout(2500)
  await page.goto(`${BASE}#/s/${sidA}`)
  const playBtn = page.locator('button:has-text("play history")')
  check('buton „redă istoricul" pe sesiune închisă', await visible(playBtn, 15000))
  await playBtn.click()
  const player = page.locator('[role=dialog][aria-label^="Playing recording"]')
  check('player-ul de transcript se deschide', await visible(player))
  // Seek exact la momentul comenzii din înregistrare (îl aflăm din .cast).
  // NU la final: la închiderea sesiunii tmux trimite clear-screen, deci ultimul
  // cadru e legitim gol — redarea reproduce fidel ce s-a întâmplat.
  const tEcho = await page.evaluate(async (sid) => {
    const text = await (await fetch(`/api/sessions/${sid}/transcript?format=cast`, { credentials: 'same-origin' })).text()
    for (const line of text.split('\n')) {
      if (!line.startsWith('[')) continue
      const e = JSON.parse(line)
      if (typeof e[2] === 'string' && e[2].includes('A_42')) return e[0]
    }
    return null
  }, sidA)
  check('transcriptul .cast conține comanda', tEcho != null)
  // Seek + verificare pe o SCARĂ de momente, nu pe unul singur. Motivul e tmux: de când
  // E2E-ul rulează pe backend-ul de producţie, panoul e repictat asincron, iar „cadrul de
  // imediat după comandă" nu mai e un moment stabil — pe un runner cu alt timing, la +0.1s
  // ecranul poate fi deja redesenat şi linia dispărută. Verificarea rămâne la fel de tare
  // (player-ul chiar trebuie să redea comanda), dar nu mai depinde de o singură fereastră.
  const seekTo = async (t) => {
    await player.locator('input[type=range]').evaluate((el, v) => {
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set
      setter.call(el, String(v))
      el.dispatchEvent(new Event('input', { bubbles: true }))
    }, t)
    for (let i = 0; i < 8; i++) {          // scrierea în xterm e asincronă
      const txt = await player.locator('.xterm-rows').first().textContent()
      if (txt?.includes('A_42')) return true
      await page.waitForTimeout(300)
    }
    return false
  }
  let rendered = false
  for (const off of [0.1, 0.3, 0.05, 0.6, 1.0]) {
    if (await seekTo((tEcho ?? 0) + off)) { rendered = true; break }
  }
  // Rezervă: dacă niciun moment punctual nu prinde comanda, redăm efectiv de la început.
  // Afirmaţia rămâne aceeaşi („player-ul redă ce s-a înregistrat"), dar nu mai depinde
  // de nimerirea unui cadru — redarea trece prin toate evenimentele.
  if (!rendered) {
    await seekTo(0)
    await player.locator('button[aria-label="Play"]').click()
    for (let i = 0; i < 60; i++) {
      const txt = await player.locator('.xterm-rows').first().textContent()
      if (txt?.includes('A_42')) { rendered = true; break }
      await page.waitForTimeout(250)
    }
    if (!rendered) {
      const dump = (await player.locator('.xterm-rows').first().textContent() ?? '').slice(0, 300)
      console.log(`     [diag] tEcho=${tEcho} ecran="${dump.replace(/\s+/g, ' ')}"`)
    }
    await player.locator('button[aria-label="Pause"]').click().catch(() => {})
  }
  check('player-ul redă conținutul istoricului (seek)', rendered)
  // butonul de redare comută starea (▶ ⇄ ❚❚)
  await player.locator('button[aria-label="Play"]').click()
  check('redarea pornește', await visible(player.locator('button[aria-label="Pause"]'), 3000))
  await page.keyboard.press('Escape')
  check('player-ul se închide cu Escape', await hidden(player))

  // ── Plierea sidebarului ──
  // O funcţie de UI fără test se strică tăcut la prima refactorizare de layout. Ce contează
  // aici nu e că sidebarul dispare, ci că EXISTĂ cale de întoarcere: ☰ e ascuns pe desktop
  // exact cât timp sidebarul e vizibil, iar plierea fără buton de redeschidere ar fi o capcană.
  const sidebar = page.locator('.wt-sidebar').first()
  // `^=`: cu alerte necitite numele accesibil devine „Open host list — unread alerts: N" (3.5.15)
  const reopen  = page.locator('button[aria-label^="Open host list"]:visible').first()
  check('sidebarul e vizibil implicit', await visible(sidebar))
  check('☰ e ascuns cât timp sidebarul e vizibil', !(await reopen.isVisible().catch(() => false)))
  await page.click('button[title="Hide the host list"]')
  await page.waitForTimeout(400)
  check('plierea ascunde sidebarul', await hidden(sidebar))
  check('☰ apare când sidebarul e pliat', await visible(reopen))
  await reopen.click()
  await page.waitForTimeout(400)
  check('☰ readuce sidebarul', await visible(sidebar))

  // ── Valul 4: OSC 133 (comenzi ca obiecte) ──
  // sesiune nouă + activarea integrării shell din panoul de comenzi
  await goHome()
  await newSession(page)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1500)
  // stack-ul keep-alive ține montate și tab-urile ascunse → restrângem la panoul
  // VIZIBIL (altfel selectorul e ambiguu peste toate sesiunile deschise)
  const activePane = page.locator('div:not([aria-hidden="true"]) > .wt-window').last()
  await activePane.locator('button[title*="Commands —"], button[title*="Commands:"]').first().click()
  const cmdPanel = page.locator('aside[aria-label="Session commands"]').last()
  check('panoul de comenzi se deschide', await visible(cmdPanel))
  // Butonul cere confirmare: tastează o comandă într-un shell VIU, iar dacă terminalul nu
  // e la un prompt (editor, prompt de parolă) textul devine altceva. Playwright respinge
  // dialogurile implicit, deci le acceptăm explicit — ca un om care citeşte şi apasă OK.
  // De la 3.1.0 confirmarea e un ConfirmModal în aplicaţie (`role="alertdialog"`), nu
  // `window.confirm` — apăsăm butonul de confirmare (ultimul; Anulează stă primul).
  await cmdPanel.locator('button:has-text("Enable shell integration")').click()
  await page.locator('[role="alertdialog"]').last().locator('button').last().click({ timeout: 5000 })
  await page.waitForTimeout(3000)   // curl + source
  // tastele de mai jos trebuie să ajungă în SHELL: dăm click în terminal ca un om, nu ne bazăm
  // pe unde a lăsat focusul dialogul de confirmare (focus-trap-ul îl întoarce pe deschizător)
  await activePane.locator('.xterm-screen').click()
  await page.waitForTimeout(200)

  // două comenzi: una reușită, una eșuată → trebuie marcate cu exit code
  await page.keyboard.type('echo OSC_OK\n')
  await page.waitForTimeout(1200)
  // subshell: setează $? = 3 FĂRĂ să închidă sesiunea
  await page.keyboard.type('(exit 3)\n')
  await page.waitForTimeout(1500)
  const panelText = (await cmdPanel.textContent()) ?? ''
  check('comenzile apar în panou (OSC 133)', panelText.includes('echo OSC_OK'))
  check('exit code-ul comenzii eșuate e capturat', /exit\s*3/.test(panelText))

  // ── Faza 0 (Val 5): OSC 7 → cwd urmărește `cd`-ul, afișat în StatusBar ──
  // Testul cheie: secvența OSC 7 supraviețuiește wrapping-ului tmux DCS și
  // ajunge la handler-ul xterm din browser (fundația panoului de fișiere).
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cd /tmp\n')
  await page.waitForTimeout(1200)
  const cwdInd = activePane.locator('span[title="/tmp"]')
  check('cwd (OSC 7) apare în StatusBar după cd', (await cwdInd.count()) > 0)
  check('cwd afișat conține calea', ((await cwdInd.first().textContent().catch(() => '')) ?? '').includes('tmp'))
  // înapoi în home ca restul testelor să ruleze din locul obișnuit
  await page.keyboard.type('cd\n')
  await page.waitForTimeout(600)

  // „copiază output-ul" trebuie să dea EXACT output-ul comenzii — fără prompt și
  // fără linia de comandă. Regresie reală din v1.0.20: clipboardul primea și
  // prompturi, iar lipirea înapoi în shell EXECUTA acele linii.
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  const okCmd = cmdPanel.locator('div.group').filter({ hasText: 'echo OSC_OK' }).first()
  await okCmd.hover()
  await okCmd.getByRole('button', { name: 'output', exact: true }).click()
  const clip = await clipboardUntil(page, (c) => c.includes('OSC_OK'))
  check('clipboardul conține output-ul comenzii', clip.includes('OSC_OK'))
  const clipClean = !/[$#]\s*$/m.test(clip) && !clip.includes('echo OSC_OK')
  // la eşec, tipărim CE a ajuns în clipboard: verificarea a picat de două ori în CI cu
  // cauze diferite (prompt repictat vs. ecou), iar fără conţinut diagnosticul e ghicit
  if (!clipClean) console.log(`     [diag] clipboard=${JSON.stringify(clip).slice(0, 400)}`)
  check('clipboardul NU conține promptul', clipClean)

  // ── Faza 1 (consola de flotă): acțiuni pe bloc ──
  // copiază comanda: clipboardul = exact linia de comandă
  await okCmd.hover()
  await okCmd.getByRole('button', { name: 'command', exact: true }).click()
  const clipCmd = await clipboardUntil(page, (c) => c.trim() === 'echo OSC_OK')
  check('copiază comanda → clipboardul are exact comanda', clipCmd.trim() === 'echo OSC_OK')
  // ca markdown: bloc ```console cu comandă + output
  await okCmd.hover()
  await okCmd.getByRole('button', { name: 'markdown', exact: true }).click()
  const clipMd = await clipboardUntil(page, (c) => c.includes('```console'))
  check('copiază ca markdown → bloc console cu comandă+output',
    clipMd.includes('```console') && clipMd.includes('$ echo OSC_OK') && clipMd.includes('OSC_OK'))
  // rulează din nou: pune comanda la prompt (staged) și se poate re-executa
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('echo RERUN_ME\n')
  await page.waitForTimeout(800)
  const srcCmd = cmdPanel.locator('div.group').filter({ hasText: 'echo RERUN_ME' }).first()
  await srcCmd.hover()
  await srcCmd.getByRole('button', { name: '↻ Run again' }).click()
  await page.waitForTimeout(300)
  await page.keyboard.press('Enter')
  await page.waitForTimeout(800)
  check('„Rulează din nou" pune comanda la prompt și se re-execută',
    ((await screenText()).match(/RERUN_ME/g) || []).length >= 3)

  // înregistrarea continuă după output zgomotos (regresia raportată).
  // click în terminal întâi: după click-ul din panou, focusul e pe buton
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('seq 1 120 > /dev/null; echo DUPA_ZGOMOT\n')
  await page.waitForTimeout(1500)
  check('comenzile se înregistrează în continuare', ((await cmdPanel.textContent()) ?? '').includes('DUPA_ZGOMOT'))

  // ── History de clipboard GLOBAL (3.5.4): copiat în sesiunea curentă (C), lipit în D ──
  // Până la 3.5.3 history-ul era per terminal: picker-ul altui tab era gol pentru ce copiai în C.
  // Copiem comanda din panoul lui C, deschidem D, Ctrl+Shift+V: intrarea apare cu eticheta lui
  // C (titlul sesiunii) şi, lipită, ajunge pe ecranul lui D.
  const sidC = await page.evaluate(() => location.hash.replace('#/s/', ''))
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('echo CLIPX_$((6*7))\n')
  await page.waitForTimeout(1200)
  const clipRow = cmdPanel.locator('div.group').filter({ hasText: 'echo CLIPX_' }).first()
  await clipRow.hover()
  await clipRow.getByRole('button', { name: 'command', exact: true }).click()
  await clipboardUntil(page, (c) => c.trim() === 'echo CLIPX_$((6*7))')
  const titleC = await page.evaluate(async (sid) => {
    const arr = await (await fetch('/api/sessions')).json()
    return (Array.isArray(arr) ? arr : []).find((s) => s.id === sid)?.title ?? ''
  }, sidC)
  // A e închisă deja (player-ul de transcript): ţinta e o sesiune NOUĂ, D, la prompt curat
  await goHome()
  await newSession(page)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1500)
  await page.keyboard.type('echo D_$((50+5))\n')
  await waitScreen('D_55')
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.press('Control+Shift+V')
  const picker = page.locator('[role=dialog][aria-label="Paste from history"]')
  check('paste picker (global): se deschide în D cu Ctrl+Shift+V', await visible(picker))
  const clipEntry = picker.locator('li').filter({ hasText: 'echo CLIPX_' }).first()
  const clipSrc = (await clipEntry.locator('.pp-source').textContent({ timeout: 3000 }).catch(() => '')) ?? ''
  if (!titleC || !clipSrc.includes(titleC)) console.log(`     [diag] titleC=${JSON.stringify(titleC)} sursa=${JSON.stringify(clipSrc)}`)
  check('paste picker (global): copierea din C e listată în D, cu eticheta lui C', !!titleC && clipSrc.includes(titleC))
  await clipEntry.locator('button').first().click()
  check('paste picker (global): intrarea din C, lipită, apare pe ecranul lui D',
    await waitScreen('echo CLIPX_$((6*7))'))
  await page.keyboard.press('Enter')         // curăţenie: promptul lui D rămâne gol
  await page.waitForTimeout(600)
  // înapoi pe C: verificările de mai jos folosesc panoul de comenzi al lui C
  await page.locator(`button[data-tab="${sidC}"]`).evaluate((el) => el.click())
  await page.waitForTimeout(800)
  await activePane.locator('.xterm-screen').click()

  // ── Faza 3 (consola de flotă): istoric global de comenzi (OSC 133 → server) ──
  await page.keyboard.press('Control+Shift+K')
  await page.waitForTimeout(300)
  await page.keyboard.type('Command history')
  await page.waitForTimeout(300)
  await page.keyboard.press('Enter')
  const hist = page.locator('[role=dialog][aria-label="Command history"]')
  check('modalul de istoric se deschide', await visible(hist))
  await hist.locator('input[aria-label="Search commands"]').fill('OSC_OK')
  await page.waitForTimeout(700)
  check('istoricul găsește comanda rulată (raportată la server)', ((await hist.textContent()) ?? '').includes('echo OSC_OK'))
  await page.keyboard.press('Escape')
  check('modalul de istoric se închide cu Escape (focus-trap)', await hidden(hist))

  // ── RECONECTARE cu replay de istoric (incidentele din 2026-08-05) ──
  // Aici s-au ascuns două bug-uri pe care restul suitei nu le vedea, fiindcă toate
  // verificările de mai sus rulează pe o sesiune PROASPĂTĂ, fără istoric de rejucat:
  //  1. coada trimisă la ataşare începea cu intrarea tmux în ecran alternativ; browserul
  //     rămânea acolo, iar tracker-ul ignoră deliberat marcajele din alt-screen → panoul
  //     de comenzi rămânea gol la FIECARE sesiune cu istoric (v1.0.128);
  //  2. odată reparat (1), marcajele DIN REPLAY erau tratate ca live → istoricul global
  //     se umplea cu prompturi şi bucăţi de output, din nou la fiecare reconectare (v1.0.129).
  const histBefore = await page.evaluate(async () =>
    (await (await fetch('/api/history?limit=200', { credentials: 'same-origin' })).json()).length)
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.waitForSelector('.xterm-screen', { timeout: 20000 })
  await page.waitForTimeout(4000)          // replay-ul cozii + reataşarea
  const histAfter = await page.evaluate(async () =>
    (await (await fetch('/api/history?limit=200', { credentials: 'same-origin' })).json()))
  check('replay-ul NU adaugă intrări în istoricul global',
    histAfter.length === histBefore, `${histBefore} → ${histAfter.length}`)
  check('istoricul nu conţine prompturi ca text de comandă',
    !histAfter.some((h) => /[@:][~\w/.-]*[#$]\s/.test(h.command ?? '')),
    JSON.stringify(histAfter.slice(0, 3)))

  // după reconectare, o comandă NOUĂ trebuie să fie marcată: dacă terminalul ar fi rămas
  // în ecran alternativ, aici n-ar apărea nimic — exact simptomul raportat pe host real
  const paneAfter = page.locator('div:not([aria-hidden="true"]) > .wt-window').last()
  await paneAfter.locator('.xterm-screen').click()
  await page.keyboard.type('echo DUPA_RELOAD\n')
  await page.waitForTimeout(2000)
  const histFinal = await page.evaluate(async () =>
    (await (await fetch('/api/history?limit=200', { credentials: 'same-origin' })).json()))
  check('după reconectare, comenzile noi ajung în istoric',
    histFinal.some((h) => (h.command ?? '').includes('echo DUPA_RELOAD')),
    JSON.stringify(histFinal.slice(0, 3)))
  check('comanda e înregistrată curat (fără prompt lipit)',
    histFinal.some((h) => (h.command ?? '').trim() === 'echo DUPA_RELOAD'),
    JSON.stringify(histFinal.filter((h) => (h.command ?? '').includes('DUPA_RELOAD'))))

  // ── ISTORIC tmux la reataşare (agent v57, op-ul `history`) ──
  // Înainte, ataşarea rejuca doar ultimii 256 KiB din transcript; sub tmux asta însemna câteva
  // ecrane. Aici: 3000 de rânduri numerotate, apoi >256 KiB de umplutură (deci rândul 100 e
  // garantat ÎN AFARA cozii de transcript), reload, şi rândul 100 trebuie să fie în scrollback-ul
  // xterm — adus doar de capture-pane. O singură dată: îmbinarea nu are voie să-l dubleze.
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type("seq -f 'WT_HIST_%g' 1 3000; yes " + 'F'.repeat(96) + ' | head -n 3500; echo WT_HIST_$((7*6))\n')
  check('istoric: output-ul mare s-a terminat', await waitScreen('WT_HIST_42', 30000))
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.waitForSelector('.xterm-screen', { timeout: 20000 })
  const histLines = await pollValue(
    () => screenText().then((t) => t.split('\n').filter((l) => l.trim() === 'WT_HIST_100').length),
    (n) => n > 0, 20000)
  const sbInfo = await page.evaluate(() => {
    const t = window.__wtTerms?.get(location.hash.replace('#/s/', ''))
    return t ? `scrollback=${t.options.scrollback} length=${t.buffer.active.length}` : 'no term'
  })
  check('istoric: după reload scrollback-ul conţine rândul 100 (capture-pane), o singură dată',
    histLines === 1, `${histLines}× WT_HIST_100; ${sbInfo}`)
  await page.locator('div:not([aria-hidden="true"]) > .wt-window').last().locator('.xterm-screen').click()
  await page.keyboard.type('echo DUPA_ISTORIC_$((40+2))\n')
  check('istoric: terminalul rămâne viu după replay-ul cu istoric', await waitScreen('DUPA_ISTORIC_42'))
  // Tab în fundal care ratează output → la revenire resync FULL → `term.reset()` în browser.
  // Resync-ul aduce şi el istoricul tmux; altfel scrollback-ul s-ar scurta la prima comutare de tab.
  const histSid = await page.evaluate(() => location.hash.replace('#/s/', ''))
  await page.keyboard.type('sleep 2; echo WT_BG_$((6*7))\n')
  await page.locator(`button[data-tab]:not([data-tab="${histSid}"])`).first().evaluate((el) => el.click())
  await page.waitForTimeout(5000)               // output-ul soseşte cât tabul e pauzat
  await page.locator(`button[data-tab="${histSid}"]`).evaluate((el) => el.click())
  const bgOk = await waitScreen('WT_BG_42', 15000)
  const histAfterResync = await pollValue(
    () => screenText().then((t) => t.split('\n').filter((l) => l.trim() === 'WT_HIST_100').length),
    (n) => n > 0, 15000)
  check('istoric: după resync-ul de revenire din fundal, rândul 100 e tot în scrollback, o dată',
    bgOk && histAfterResync === 1, `bg=${bgOk} ${histAfterResync}× WT_HIST_100`)

  // ── Faza 2 (Val 5): panoul de fișiere — drawer, follow-cwd, operații ──
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cd /tmp\n')
  await page.waitForTimeout(900)
  await activePane.locator('button[title^="Files"]').click()
  const filePanel = page.locator('aside[aria-label="Session files"]').last()
  check('panoul de fișiere se deschide', await visible(filePanel))
  await page.waitForTimeout(900)
  const fpPath = await filePanel.locator('input[title*="Type a path"]').inputValue()
  check('panoul urmărește cwd-ul din terminal (OSC 7 → /tmp)', fpPath === '/tmp')

  // director nou
  await filePanel.locator('button[title="New folder"]').click()
  const nf = filePanel.locator('input[placeholder="folder name"]')
  await nf.fill('wt_ui_test')
  await nf.press('Enter')
  await page.waitForTimeout(1000)
  check('director nou creat apare în listă', ((await filePanel.textContent()) ?? '').includes('wt_ui_test'))

  // ștergere cu confirmare inline
  const fpRow = filePanel.locator('div.group').filter({ hasText: 'wt_ui_test' }).first()
  await fpRow.hover()
  await fpRow.locator('button[title="Delete"]').click()
  await filePanel.locator('button:has-text("Delete")').last().click()
  await page.waitForTimeout(1000)
  check('directorul șters dispare din listă', !((await filePanel.textContent()) ?? '').includes('wt_ui_test'))

  // ── Faza 3 (Val 5): editor Monaco — deschide, editează, salvează pe host ──
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('printf "linia1\\nlinia2\\n" > /tmp/wt_edit.txt\n')
  await page.waitForTimeout(700)
  await filePanel.locator('button[title="Reload"]').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('wt_edit')
  await page.waitForTimeout(500)
  const editRow = filePanel.locator('div.group').filter({ hasText: 'wt_edit.txt' }).first()
  await editRow.hover()
  await editRow.locator('button[title="Edit"]').click()
  const cm = page.locator('.monaco-editor')
  await cm.waitFor({ state: 'visible', timeout: 15000 })
  await page.waitForTimeout(600)   // Monaco se iniţializează asincron (worker + layout)
  check('editorul Monaco se deschide cu conținutul', ((await page.locator('.monaco-editor .view-lines').textContent()) ?? '').includes('linia1'))
  await cm.click()
  await page.keyboard.press('Control+End')
  await page.keyboard.type('linia3noua')
  await page.locator('button:has-text("Save")').click()
  await page.waitForTimeout(1200)
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cat /tmp/wt_edit.txt\n')
  check('salvarea din editor a scris pe host', await waitScreen('linia3noua'))

  // Monaco SLIM (3.5.6): doar tokenizerele Monarch de bază + un singur worker (editor.worker).
  // Un .yaml trebuie să iasă COLORAT (≥3 clase de token: implicit, cheie, număr/comentariu — un
  // limbaj neînregistrat dă o singură clasă), iar workerul editorului să se încarce sub CSP-ul
  // REAL al gateway-ului (script-src 'self', fără worker-src) fără nicio violare. Editorul slim
  // nu-şi cere singur workerul la editare obişnuită, deci îl pornim explicit, cu URL-ul exact pe
  // care îl foloseşte MonacoEnvironment.getWorker (citit din chunk-ul FileEditor deja încărcat).
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('printf "name: web\\nport: 8080 # comentariu\\n" > /tmp/wt_hl.yaml\n')
  await page.waitForTimeout(700)
  await filePanel.locator('button[title="Reload"]').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('wt_hl')
  await pollValue(() => filePanel.textContent().then((t) => t ?? ''), (t) => t.includes('wt_hl.yaml'))
  const hlRow = filePanel.locator('div.group').filter({ hasText: 'wt_hl.yaml' }).first()
  await hlRow.hover()
  await hlRow.locator('button[title="Edit"]').click()
  await page.locator('.monaco-editor').waitFor({ state: 'visible', timeout: 15000 })
  const hlClasses = await pollValue(() => page.evaluate(() => [...new Set([...document.querySelectorAll(
    '.monaco-editor .view-lines span[class^="mtk"]')].map((el) => el.className))]), (c) => c.length >= 3, 8000)
  check('editor: un .yaml e colorat (tokenizer Monarch, Monaco slim)', hlClasses.length >= 3)
  if (hlClasses.length < 3) console.error('  [diag] clase de token:', hlClasses)
  console.log(`     [diag] workere pornite de editor până aici: ${page.workers().map((w) => w.url().split('/').pop()).join(', ') || 'niciunul'}`)
  const workerRes = await page.evaluate(async () => {
    const chunk = performance.getEntriesByType('resource').map((e) => e.name)
      .find((n) => /\/assets\/FileEditor-[^/]*\.js$/.test(n))
    if (!chunk) return 'chunk FileEditor negăsit'
    const url = ((await (await fetch(chunk)).text()).match(/\/assets\/editor\.worker-[\w-]+\.js/) ?? [])[0]
    if (!url) return 'URL-ul workerului negăsit în chunk'
    return await new Promise((resolve) => {
      let w
      const onViol = (e) => resolve(`CSP: ${e.violatedDirective} ${e.blockedURI}`)
      document.addEventListener('securitypolicyviolation', onViol, { once: true })
      const done = (r) => { document.removeEventListener('securitypolicyviolation', onViol); w?.terminate(); resolve(r) }
      try { w = new Worker(url) } catch (e) { done(`excepţie: ${e}`); return }
      w.onerror = (e) => done(`eroare: ${e.message || 'încărcare eşuată'}`)
      setTimeout(() => done('ok'), 2000)       // fără eroare în 2s = scriptul s-a încărcat şi rulează
    })
  })
  check('editor: workerul Monaco se încarcă sub CSP-ul gateway-ului (fără violări)', workerRes === 'ok' && cspErrors.length === 0)
  if (workerRes !== 'ok' || cspErrors.length) console.error('  [diag] worker:', workerRes, cspErrors)
  // curăţenie: închidem editorul (fişierul e curat → fără confirmare) şi refacem filtrul de dinainte
  await page.locator('[role=dialog][aria-label^="Edit"] button:has-text("Close")').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('wt_edit')
  await page.waitForTimeout(400)

  // ── FILE ACTIONS în meniul contextual al terminalului (refoloseşte panoul/editorul/motorul) ──
  // Panoul de fişiere e deschis pe /tmp, deci cwd-ul (OSC 7) ancorează acţiunile acolo.
  const cursorY = () => page.evaluate(() => {
    const sid = location.hash.replace('#/s/', '')
    const term = window.__wtTerms?.get(sid)
    return term ? term.buffer.active.cursorY : -1
  })
  await activePane.locator('.xterm-screen').click({ button: 'right' })
  const ctx = page.locator('[role=menu][aria-label="Terminal actions"]')
  check('meniul contextual al terminalului se deschide', await visible(ctx))
  check('meniul contextual grupează acţiunile în submeniul Files',
    (await ctx.locator('button[aria-haspopup="menu"]:has-text("Files")').count()) > 0)

  // Upload here… urcă prin motorul de upload (lib). Punem fişierul direct pe inputul ascuns —
  // acelaşi efect ca alegerea din dialogul de fişiere (onChange → uploadHere → cwd), fără să
  // depindem de un filechooser headless (fragil). Închidem întâi meniul (Escape).
  await page.keyboard.press('Escape')
  await page.locator('input[data-testid="wt-ctx-upload"]').setInputFiles({
    name: 'wt_ctx_up.txt', mimeType: 'text/plain', buffer: Buffer.from('ctx-upload-ok'),
  })
  await page.waitForTimeout(1500)
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cat /tmp/wt_ctx_up.txt\n')
  check('Upload here (meniu) urcă fişierul în cwd', await waitScreen('ctx-upload-ok'))
  // scoatem jobul din widgetul de transferuri ca testul „pilula" de mai jos să vadă DOAR wt_edit.txt
  // (altfel pilula pliată rezumă mai multe joburi şi nu mai conţine numele aşteptat)
  await page.evaluate(() => {
    const s = window.__wtTransfers?.store
    if (!s?.snapshot) return
    for (const j of s.snapshot().values()) if ((j.name || '').includes('wt_ctx_up')) s.remove(j.id)
  })

  // New folder → panoul se (re)deschide pe cwd în modul inline „dosar nou" (reutilizează doMkdir)
  await activePane.locator('.xterm-screen').click({ button: 'right' })
  await ctx.locator('button[aria-haspopup="menu"]:has-text("Files")').click()
  await ctx.locator('button:has-text("New folder")').click()
  const fpCtx = page.locator('aside[aria-label="Session files"]').last()
  const nfCtx = fpCtx.locator('input[placeholder="folder name"]')
  await nfCtx.fill('wt_ctx_dir'); await nfCtx.press('Enter')
  // mkdir + re-listarea sunt asincrone: pollăm lista până apare directorul (nu un singur read)
  const dirListed = await pollValue(() => fpCtx.textContent().then((t) => t ?? ''), (t) => t.includes('wt_ctx_dir'))
  check('New folder (meniu) creează directorul în cwd', dirListed.includes('wt_ctx_dir'))

  // Clear terminal = Ctrl-L: shell-ul redesenează promptul SUS (cursorY scade spre 0), NU un clear local
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('seq 1 40\n')
  // aşteptăm ca output-ul să fi coborât cursorul (rendering asincron pe runner încărcat)
  const yBefore = await pollValue(cursorY, (y) => y > 2, 8000)
  await activePane.locator('.xterm-screen').click({ button: 'right' })
  await ctx.locator('button:has-text("Clear terminal")').click()
  // pollăm până Ctrl-L redesenează promptul sus (nu un singur read după un sleep fix)
  const yAfter = await pollValue(cursorY, (y) => y >= 0 && y <= 2, 8000)
  check('Clear terminal trimite Ctrl-L şi shell-ul redesenează promptul sus',
    yAfter >= 0 && yAfter <= 2 && yAfter < yBefore, `${yBefore} → ${yAfter}`)

  // Fişier mare (>1 MiB): la deschidere în editor apar bannerul + doar-citire (reutilizează FileEditor)
  await activePane.locator('.xterm-screen').click()
  // ~1.9 MB CU rânduri (seq), nu o singură linie uriaşă: tot peste 1 MiB (deci trunchiat + doar
  // citire), dar Monaco îl randează uşor (virtualizare pe rânduri) — fără să încetinească runnerul.
  await page.keyboard.type('seq 1 300000 > /tmp/wt_big.txt\n')
  await page.waitForTimeout(1500)
  await fpCtx.locator('button[title="Reload"]').click()
  await fpCtx.locator('input[placeholder="filter…"]').fill('wt_big')
  // scrierea + re-listarea sunt asincrone: pollăm până apare rândul (ca la testul cu nume special)
  await pollValue(() => fpCtx.textContent().then((t) => t ?? ''), (t) => t.includes('wt_big.txt'))
  const bigRow = fpCtx.locator('div.group').filter({ hasText: 'wt_big.txt' }).first()
  await bigRow.hover()
  await bigRow.locator('button[title="Edit"]').click()
  const cmBig = page.locator('.monaco-editor')
  await cmBig.waitFor({ state: 'visible', timeout: 15000 })
  const bigBanner = page.locator('[data-testid="editor-bigfile-banner"]')
  check('editor: banner de fişier mare la fişier trunchiat',
    (await visible(bigBanner, 10000)) && ((await bigBanner.textContent()) ?? '').includes('read-only'))
  const bigDlg = page.locator('[role=dialog][aria-label^="Edit"]')
  check('editor: fişierul mare e doar în citire (fără buton Save)',
    (await bigDlg.locator('button:has-text("Save")').count()) === 0)
  // curăţenie pentru testele următoare: închide editorul şi goleşte filtrul (panoul rămâne pe /tmp)
  await bigDlg.locator('button:has-text("Close")').click()
  await fpCtx.locator('input[placeholder="filter…"]').fill('')
  await fpCtx.locator('button[title="Reload"]').click()
  await page.waitForTimeout(600)

  // ── Faza 4 (Val 5): confirmare de overwrite la upload peste fișier existent ──
  await filePanel.locator('input[type=file]').setInputFiles({
    name: 'wt_edit.txt', mimeType: 'text/plain', buffer: Buffer.from('continut-suprascris-faza4'),
  })
  await page.waitForTimeout(500)
  check('confirmarea de overwrite apare la coliziune', ((await filePanel.textContent()) ?? '').includes("Overwrite"))
  await filePanel.locator('button:has-text("Overwrite")').click()
  await page.waitForTimeout(1200)
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cat /tmp/wt_edit.txt\n')
  check('overwrite confirmat scrie noul conținut pe host', await waitScreen('continut-suprascris-faza4'))
  // Transferuri: progresul (upload/download) stă acum într-un WIDGET plutitor jos-dreapta, care
  // înlocuieşte fostul chip din bara de taburi + popover + banda de atenţie de sus. Pliat = o
  // pilulă cu sumar; extins = un card cu rândul (Done + Copy path). Minimize îl re-pliază.
  const pill = page.locator('[data-testid="wt-transfers-pill"]')
  check('widgetul de transferuri (pilula) apare jos-dreapta cu upload-ul terminat',
    (await visible(pill)) && ((await pill.textContent()) ?? '').includes('wt_edit.txt'))
  check('banda veche de transferuri nu mai există (atenţia e în widget)',
    (await page.locator('section[aria-label="Transfers"]').count()) === 0)
  await pill.click()
  const card = page.locator('[data-testid="wt-transfers-card"]')
  const cardText = (await visible(card)) ? ((await card.textContent()) ?? '') : ''
  check('extins: cardul arată rândul (Done + Copy path)',
    cardText.includes('wt_edit.txt') && cardText.includes('Done') && (await card.locator('button[aria-label^="Copy path"]').count()) >= 1)
  await card.locator('button[aria-label="Minimize"]').click().catch(() => {})
  check('minimize re-pliază widgetul la pilulă', (await hidden(card)) && (await visible(pill)))
  // curăţenie pentru secţiunile următoare: re-extinde şi aruncă rândul terminat
  await pill.click()
  await card.locator('button[aria-label^="Dismiss"]').first().click().catch(() => {})

  // ── Transfers phase 2: DOWNLOAD prin acelaşi motor (job ↓ în widget, progres, Done) ──
  // Download-ul unui fişier trece acum prin motorul de transfer, nu printr-un `<a download>` oarbă:
  // apare un job ↓ în widget şi se termină singur. Fişier mic → fallback Blob (fără dialog de salvare,
  // deci capturabil în headless). `wt_edit.txt` tocmai a fost scris, deci există în listare.
  const dlPromise = page.waitForEvent('download', { timeout: 15000 }).catch(() => null)
  const dlRow = filePanel.locator('div.group').filter({ hasText: 'wt_edit.txt' }).first()
  await dlRow.hover()
  await dlRow.locator('button[aria-label^="Download"]').first().click()
  // locator agnostic la starea pliat/extins a widgetului (pilulă SAU card)
  const dwidget = page.locator('[data-testid="wt-transfers-pill"], [data-testid="wt-transfers-card"]')
  check('download: apare un job de transfer în widget', (await visible(dwidget, 8000)))
  const dl = await dlPromise
  check('download: fişierul chiar se descarcă (Blob, eveniment de download)', dl != null)
  // se termină: fişier mic → aproape instant. Citim starea din store (sursa pe care o reflectă UI-ul),
  // nu textul pilulei: sumarul ei nu arată per-job „Done".
  let dlDone = false
  for (let i = 0; i < 40 && !dlDone; i++) {
    dlDone = await page.evaluate(() => {
      const snap = window.__wtTransfers?.store?.snapshot?.()
      if (!snap) return false
      for (const j of snap.values()) if (j.dir === 'down' && j.state === 'done') return true
      return false
    })
    if (!dlDone) await page.waitForTimeout(250)
  }
  check('download: jobul se termină (Done)', dlDone)

  // ── 3.5.5: selecţie multiplă + descărcare în bloc + folder prin Transferuri + copiere pe host ──
  // Headless n-are cu cine vorbi un selector de fişier/folder (File System Access) — îl scoatem, ca
  // motorul să cadă pe Blob (evenimente de download capturabile), exact calea browserelor fără FSA.
  await page.evaluate(() => {
    const w = window
    try { Object.defineProperty(w, 'showSaveFilePicker', { value: undefined, configurable: true }) } catch { /* */ }
    try { Object.defineProperty(w, 'showDirectoryPicker', { value: undefined, configurable: true }) } catch { /* */ }
  })
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('printf sel-unu > /tmp/wt_sel1.txt; printf sel-doi > /tmp/wt_sel2.txt; mkdir -p /tmp/wt_seldir/sub /tmp/wt_cpdst && printf in-dir > /tmp/wt_seldir/sub/x.txt\n')
  await page.waitForTimeout(800)
  await filePanel.locator('button[title="Reload"]').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('wt_sel')
  await pollValue(() => filePanel.textContent().then((t) => t ?? ''), (t) => t.includes('wt_sel2.txt') && t.includes('wt_seldir'))
  // „Selectează tot" = ce se VEDE: filtrul lasă wt_sel1.txt, wt_sel2.txt şi folderul wt_seldir
  await filePanel.locator('[data-testid="wt-files-select-all"]').check()
  const selbar = filePanel.locator('[data-testid="wt-files-selbar"]')
  check('multi-select: „Select all" respectă filtrul (3 rânduri) şi arată bara de selecţie',
    (await visible(selbar)) && ((await selbar.textContent()) ?? '').includes('3 selected'))
  // deselectăm folderul cu Ctrl+click pe rândul lui → rămân cele 2 fişiere
  await filePanel.locator('div.group').filter({ hasText: 'wt_seldir' }).first().click({ modifiers: ['Control'] })
  check('multi-select: Ctrl+click comută un rând (2 selectate)', ((await selbar.textContent()) ?? '').includes('2 selected'))
  const dls = []
  const onDl = (d) => dls.push(d.suggestedFilename())
  page.on('download', onDl)
  await selbar.locator('button:has-text("Download")').click()
  let bulkJobs = 0
  for (let i = 0; i < 60 && (bulkJobs < 2 || dls.length < 2); i++) {
    bulkJobs = await page.evaluate(() => {
      const snap = window.__wtTransfers?.store?.snapshot?.()
      return snap ? [...snap.values()].filter((j) => j.dir === 'down' && /wt_sel[12]\.txt$/.test(j.dest)).length : 0
    })
    if (bulkJobs < 2 || dls.length < 2) await page.waitForTimeout(250)
  }
  check('bulk download: 2 fişiere selectate → 2 joburi de transfer', bulkJobs === 2)
  check('bulk download: ambele fişiere chiar se descarcă', dls.includes('wt_sel1.txt') && dls.includes('wt_sel2.txt'))
  await filePanel.locator('[data-testid="wt-files-selbar"] button:has-text("Clear")').click()
  check('multi-select: Clear goleşte selecţia (bara dispare)', await hidden(selbar))

  // folder → .tgz prin MOTOR: rând de arhivă în Transferuri (fără %, octeţi primiţi), apoi Done
  const dirRow = filePanel.locator('div.group').filter({ hasText: 'wt_seldir' }).first()
  await dirRow.hover()
  await dirRow.locator('button[aria-label="Download wt_seldir as a .tgz archive"]').click()
  let arState = ''
  for (let i = 0; i < 80 && arState !== 'done'; i++) {
    arState = await page.evaluate(() => {
      const snap = window.__wtTransfers?.store?.snapshot?.()
      const j = snap ? [...snap.values()].find((x) => x.kind === 'archive' && x.dest.endsWith('/wt_seldir')) : null
      return j ? j.state : ''
    })
    if (arState !== 'done') await page.waitForTimeout(250)
  }
  check('folder download: rând de arhivă în Transferuri care se termină (Done)', arState === 'done')
  check('folder download: arhiva .tgz chiar se descarcă', dls.includes('wt_seldir.tgz'))
  page.off('download', onDl)

  // Copy to host… : pe un singur agent testăm copierea pe ACELAŞI host, în alt folder (permisă —
  // duplicat / mutare de date fără browser). Copierea A → B între doi agenţi e în fs-test.sh.
  await filePanel.locator('div.group').filter({ hasText: 'wt_sel1.txt' }).first()
    .locator('input[type=checkbox]').check()
  await filePanel.locator('[data-testid="wt-files-selbar"] button:has-text("Copy to host")').click()
  const cdlg = page.locator('[data-testid="wt-copy-dialog"]')
  check('copy: dialogul „Copy to host…" se deschide din bara de selecţie', await visible(cdlg))
  // întâi lăsăm dialogul să termine listarea iniţială (hosturi + ~), apoi tastăm destinaţia şi
  // aşteptăm ca folderul tastat să fie cel listat (câmpul devine calea canonică)
  await pollValue(() => cdlg.locator('ul[aria-label="Folders"] li').count(), (n) => n > 0)
  await cdlg.locator('#wt-copy-dir').fill('/tmp/wt_cpdst')
  await cdlg.locator('#wt-copy-dir').press('Enter')
  await pollValue(() => cdlg.locator('ul[aria-label="Folders"]').textContent().then((t) => t ?? ''), (t) => t.includes('No subfolders'))
  await page.waitForTimeout(300)
  const cpDirTyped = await cdlg.locator('#wt-copy-dir').inputValue()
  await cdlg.locator('button:has-text("Copy 1 file")').click()
  let cpState = ''
  for (let i = 0; i < 80 && cpState !== 'done'; i++) {
    cpState = await page.evaluate(() => {
      const snap = window.__wtTransfers?.store?.snapshot?.()
      const j = snap ? [...snap.values()].find((x) => x.dir === 'copy') : null
      return j ? j.state : ''
    })
    if (cpState !== 'done' && cpState !== 'err') await page.waitForTimeout(250)
    else break
  }
  check('copy: job „copy" în Transferuri, terminat pe server (Done)', cpState === 'done')
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cat /tmp/wt_cpdst/wt_sel1.txt && echo " CP_OK"\n')
  const cpOk = await waitScreen('sel-unu CP_OK')
  check('copy: fişierul a ajuns în folderul destinaţie, cu acelaşi conţinut', cpOk)
  if (!cpOk) console.error('  [diag] copy: dir tastat =', cpDirTyped, '· rând =', await page.evaluate(() =>
    JSON.stringify([...(window.__wtTransfers?.store?.snapshot?.()?.values?.() ?? [])].filter((j) => j.dir === 'copy')
      .map((j) => ({ dest: j.dest, state: j.state, detail: j.detail, err: j.error })))))
  await filePanel.locator('input[placeholder="filter…"]').fill('')

  // ── Transfers phase 2: PAUSE apoi RESUME un upload (continuă de la offset-ul real) ──
  // Întârziem fiecare felie cu route() ca upload-ul să fie GARANTAT încă în curs când îl punem pe
  // pauză (localhost + agent în container e altfel prea rapid). Pauza/reluarea le dăm prin hook-ul de
  // test `window.__wtTransfers` (ca `window.__wtTerms` pentru terminale): clic-ul pe butoanele din widget
  // e nesigur cât se re-randează (Playwright îl vede „instabil"), dar UI-ul tot reflectă starea
  // — pe care o verificăm în store. La pauză XHR-urile în zbor sunt anulate → route.continue
  // poate pica, de aceea try/catch.
  const UP_RE = /\/fs\/upload\?/
  await waitAgentOnline(host.id, 'pause/upload')
  // Ţinem fiecare felie în zbor 30 s (nu 8): felia TREBUIE să fie încă reţinută când o punem pe
  // pauză. Cu 8 s, pe un runner încărcat, `visible(pwidget)` (până la 8 s) + poll-ul după jobul
  // activ (până la 8 s) puteau ele singure consuma fereastra → felia se elibera, iar cele 24 MB
  // aterizau INSTANT pe loopback → job `done` înainte de pauză → `paused` niciodată observat.
  // Nu încetineşte testul: anulăm (pauză) + `unroute` înainte ca reţinerea să conteze.
  await page.route(UP_RE, async (route) => {
    await new Promise((r) => setTimeout(r, 30000))
    try { await route.continue() } catch { /* felia a fost anulată de pauză */ }
  })
  const PBYTES = 24 * 1024 * 1024
  await filePanel.locator('input[type=file]').setInputFiles({
    name: 'wt_pause.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(PBYTES, 7),
  })
  const pwidget = page.locator('[data-testid="wt-transfers-pill"], [data-testid="wt-transfers-card"]')
  check('pause: upload-ul porneşte şi apare în widget', await visible(pwidget, 8000))
  // Pollăm după jobul de UPLOAD activ: el apare în store abia după cererea `status` din motor (o
  // scurtă cursă faţă de apariţia widgetului, care poate arăta întâi jobul de download „done" ce
  // lâncezeşte 20 s). Filtrăm pe `!j.dir` (upload) + stare activă.
  let jobId = null
  for (let i = 0; i < 100 && !jobId; i++) {
    jobId = await page.evaluate(() => {
      const snap = window.__wtTransfers?.store?.snapshot?.()
      if (!snap) return null
      for (const j of snap.values()) if (!j.dir && (j.state === 'running' || j.state === 'stalled' || j.state === 'retrying')) return j.id
      return null
    })
    if (!jobId) await page.waitForTimeout(200)
  }
  check('pause: upload activ găsit în store', !!jobId)
  if (!jobId) console.error('  [diag] joburi în store:', await page.evaluate(() =>
    JSON.stringify([...(window.__wtTransfers?.store?.snapshot?.()?.values?.() ?? [])].map((j) => ({ dir: j.dir, state: j.state, err: j.error })))))
  await page.evaluate((id) => window.__wtTransfers.pauseUpload(id), jobId)
  // Verificăm starea în store (sursa pe care o citeşte UI-ul). NU textul widgetului: cât jobul de
  // download „done" mai lâncezeşte (20 s), sumarul arată „2 transfers", nu starea per-job.
  let sawPaused = false
  for (let i = 0; i < 40 && !sawPaused; i++) {
    const st = await page.evaluate((id) => window.__wtTransfers?.store?.get?.(id)?.state, jobId)
    if (st === 'paused') sawPaused = true
    else await page.waitForTimeout(200)
  }
  check('pause: transferul intră în pauză', sawPaused)
  if (!sawPaused) console.error('  [diag] starea jobului:', await page.evaluate((id) => window.__wtTransfers?.store?.get?.(id)?.state, jobId))
  await page.unroute(UP_RE)                      // reluarea de acum înainte curge normal (rapid)
  await page.evaluate((id) => window.__wtTransfers.resumeUpload(id), jobId)
  // se termină după reluare — verificăm pe HOST că fişierul are toţi octeţii (reluat corect, nu corupt)
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type(`for i in $(seq 1 60); do [ -f /tmp/wt_pause.bin ] && [ $(wc -c < /tmp/wt_pause.bin) = ${PBYTES} ] && { echo PAUSE_RESUME_OK; break; }; sleep 1; done\n`)
  check('resume: upload-ul se termină complet pe host (reluat de la offset)', await waitScreen('PAUSE_RESUME_OK', 40000))

  // Paste de IMAGINE în terminal → fişierul e scris în inbox-ul hostului (~/.webterm/inbox/
  // <timestamp>.png) şi calea lui, citată la nevoie, e tastată la prompt (fără Enter). Tastăm
  // `wc -c ` înainte, ca Enter-ul de după să dovedească şi că fişierul chiar există pe host.
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('wc -c ')
  await activePane.locator('.xterm-helper-textarea').evaluate((ta) => {
    const dt = new DataTransfer()
    dt.items.add(new File([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], 'image.png', { type: 'image/png' }))
    ta.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }))
  })
  // Feedback de UX: la final apare un toast care EXPLICĂ ce s-a întâmplat (salvat în inbox + calea
  // inserată la prompt). Apare simultan cu inserarea căii şi lâncezeşte ~6 s — pollăm des, într-o
  // fereastră generoasă pornită chiar după paste, ca să nu ratăm momentul pe un runner lent.
  let pasteToast = false
  for (let i = 0; i < 80 && !pasteToast; i++) {
    const txt = (await page.locator('.wt-toast').allTextContents()).join(' ')
    if (/added to the prompt|adăugat/i.test(txt)) pasteToast = true
    else await page.waitForTimeout(200)
  }
  check('paste de imagine: toastul explică salvarea şi inserarea căii', pasteToast)
  check('paste de imagine: calea din inbox e tastată la prompt', await waitScreen('/.webterm/inbox/', 15000))
  await page.keyboard.type('&& echo PASTE_OK\n')
  check('fişierul lipit există pe host (4 octeţi)', await waitScreen('PASTE_OK', 8000))

  // ── Test #2: nume cu spații/paranteze/diacritice (encoding pe tot lanțul) ──
  const SPECIAL = 'raport ședință (2).txt'
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type(`printf salut > "/tmp/${SPECIAL}"\n`)
  await page.waitForTimeout(700)
  // Ducem panoul EXPLICIT în /tmp: după paste-ul de imagine (inbox) sau un upload lent, panoul
  // putea rămâne în alt director, iar fişierul „lipsea" din listă din motive de test, nu de produs.
  const fpPathInput = filePanel.locator('input[title*="Type a path"]')
  await fpPathInput.fill('/tmp')
  await fpPathInput.press('Enter')
  await pollValue(() => fpPathInput.inputValue(), (v) => v === '/tmp')
  await filePanel.locator('button[title="Reload"]').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('raport')
  // Pollăm: după Reload listarea FS se întoarce ASINCRON, iar panoul se re-randează după ea —
  // un singur read (chiar şi după 500 ms) prindea lista încă ne-împrospătată pe un runner lent.
  const spText = await pollValue(() => filePanel.textContent().then((t) => t ?? ''), (t) => t.includes(SPECIAL))
  check('fișier cu spații/diacritice apare în listă', spText.includes(SPECIAL))
  if (!spText.includes(SPECIAL)) {
    // CI-ul pica aici constant, local niciodată: a ajuns comanda în shell? cu ce nume s-a creat?
    // (tmux fără locale UTF-8 transformă ș/ț în „_" — atunci lista are alt nume)
    await activePane.locator('.xterm-screen').click()
    await page.keyboard.type('ls -b /tmp | grep -i raport; locale | head -3\n')
    await page.waitForTimeout(1200)
    const tail = (await screenText()).split('\n').filter((l) => l.trim()).slice(-6).join(' ⏎ ')
    console.error('  [diag] ecran:', tail.slice(-300))
    console.error('  [diag] panou:', (spText.match(/raport[^\n]{0,40}/) || ['(nimic cu raport)'])[0])
  }
  if (!spText.includes(SPECIAL)) console.error('  [diag] panoul e în', await fpPathInput.inputValue())
  const spRow = filePanel.locator('div.group').filter({ hasText: SPECIAL }).first()
  // Fără rândul din listă NU mai crăpăm tot scriptul (crash-ul forţa re-rularea pe un container
  // cu stare rămasă, unde picau apoi alte verificări): verificările de mai jos pică individual.
  let spEditOk = false, spDelOk = false
  if (spText.includes(SPECIAL)) {
  await spRow.hover()
  await spRow.locator('button[title="Edit"]').click()
  const spCm = page.locator('.monaco-editor')
  await spCm.waitFor({ state: 'visible', timeout: 15000 })
  await page.waitForTimeout(600)
  spEditOk = ((await page.locator('.monaco-editor .view-lines').textContent()) ?? '').includes('salut')
  await page.keyboard.press('Escape')
  await page.waitForTimeout(400)
  await spRow.hover()
  await spRow.locator('button[title="Delete"]').click()
  await filePanel.locator('button:has-text("Delete")').last().click()
  await page.waitForTimeout(800)
  spDelOk = !((await filePanel.textContent()) ?? '').includes('raport ședință')
  }
  check('editorul deschide fișierul cu nume special (encoding preview)', spEditOk)
  check('ștergerea fișierului cu nume special reușește (encoding delete)', spDelOk)

  // ── Port forwards: panoul (declară un forward, apare în listă) ──
  await activePane.locator('button[title^="Port forwards"]').click()
  const fwdPanel = page.locator('aside[aria-label="Port forwards"]').last()
  check('panoul de forward-uri se deschide', await visible(fwdPanel))
  await fwdPanel.locator('button:has-text("Add forward")').click()
  await fwdPanel.locator('input[placeholder="Name (e.g. Grafana)"]').fill('e2e-fwd')
  await fwdPanel.locator('input[placeholder="port"]').fill('9997')
  await fwdPanel.getByRole('button', { name: 'Add', exact: true }).click()
  await page.waitForTimeout(1000)
  check('forward declarat apare în listă', ((await fwdPanel.textContent()) ?? '').includes('e2e-fwd'))
  check('adresa publică (URL) e afișată în listă', ((await fwdPanel.textContent()) ?? '').includes('e2e-fwd.127.0.0.1'))
  // editează: schimbă portul și salvează (PATCH)
  await fwdPanel.locator('button[title="Edit"]').first().click()
  await fwdPanel.locator('input[placeholder="port"]').fill('8123')
  await fwdPanel.getByRole('button', { name: 'Save', exact: true }).click()
  await page.waitForTimeout(1000)
  check('forward editat reflectă noul port', ((await fwdPanel.textContent()) ?? '').includes('8123'))
  await fwdPanel.locator('button[aria-label="Close forwards panel"]').click()

  // ── Faza 2 (consola de flotă): rulare pe mai multe hosturi ──
  await page.locator('button[aria-label="Run on hosts"]').click()
  const fleet = page.locator('div[aria-label="Run on hosts"]')
  check('modalul de rulare pe flotă se deschide', await visible(fleet))
  await fleet.locator('textarea[aria-label="Command"]').fill('echo FLEET_OK')
  // niciun host nu e preselectat (3.5.3): „Select all (N)" e o alegere explicită
  await fleet.getByRole('button', { name: /^Select all/ }).click()
  await fleet.getByRole('button', { name: /Continue/ }).click()
  await fleet.getByRole('button', { name: /Run on \d+ host/ }).click()
  await page.waitForTimeout(3500)
  const fleetText = (await fleet.textContent()) ?? ''
  check('rularea pe flotă întoarce exit 0', /exit 0/.test(fleetText))
  check('grila de flotă arată output-ul comenzii', fleetText.includes('FLEET_OK'))
  await page.keyboard.press('Escape')
  check('modalul de flotă se închide cu Escape (focus-trap)', await hidden(fleet))

  // ── Comenzi salvate de flotă = snippet-uri pe server (3.5.4) ──
  // (a) migrarea one-time: o comandă din vechiul localStorage urcă pe server la deschidere
  await page.evaluate(() => localStorage.setItem('wt-fleet-saved',
    JSON.stringify([{ name: 'E2E legacy', command: 'echo LEGACY_E2E' }])))
  await page.locator('button[aria-label="Run on hosts"]').click()
  check('consola de flotă se redeschide', await visible(fleet))
  const legacyBtn = fleet.getByRole('button', { name: 'Use saved command: E2E legacy' })
  check('comanda din localStorage a migrat (listată din server)', await visible(legacyBtn, 8000))
  const migratedState = await page.evaluate(async () => ({
    key: localStorage.getItem('wt-fleet-saved'),
    onServer: (await fetch('/api/snippets', { credentials: 'same-origin' }).then((r) => r.json()))
      .some((x) => x.body === 'echo LEGACY_E2E'),
  }))
  check('migrarea: snippet pe server + cheia locală ştearsă',
    migratedState.onServer && migratedState.key === null)
  // (b) salvare cu ţinte: hostul e2e poartă eticheta `e2e-fleet`
  await fleet.locator('textarea[aria-label="Command"]').fill('echo TAGGED_E2E')
  await fleet.getByRole('button', { name: /^Select all/ }).click()
  await fleet.getByLabel(/Remember target tags: .*e2e-fleet/).check()
  await fleet.locator('input[aria-label="Name this command"]').fill('E2E tagged')
  await fleet.getByRole('button', { name: 'Save command' }).click()
  await page.waitForTimeout(800)
  const tagged = await page.evaluate(async () =>
    (await fetch('/api/snippets', { credentials: 'same-origin' }).then((r) => r.json()))
      .find((x) => x.title === 'E2E tagged'))
  check('comanda de flotă salvată pe server cu ţintele (tags)',
    !!tagged && tagged.body === 'echo TAGGED_E2E' && (tagged.targets?.tags ?? []).includes('e2e-fleet'))
  await page.keyboard.press('Escape')
  await hidden(fleet)
  // (c) redeschis: listată din server; alegerea ei preselectează hostul etichetat
  await page.locator('button[aria-label="Run on hosts"]').click()
  const taggedBtn = fleet.getByRole('button', { name: 'Use saved command: E2E tagged' })
  check('comanda cu ţinte e listată după redeschidere', await visible(taggedBtn, 8000))
  check('nimic preselectat înainte de alegere', (await fleet.locator('button[aria-pressed="true"]').count()) === 0)
  await taggedBtn.click()
  await page.waitForTimeout(300)
  const pressed = fleet.locator('button[aria-pressed="true"]')
  check('alegerea ei selectează hostul etichetat (+ „matches 1")',
    (await pressed.count()) === 1 && ((await pressed.first().textContent()) ?? '').includes('ci-local')
    && /matches 1 online host/.test((await fleet.getByTestId('fleet-matches').textContent()) ?? '')
    && (await fleet.locator('textarea[aria-label="Command"]').inputValue()) === 'echo TAGGED_E2E')
  await page.keyboard.press('Escape')
  await hidden(fleet)

  // op `run` la nivel de API: exit code-uri CORECTE (regresie reaper — comenzi
  // eșuate raportate ca succes), timeout respectat, captură. ×5 pe eșec ca să
  // prindem race-ul dintre reaper-ul agentului și subprocess.run.
  const runChecks = await page.evaluate(async () => {
    const hosts = await fetch('/api/hosts', { credentials: 'same-origin' }).then((r) => r.json())
    const hid = (hosts.find((h) => h.online) || {}).id
    const call = (command, timeout) => fetch(`/api/hosts/${hid}/run`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ command, timeout }),
    }).then((r) => r.json())
    let allExit7 = true
    for (let i = 0; i < 5; i++) { const r = await call('exit 7'); if (r.exit_code !== 7) allExit7 = false }
    const t = await call('sleep 3', 1)
    const o = await call('printf ABC')
    return { allExit7, timedOut: t.timed_out === true, out: (o.stdout || '').trim(), oExit: o.exit_code }
  })
  check('run: exit code corect pe eșec ×5 (regresie reaper)', runChecks.allExit7)
  check('run: timeout respectat', runChecks.timedOut)
  check('run: stdout capturat + exit 0', runChecks.out === 'ABC' && runChecks.oExit === 0)

  // ── Host offline: overlay în sesiune ──
  // Agentul REAL e oprit (`ptyd.py stop`) şi repornit cu aceeaşi configuraţie: sesiunea deschisă
  // trebuie să arate cardul (de când + Diagnostic), Dismiss să-l ascundă, iar la revenire cardul
  // dispare peste tot şi se anunţă „back online". Sesiunile tmux supravieţuiesc opririi agentului
  // şi sunt re-adoptate — verificăm că terminalul curge din nou (restul testului depinde de agent).
  await goHome()
  await newSession(page)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1300)
  const offWin = page.locator('div:not([aria-hidden="true"]) > .wt-window').last()
  await offWin.locator('.xterm-screen').click()
  await page.keyboard.type('echo OFF_PRE_$((40+2))\n')
  await waitScreen('OFF_PRE_42')
  const offCard = offWin.locator('[data-testid="host-offline"]')
  const stopped = await agentCtl('stop')
  const wentOffline = await waitAgentOffline(host.id)
  // App-ul re-citeşte /api/hosts la 5s: cardul apare la următorul poll
  check('host offline: overlay-ul apare în sesiunea deschisă (agent oprit)',
    stopped && wentOffline && await visible(offCard, 15000))
  const offText = (await offCard.textContent().catch(() => '')) ?? ''
  check('host offline: „Offline since HH:MM" + buton Diagnostics',
    /Offline since \d{1,2}:\d{2}/.test(offText)
      && await offCard.getByRole('button', { name: 'Diagnostics' }).isVisible().catch(() => false))
  check('host offline: cardul nu fură focusul terminalului',
    await page.evaluate(() => !!document.activeElement?.classList.contains('xterm-helper-textarea')))
  // celelalte sesiuni deschise pe acelaşi host (taburi montate) îşi au propriul card — Dismiss
  // e per-cădere ŞI per-sesiune, deci după el trebuie să rămână cel puţin unul în pagină
  const allCards = page.locator('[data-testid="host-offline"]')
  await offCard.getByRole('button', { name: 'Dismiss' }).click()
  check('host offline: Dismiss ascunde overlay-ul (doar în sesiunea asta)',
    (await hidden(offCard)) && (await allCards.count()) > 0)
  const backPill = offWin.locator('[data-testid="host-back-online"]')
  // aşteptarea porneşte ÎNAINTE de repornire: confirmarea e vizibilă doar câteva secunde
  const backSeen = backPill.waitFor({ state: 'visible', timeout: 70000 })
    .then(async () => ((await backPill.textContent()) ?? '') + ' | '
      + ((await offWin.locator('[data-testid="host-offline-live"]').textContent()) ?? ''))
    .catch(() => '')
  const restarted = await agentCtl('start')
  const backOnline = await waitAgentOnline(host.id, 'host-offline overlay', 60000)
  const backText = await backSeen
  check('host offline: la revenire cardul dispare din toate sesiunile',
    restarted && backOnline && (await pollValue(() => allCards.count(), (n) => n === 0, 15000)) === 0)
  check('host offline: „back online" anunţat (vizibil + regiunea aria-live)',
    (backText.match(/is back online/g) ?? []).length === 2)
  await offWin.locator('.xterm-screen').click()
  await page.keyboard.type('echo OFF_POST_$((40+2))\n')
  check('host offline: terminalul curge din nou după repornirea agentului (tmux re-adoptat)',
    await waitScreen('OFF_POST_42', 30000))

  // ── Test #1: izolare cwd pe sesiune (mecanismul din spatele split-ului) ──
  // Fiecare panou de fișiere filtrează evenimentele OSC 7 după sid-ul sesiunii
  // lui. Un `cd` într-o sesiune NU trebuie să miște panoul altei sesiuni — la fel
  // în split (două panouri vizibile) ca și între taburi (keep-alive le ține montate).
  const vis = () => page.locator('div:not([aria-hidden="true"]) > .wt-window').last()
  const visPath = () => vis().locator('input[title*="Type a path"]').inputValue()
  await goHome()
  await newSession(page)                     // X1 (integrată din ~/.bashrc)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1300)
  const x1hash = await page.evaluate(() => location.hash)
  await vis().locator('.xterm-screen').click()
  await page.keyboard.type('cd /tmp\n')
  await page.waitForTimeout(800)
  await vis().locator('button[title^="Files"]').click()
  // Pollăm calea: panoul o prinde dintr-un OSC 7 care se propagă ASINCRON după `cd` — un read fix
  // (800 ms) o rata pe un runner lent. Aserţiunea rămâne pe egalitate exactă, deci un cross-talk real pică.
  check('X1: panoul urmărește cwd-ul lui (/tmp)', (await pollValue(visPath, (v) => v === '/tmp')) === '/tmp')
  // agentul raportează cwd-ul sesiunii direct (fără shell integration) — calea
  // /proc pe backend pty; pane_current_path pe tmux. Așa panoul se deschide unde
  // ești, nu în ~, chiar dacă integrarea shell nu e activă pe host.
  const x1sid = (await page.evaluate(() => location.hash)).replace('#/s/', '')
  await waitAgentOnline(host.id, 'fs/cwd')
  // Pollăm API-ul: agentul raportează cwd-ul din /proc (pty) / pane_current_path (tmux), care se
  // actualizează ASINCRON după `cd /tmp` — un singur fetch îl prindea încă pe cel vechi pe loopback-ul rapid.
  const cwdApi = await pollValue(
    () => page.evaluate(async ([hid, sid]) => {
      const r = await fetch(`/api/hosts/${hid}/fs/cwd?sid=${sid}`, { credentials: 'same-origin' })
      return r.ok ? (await r.json()).cwd : `ERR ${r.status} ${(await r.json().catch(() => ({}))).code ?? ''}`
    }, [host.id, x1sid]),
    (v) => v === '/tmp', 20000)
  check('agentul raportează cwd-ul sesiunii pentru deschiderea panoului', cwdApi === '/tmp')
  if (cwdApi !== '/tmp') console.error('  [diag] fs/cwd a întors', JSON.stringify(cwdApi), 'pentru sid', x1sid)

  await newSession(page)                     // X2
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1300)
  await vis().locator('.xterm-screen').click()
  await page.keyboard.type('cd /var\n')
  await page.waitForTimeout(800)
  await vis().locator('button[title^="Files"]').click()
  check('X2: panoul urmărește cwd-ul lui (/var)', (await pollValue(visPath, (v) => v === '/var')) === '/var')

  // înapoi la X1 — panoul lui trebuie să fie ÎNCĂ /tmp (n-a reacționat la cwd-ul lui X2)
  await page.evaluate((h) => { location.hash = h }, x1hash)
  await page.waitForTimeout(1000)
  // Pollăm pe /tmp: dacă panoul lui X1 ar fi reacţionat (greşit) la cd-ul lui X2, poll-ul expiră pe
  // /var şi check-ul tot pică — deci robusteţea NU slăbeşte acoperirea izolării.
  check('izolare: X1 rămâne /tmp după ce X2 a făcut cd (fără cross-talk între sesiuni)',
    (await pollValue(visPath, (v) => v === '/tmp')) === '/tmp')

  // ── Split-views: layout denumit, comutare, persistenţă la reload, ştergere ──
  // La punctul ăsta sunt ≥2 taburi (X1, X2 + sesiunile anterioare), deci „+ Split view" apare.
  // Confirmările App/Sidebar/SessionView NU mai sunt window.confirm (dialog propriu, role=alertdialog);
  // handlerul nativ rămâne doar pentru panourile încă neconvertite (ex. Toolbox → SSH keys, mai jos).
  page.on('dialog', (d) => d.accept())
  const confirmInApp = async () => {
    const dlg = page.locator('[role="alertdialog"]').last()
    await dlg.waitFor({ timeout: 5000 })
    // butonul de confirmare e ULTIMUL din dialog (Anulează stă primul, focusat la `danger`)
    await dlg.locator('button').last().click()
  }
  await page.locator('button[aria-label="New split view"]').click()
  await page.waitForSelector('input[placeholder="e.g. prod-debug"]', { timeout: 5000 })
  check('split: wizard-ul se deschide cu câmp de nume',
    (await page.locator('input[placeholder="e.g. prod-debug"]').count()) === 1)
  await page.locator('input[placeholder="e.g. prod-debug"]').fill('e2e-split')
  // deterministic: wizard-ul pre-bifează primele taburi (pot fi 3–4 → grilă). Debifăm tot şi
  // alegem EXACT 2 sesiuni → un split cu divider, ca să testăm calea de 2 panouri.
  // doar bifele WIZARD-ului: panoul de fişiere deschis în spate are şi el bife (selecţie, 3.5.5)
  const boxes = page.locator('[aria-labelledby="wt-split-wizard-title"] input[type="checkbox"]:visible')
  for (let i = (await boxes.count()) - 1; i >= 0; i--) { if (await boxes.nth(i).isChecked()) await boxes.nth(i).click() }
  await boxes.nth(0).click(); await boxes.nth(1).click()
  await page.locator('button:has-text("Show side by side")').click()
  await page.waitForTimeout(1200)
  check('split: se randează split-ul de 2 panouri (divider prezent)',
    (await page.locator('[aria-label^="Resize the split"]').count()) >= 1)
  check('split: chip-ul denumit apare în bara de taburi',
    (await page.locator('button:has-text("e2e-split")').count()) >= 1)

  // navigare liberă: click pe un tab de sesiune IESE din split, dar chip-ul RĂMÂNE (revii oricând)
  await page.locator('button[data-tab]').first().evaluate((el) => el.click())
  await page.waitForTimeout(600)
  check('split: click pe un tab de sesiune iese din split (divider dispare)',
    (await page.locator('[aria-label^="Resize the split"]').count()) === 0)
  check('split: chip-ul rămâne în bară după ce ieşi (revii oricând)',
    (await page.locator('button:has-text("e2e-split")').count()) >= 1)
  await page.locator('button:has-text("e2e-split")').first().click()
  await page.waitForTimeout(800)
  check('split: revin la split din chip (divider reapare)',
    (await page.locator('[aria-label^="Resize the split"]').count()) >= 1)

  // REGRESIE: în split activ, click pe un host din sidebar trebuie să IASĂ din split şi să
  // arate pagina hostului. Înainte `splitActive` avea prioritate de render peste pagina
  // hostului, iar click-ul pe host părea mort până dădeai întâi click pe un tab (care
  // dezactiva split-ul). `selectHost` dezactivează acum split-ul, ca `selectSession`.
  await page.locator('.wt-sidebar button:has-text("ci-local")').first().click()
  await page.waitForTimeout(600)
  check('split: click pe un host din sidebar iese din split (divider dispare)',
    (await page.locator('[aria-label^="Resize the split"]').count()) === 0)
  // revin pe o SESIUNE (nu pe pagina hostului) înainte de a reintra în split: paşii de după
  // (reload, apoi Toolbox din bara sesiunii) cer o sesiune selectată, nu ruta /h/<id>.
  await page.locator('button[data-tab]').first().evaluate((el) => el.click())
  await page.waitForTimeout(400)
  // revin la split din chip → readuce selecţia în localStorage pentru testul de reload de mai jos
  await page.locator('button:has-text("e2e-split")').first().click()
  await page.waitForTimeout(800)
  check('split: revin iar la split din chip după navigarea pe host',
    (await page.locator('[aria-label^="Resize the split"]').count()) >= 1)

  // reload → definiţia vine din server (cross-device), selecţia activă din localStorage
  await page.reload()
  await page.waitForTimeout(2000)
  check('split: persistă la reload (definiţie server-side + selecţie locală)',
    (await page.locator('button:has-text("e2e-split")').count()) >= 1
    && (await page.locator('[aria-label^="Resize the split"]').count()) >= 1)

  // ştergere din chip → dispare
  await page.locator('div.wt-tab:has-text("e2e-split") button[aria-label="Delete split view"]').click()
  await confirmInApp()                       // ConfirmModal (danger) în locul window.confirm
  await page.waitForTimeout(800)
  check('split: ştergerea scoate chip-ul',
    (await page.locator('button:has-text("e2e-split")').count()) === 0)

  // ── Toolbox → SSH keys (chei de deploy host→host) + engine-urile InfluxDB ──
  // Pagina hostului → Toolbox. Containerul de CI N-ARE ssh-keygen, deci întâi verificăm
  // exact ce vede un user pe un host minimal: eroarea CLARĂ, nu o tăcere. Apoi pre-creăm
  // perechea prin op-ul `run` (fix calea de „adopţie" a fişierelor existente) şi verificăm
  // calea fericită: fingerprint SHA256 calculat de gateway, delete cu confirmare.
  const hostsNow = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
  const ciHost = hostsNow.find((h) => h.name === 'ci-local')
  // în starea de aici există o sesiune activă → deschidem Toolbox din bara sesiunii (butonul de
  // pe pagina hostului apare doar când nicio sesiune nu e selectată)
  await page.locator('button[title="Toolbox — database connections"]').last().click()
  const tbx = page.locator('aside[aria-label="Toolbox"]').last()
  await tbx.locator('button:has-text("SSH keys")').click()
  await page.waitForTimeout(600)
  check('sshkeys: tab-ul se deschide cu avertismentul de securitate (H-4)',
    await visible(tbx.locator('text=passphrase-less')))
  await tbx.locator('button:has-text("Generate key on this host")').click()
  await page.waitForTimeout(2500)
  check('sshkeys: host fără ssh-keygen → eroare explicită (openssh-client)',
    await visible(tbx.locator('text=openssh-client')))
  const seed = 'mkdir -p ~/.ssh && printf \'%s\\n\' \'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPZm4qhqNbyCLZbB9jTZ8oS7Ku+m+9lSpM9C7EOMi3O webterm-deploy\' > ~/.ssh/webterm_ed25519.pub && touch ~/.ssh/webterm_ed25519 && chmod 600 ~/.ssh/webterm_ed25519'
  const seedRes = await (await fetch(`${BASE}/api/hosts/${ciHost.id}/run`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
    body: JSON.stringify({ command: seed, timeout: 30 }),
  })).json()
  if (seedRes.exit_code !== 0) console.error('seed a eșuat:', seedRes)
  await tbx.locator('button:has-text("Generate key on this host")').click()
  await page.waitForTimeout(2500)
  check('sshkeys: generate adoptă perechea existentă → fingerprint SHA256 + „nedeployată"',
    await visible(tbx.locator('text=SHA256:')) && await visible(tbx.locator('text=Not deployed anywhere yet')))
  // ştergerea cere ConfirmModal-ul propriu (nu mai e window.confirm, deci handler-ul de
  // `dialog` nu-l vede): apăsăm „Delete" în alertdialog, ca un om
  await tbx.locator('button[title="Delete the key (files + record)"]').click()
  await page.locator('[role=alertdialog] button:has-text("Delete")').click()
  await page.waitForTimeout(2000)
  check('sshkeys: delete (cu confirmare) → înapoi la starea de generate',
    await visible(tbx.locator('button:has-text("Generate key on this host")')))
  // formularul de conexiune InfluxDB 2.x: token ≠ parolă → Org în loc de user, fără câmp de
  // bază, iar hint-ul explică injecţia prin env (niciodată argv/transcript)
  await tbx.locator('button:has-text("Connections")').click()
  await tbx.locator('button[aria-label="New connection"]').click()
  const connDlg = page.locator('.glass').last()
  await connDlg.locator('select').first().selectOption('influxdb2')
  await page.waitForTimeout(300)
  check('influx2: formularul arată Org, fără câmp de bază de date',
    await visible(connDlg.locator('text=Org (optional)'))
    && (await connDlg.locator('span:has-text("Database")').count()) === 0)
  check('influx2: hint-ul explică token-ul (env, nu argv)',
    await visible(connDlg.locator('text=API token')))
  await connDlg.locator('button:has-text("Cancel")').click()
  await tbx.locator('button[aria-label="Close"]').click().catch(() => {})

  // ── AI tools (3.5.0): manager pentru CLAUDE.md / sub-agenţi / skill-uri, prin API-ul fs ──
  // Deschis din meniul contextual al terminalului (calea principală), pe scope-ul Global (~) ca
  // să nu depindem de cwd-ul OSC 7. Creăm un agent din şablonul „Code reviewer", verificăm
  // FIŞIERUL de pe host (nu doar UI-ul), apoi îl ştergem prin ConfirmModal.
  const runOnHost = async (command) => (await (await fetch(`${BASE}/api/hosts/${ciHost.id}/run`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
    body: JSON.stringify({ command, timeout: 30 }),
  })).json())
  await page.locator('.xterm-screen').last().click({ button: 'right' })
  await page.locator('[role=menu][aria-label="Terminal actions"] button:has-text("AI tools")').click()
  const ai = page.locator('aside[aria-label="AI tools"]').last()
  check('ai: panoul AI tools se deschide din meniul contextual', await visible(ai, 8000))
  await ai.locator('[role=tab]:has-text("Global")').click()
  await ai.locator('button:has-text("New agent")').click()
  await ai.locator('input[placeholder="code-reviewer"]').fill('Bad Name')
  await ai.locator('form button[type=submit]').click()
  check('ai: un nume invalid e refuzat (regula + sugestie), fără să creeze ceva pe host',
    await visible(ai.locator('[role=alert]:has-text("Try: bad-name")'))
    && ((await runOnHost('ls ~/.claude/agents 2>/dev/null')).stdout ?? '').trim() === '')
  await ai.locator('input[placeholder="code-reviewer"]').fill('e2e-reviewer')
  await ai.locator('form select').selectOption('agent-reviewer')
  await ai.locator('form button[type=submit]').click()
  const aiEditor = page.locator('[role=dialog][aria-label="Edit e2e-reviewer"]')
  check('ai: crearea deschide editorul pe fişierul nou', await visible(aiEditor, 10000))
  await page.keyboard.press('Escape')
  await hidden(aiEditor)
  const aiFile = await pollValue(
    async () => (await runOnHost('cat ~/.claude/agents/e2e-reviewer.md')).stdout ?? '',
    (v) => v.includes('name: e2e-reviewer'))
  check('ai: fişierul e pe host, cu frontmatter-ul şablonului',
    aiFile.includes('name: e2e-reviewer') && aiFile.includes('tools: Read, Grep, Glob, Bash'))
  check('ai: lista arată agentul cu descrierea din frontmatter',
    await visible(ai.locator('li:has-text("e2e-reviewer"):has-text("Reviews recent code changes")'), 8000))
  await ai.locator('button[aria-label="Delete e2e-reviewer"]').click()
  await page.locator('[role=alertdialog] button:has-text("Delete")').click()
  await hidden(ai.locator('li:has-text("e2e-reviewer")'), 8000)
  const aiGone = await runOnHost('test -e ~/.claude/agents/e2e-reviewer.md && echo there || echo gone')
  check('ai: ştergerea (cu confirmare) scoate fişierul de pe host', (aiGone.stdout ?? '').trim() === 'gone')
  await ai.locator('button[aria-label="Close"]').click().catch(() => {})

  // ── Add host → Test connection + cheie generată la creare (3.5.4) ──
  // După AI tools (care cer vederea de sesiune): de aici înainte paşii pornesc de pe Home.
  // Ţintă SSH REALĂ fără sshd în imagine: un server asyncssh (asyncssh e deja în container, e
  // dependenţa gateway-ului) pornit pe 127.0.0.1:2222 prin agentul de test. Gateway-ul îl sună
  // pe loopback-ul containerului — exact dial-ul real. Cheile publice acceptate vin din
  // ~/.ssh/authorized_keys (root), deci one-liner-ul afişat de formular chiar e testat.
  const ciRun = async (command) => (await (await fetch(`${BASE}/api/hosts/${ciHost.id}/run`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: BASE },
    body: JSON.stringify({ command, timeout: 30 }),
  })).json())
  const sshdPy = [
    'import asyncio, os, asyncssh',
    "AK = os.path.expanduser('~/.ssh/authorized_keys')",
    'class S(asyncssh.SSHServer):',
    '    def begin_auth(self, u): return True',
    '    def password_auth_supported(self): return True',
    "    def validate_password(self, u, p): return u == 'e2e' and p == 'parola-e2e-ssh-123456'",
    '    def public_key_auth_supported(self): return True',
    '    def validate_public_key(self, u, k):',
    "        want = k.export_public_key().decode().split()[:2]",
    '        try: lines = open(AK).read().splitlines()',
    '        except OSError: return False',
    '        return any(l.split()[:2] == want for l in lines)',
    'async def main():',
    "    key = asyncssh.generate_private_key('ssh-ed25519')",
    "    await asyncssh.create_server(S, '127.0.0.1', 2222, server_host_keys=[key])",
    "    open('/tmp/wt-e2e-sshd.pid', 'w').write(str(os.getpid()))",
    "    open('/tmp/wt-e2e-sshd.fp', 'w').write(key.get_fingerprint())",
    '    await asyncio.sleep(1800)',
    'asyncio.run(main())',
  ].join('\n')
  const sshdB64 = Buffer.from(sshdPy).toString('base64')
  // re-rulabil (CI re-încearcă E2E o dată): serverul încercării anterioare e oprit întâi
  const sshdStart = await ciRun(
    '[ -f /tmp/wt-e2e-sshd.pid ] && kill "$(cat /tmp/wt-e2e-sshd.pid)" 2>/dev/null; sleep 0.3; '
    + 'rm -f /tmp/wt-e2e-sshd.fp /tmp/wt-e2e-sshd.pid; '
    + `echo ${sshdB64} | base64 -d > /tmp/wt-e2e-sshd.py && `
    + '(setsid nohup python3 /tmp/wt-e2e-sshd.py >/tmp/wt-e2e-sshd.log 2>&1 </dev/null &); '
    + 'for i in $(seq 1 60); do [ -s /tmp/wt-e2e-sshd.fp ] && break; sleep 0.25; done; cat /tmp/wt-e2e-sshd.fp')
  const sshdFp = (sshdStart.stdout ?? '').trim()
  if (!sshdFp.startsWith('SHA256:')) console.error('fixture sshd:', sshdStart, (await ciRun('cat /tmp/wt-e2e-sshd.log')).stdout)
  const addHostDlg = page.locator('[role=dialog][aria-label="Add a host"]')
  const openAddSsh = async (name, port) => {
    await goHome()
    await page.click('button[aria-label="Add host"]')
    await addHostDlg.getByRole('button', { name: 'SSH', exact: true }).click()
    await addHostDlg.getByLabel('Name', { exact: true }).fill(name)
    await addHostDlg.getByLabel('Hostname / IP').fill('127.0.0.1')
    await addHostDlg.locator('input[aria-label="Port"]').fill(String(port))
    await addHostDlg.getByLabel('User', { exact: true }).fill('e2e')
  }
  const testResult = addHostDlg.locator('[data-testid="hosttest-result"]')
  // portul închis: etapa TCP pică, cu textul tradus, iar focusul merge pe câmpul Port
  await openAddSsh('e2e-closed-port', 1)
  await addHostDlg.getByLabel('SSH password').fill('orice')
  await addHostDlg.locator('[data-testid="hosttest-run"]').click()
  check('hosttest: port închis → „TCP failed: Connection refused" + focus pe Port',
    await visible(testResult.locator('text=Connection refused').first(), 15000)
    && (await page.evaluate(() => document.activeElement?.getAttribute('aria-label'))) === 'Port')
  await addHostDlg.locator('button:has-text("Cancel")').last().click()
  await hidden(addHostDlg)
  // ţinta reală: test reuşit → „Save (verified)" → hostul e pinat cu cheia văzută de test
  await openAddSsh('e2e-ssh-tested', 2222)
  await addHostDlg.getByLabel('SSH password').fill('parola-e2e-ssh-123456')
  await addHostDlg.locator('[data-testid="hosttest-run"]').click()
  const okStages = addHostDlg.locator('[data-testid="hosttest-stages"] li[data-state="ok"]')
  await visible(testResult.locator('text=Connection verified'), 15000)
  check('hosttest: SSH real → 4 etape ✓ (TCP, SSH, host key cu amprenta, authentication)',
    (await okStages.count()) === 4 && ((await testResult.textContent()) ?? '').includes(sshdFp || 'SHA256:'))
  const saveVerified = addHostDlg.locator('button:has-text("Save (verified)")')
  check('hosttest: după test butonul devine „Save (verified)"', await visible(saveVerified))
  await saveVerified.click()
  await addHostDlg.locator('button:has-text("Done")').click()
  const sshHosts = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
  const tested = sshHosts.find((h) => h.name === 'e2e-ssh-tested')
  const hk = tested ? await (await fetch(`${BASE}/api/hosts/${tested.id}/hostkey`, { headers: { Cookie: cookie } })).json() : {}
  check('hosttest: hostul salvat e pinat de la creare cu cheia văzută de test',
    !!tested && hk.pinned === true && hk.fingerprint === sshdFp)
  // cheia generată în formular: publica + one-liner-ul; rulat pe ţintă → testul trece cu cheia
  await openAddSsh('e2e-ssh-genkey', 2222)
  await addHostDlg.locator('label:has-text("SSH key")').click()
  await addHostDlg.locator('button:has-text("Generate a key for this host")').click()
  const pendingPub = addHostDlg.locator('[data-testid="pending-key-pub"]')
  check('hosttest: „Generate a key for this host" arată cheia publică ed25519',
    await visible(pendingPub) && ((await pendingPub.textContent()) ?? '').startsWith('ssh-ed25519 '))
  const oneLiner = (await addHostDlg.locator('[data-testid="pending-key"] code').nth(1).textContent()) ?? ''
  await ciRun(oneLiner)
  await addHostDlg.locator('[data-testid="hosttest-run"]').click()
  await visible(testResult.locator('text=Connection verified'), 15000)
  await addHostDlg.locator('button:has-text("Save (verified)")').click()
  await addHostDlg.locator('button:has-text("Done")').click()
  const genHost = (await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json())
    .find((h) => h.name === 'e2e-ssh-genkey')
  check('hosttest: one-liner rulat pe ţintă → test reuşit cu cheia, salvată ca auth key',
    !!genHost && genHost.auth_method === 'key' && genHost.has_credentials === true)
  // curăţenie: hosturile SSH de test nu trebuie să schimbe sidebar-ul pentru paşii următori
  for (const h of [tested, genHost]) {
    if (h) await fetch(`${BASE}/api/hosts/${h.id}`, { method: 'DELETE', headers: { Cookie: cookie, Origin: BASE } })
  }
  await ciRun('[ -f /tmp/wt-e2e-sshd.pid ] && kill "$(cat /tmp/wt-e2e-sshd.pid)"; rm -f /tmp/wt-e2e-sshd.pid')

  // ── Export / import CSV de hosturi (3.5.4) ──
  // Export: Add host → Import CSV → „Export hosts…" → All → descărcarea chiar pleacă, cu BOM şi
  // antetul fix. Import: un CSV lipit cu 2 rânduri SSH, unul cu numele agentului de test
  // (duplicat), unul nou → previzualizarea le marchează exists/new, iar importul creează exact 1.
  await goHome()
  await page.click('button[aria-label="Add host"]')
  await addHostDlg.getByRole('button', { name: 'Import CSV', exact: true }).click()
  await addHostDlg.locator('button:has-text("Export hosts…")').click()
  const csvExport = page.locator('[data-testid="csv-export"]')
  await visible(csvExport)
  await csvExport.getByRole('button', { name: 'All', exact: true }).click()
  const [csvDl] = await Promise.all([
    page.waitForEvent('download', { timeout: 15000 }),
    csvExport.locator('button:has-text("Export CSV (")').click(),
  ])
  const csvBytes = await readFile(await csvDl.path())
  const csvText = csvBytes.toString('utf8')
  check('csv: exportul descarcă webterm-hosts-AAAALLZZ.csv cu BOM + antetul fix + hostul de test',
    /^webterm-hosts-\d{8}\.csv$/.test(csvDl.suggestedFilename())
    && csvBytes[0] === 0xef && csvBytes[1] === 0xbb && csvBytes[2] === 0xbf
    && csvText.slice(1).startsWith('name,connection_type,hostname,port,username,via_host,folder,tags,note,'
      + 'require_2fa,credential_policy,auth_method,agent_note\r\n')
    && csvText.includes('\r\nci-local,agent,'))
  await page.click('button[aria-label="Add host"]')
  await addHostDlg.getByRole('button', { name: 'Import CSV', exact: true }).click()
  await addHostDlg.locator('[data-testid="csv-text"]').fill(
    'name,connection_type,hostname,port,username\r\n'
    + 'ci-local,ssh,10.77.0.1,22,e2e\r\n'
    + 'e2e-csv-new,ssh,10.77.0.2,2200,e2e\r\n')
  await addHostDlg.locator('button:has-text("Preview")').click()
  const csvStatus = addHostDlg.locator('[data-testid="csv-row-status"]')
  await visible(csvStatus.first())
  // lista de hosturi existente soseşte asincron: aşteptăm activ statusul final, cu plafon
  let kinds = []
  for (let i = 0; i < 50 && kinds.join(',') !== 'exists,new'; i++) {
    kinds = await csvStatus.evaluateAll((els) => els.map((e) => e.getAttribute('data-kind')))
    if (kinds.join(',') !== 'exists,new') await page.waitForTimeout(100)
  }
  check('csv: previzualizarea marchează duplicatul „exists" şi rândul nou „new"',
    kinds.join(',') === 'exists,new')
  await addHostDlg.locator('button:has-text("Import (1)")').click()
  await visible(addHostDlg.locator('[data-testid="csv-import-result"]'), 10000)
  const afterCsv = await (await fetch(`${BASE}/api/hosts`, { headers: { Cookie: cookie } })).json()
  const csvNew = afterCsv.filter((h) => h.name === 'e2e-csv-new')
  check('csv: importul creează exact 1 host (SSH, port 2200, politica ask), duplicatul rămâne neatins',
    csvNew.length === 1 && csvNew[0].ssh_port === 2200 && csvNew[0].credential_policy === 'ask'
    && afterCsv.filter((h) => h.name === 'ci-local').length === 1)
  await addHostDlg.locator('button:has-text("Done")').click()
  await hidden(addHostDlg)
  for (const h of csvNew) await fetch(`${BASE}/api/hosts/${h.id}`, { method: 'DELETE', headers: { Cookie: cookie, Origin: BASE } })

  // ── Sfaturi contextuale (coach tips): apariţie scalonată + persistenţă + reset ──
  // Presetarea de la început a marcat toate cheile `wt_tip_*` ca văzute (ca sfaturile să nu
  // blocheze fluxul). Aici le ŞTERGEM — păstrând `wt_walkthrough_done`, altfel turul s-ar
  // deschide peste sesiune — ca să testăm apariţia reală pe prima sesiune vie. (Persistenţa o
  // verificăm pe cheia din localStorage, NU printr-un reload: reload-ul ar re-rula addInitScript
  // şi ar re-preseta cheile, mascând exact dismiss-ul pe care vrem să-l dovedim.)
  await goHome()
  await page.evaluate(() => {
    try { for (const k of ['wt_tip_addhost_agent', 'wt_tip_addhost_ssh', 'wt_tip_terminal_paste', 'wt_tip_toolbar']) localStorage.removeItem(k) } catch { /**/ }
  })
  await newSession(page)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  const pasteTip = page.locator('[data-testid="coachtip-wt_tip_terminal_paste"]')
  const toolbarTip = page.locator('[data-testid="coachtip-wt_tip_toolbar"]')
  check('tips: sfatul de paste/drop apare pe prima sesiune vie', await visible(pasteTip, 8000))
  // „Got it" închide sfatul; dovada persistenţei e cheia scrisă, nu un reload (vezi mai sus)
  await pasteTip.locator('button:has-text("Got it")').click()
  check('tips: închiderea persistă (wt_tip_terminal_paste=1)',
    (await page.evaluate(() => localStorage.getItem('wt_tip_terminal_paste'))) === '1')
  // scalonare: toolbar-ul apare DOAR după ce paste-ul s-a închis (niciodată simultan)
  check('tips: sfatul de toolbar apare după închiderea celui de paste', await visible(toolbarTip, 8000))
  await toolbarTip.locator('button:has-text("Got it")').click()
  check('tips: ambele sfaturi închise după „Got it"',
    (await hidden(pasteTip)) && (await hidden(toolbarTip)))
  // „Arată din nou sfaturile" din Setări → Preferinţe şterge toate cheile wt_tip_*
  await goHome()
  await page.click('button[aria-label="Settings"]')
  await page.click('button:has-text("Preferences")')
  await page.click('button:has-text("Show contextual tips again")')
  check('tips: „reset tips" din Setări şterge toate cheile wt_tip_*',
    await page.evaluate(() => ['wt_tip_addhost_agent', 'wt_tip_addhost_ssh', 'wt_tip_terminal_paste', 'wt_tip_toolbar'].every((k) => localStorage.getItem(k) === null)))
  await page.keyboard.press('Escape')

  // ── Căutarea din Setări (3.5.9): rezultatul ales comută tab-ul şi evidenţiază secţiunea ──
  await page.click('button[aria-label="Settings"]')
  const setSearch = page.locator('[role=dialog] [role=search] input')
  const curTab = () => page.locator('nav[aria-label="Settings categories"] button[aria-current="true"]').textContent()
  const flashed = (id) => page.waitForFunction((sid) => {
    const el = document.querySelector(`[data-setting-id="${sid}"]`)
    return !!el && el.offsetParent !== null && el.classList.contains('wt-setting-flash')
  }, id, { timeout: 5000 }).then(() => true, () => false)
  await setSearch.fill('webhook')
  await page.locator('[role=listbox] [role=option]').first().waitFor({ state: 'visible', timeout: 5000 })
  await page.keyboard.press('Enter')
  const whOk = await flashed('webhook')
  check('setări: „webhook" + Enter → tab-ul Notifications, secţiunea webhook evidenţiată',
    whOk && (await curTab()) === 'Notifications')
  await setSearch.fill('passkey')
  await page.keyboard.press('Enter')
  const pkOk = await flashed('passkeys')
  check('setări: „passkey" + Enter → tab-ul Sign-in & 2FA, secţiunea Passkeys',
    pkOk && (await curTab()) === 'Sign-in & 2FA')
  // „/" (focus în afara unui câmp) duce la căutare; Escape goleşte, nu închide modalul
  await page.locator('nav[aria-label="Settings categories"] button', { hasText: 'Account' }).click()
  await page.keyboard.press('/')
  await page.keyboard.type('zzqx')
  const noneShown = await visible(page.locator('[role=dialog] >> text=No setting matches'), 3000)
  await page.keyboard.press('Escape')
  check('setări: „/" focusează căutarea, starea goală apare, Escape goleşte fără să închidă',
    noneShown && (await setSearch.inputValue()) === '' && (await page.locator('[role=dialog][aria-label="Settings"]').isVisible()))
  await page.keyboard.press('Escape')
  // după reset, sfatul reapare pe o sesiune nouă (readus la viaţă, nu mort definitiv)
  await goHome()
  await newSession(page)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  check('tips: după reset, sfatul de paste reapare pe o sesiune nouă', await visible(pasteTip, 8000))
  await pasteTip.locator('button:has-text("Got it")').click().catch(() => {})   // curăţenie: nu lăsa sfatul deschis peste testul de walkthrough

  // ── Walkthrough de bun venit: redeschiderea manuală din „?" ──
  // Auto-open-ul e dezactivat (am presetat `wt_walkthrough_done` la început), deci aici testăm
  // DOAR calea manuală + persistenţa bifei „nu mai arăta". Ştergem întâi cheia ca verificarea
  // finală să fie reală (bifa chiar o re-scrie), nu doar să reconfirme presetarea.
  await goHome()
  await page.evaluate(() => { try { localStorage.removeItem('wt_walkthrough_done') } catch { /**/ } })
  // focus pe un buton (nu în terminal/câmp): „?" nu se declanşează dintr-un câmp sau din terminal
  await page.focus('button[aria-label="Settings"]')
  await page.keyboard.press('?')
  await page.waitForSelector('[role=dialog][aria-label="Keyboard shortcuts"]', { timeout: 5000 })
  await page.click('button:has-text("Replay the welcome walkthrough")')
  const walk = page.locator('[data-testid="walkthrough"]')
  check('walkthrough: „?" → Replay deschide turul la pasul 1',
    (await visible(walk)) && ((await walk.textContent()) ?? '').includes('Welcome to WebTerm'))
  await walk.locator('button:has-text("Next")').click()
  check('walkthrough: Next avansează la pasul 2 (Add a host)',
    ((await walk.textContent()) ?? '').includes('Add a host'))
  await walk.locator('button[aria-label="Step 7 of 7"]').click()
  check('walkthrough: dot-ul sare la ultimul pas (You\'re all set)',
    ((await walk.textContent()) ?? '').includes("You're all set"))
  await walk.locator('input[type=checkbox]').check()
  await walk.locator('button:has-text("Skip for now")').click()
  check('walkthrough: turul se închide după Skip', await hidden(walk))
  check('walkthrough: „nu mai arăta" + închidere persistă wt_walkthrough_done=1',
    (await page.evaluate(() => localStorage.getItem('wt_walkthrough_done'))) === '1')

  // ── 3.5.13: download File System Access întrerupt de un reload → „Interrupted — Resume / Discard" ──
  // Punem în IndexedDB DOAR metadatele (exact ce rămâne după un tab închis la mijlocul unui download),
  // fără handle: în contextul off-the-record al Playwright citirea unui FileSystemFileHandle din IDB
  // OPREŞTE browserul — motivul pentru care lista de la pornire nu atinge handle-urile. Resume (care
  // îl citeşte) e acoperit de vitest (downloads.resume.test.ts) şi de o sondă cu profil persistent.
  const meUid = await page.evaluate(async () =>
    (await (await fetch('/api/state', { credentials: 'same-origin' })).json()).user_id)
  await page.evaluate(async (uid) => {
    await new Promise((res, rej) => {
      const rq = indexedDB.open('webterm-transfers', 1)
      rq.onupgradeneeded = () => {
        const d = rq.result
        if (!d.objectStoreNames.contains('downloads')) d.createObjectStore('downloads', { keyPath: 'key' })
        if (!d.objectStoreNames.contains('handles')) d.createObjectStore('handles')
      }
      rq.onsuccess = () => {
        const now = Date.now()
        const t = rq.result.transaction('downloads', 'readwrite')
        t.objectStore('downloads').put({ key: `${uid}:1:/tmp/wt_dl_resume.bin`, v: 1, userId: uid, hostId: 1,
          hostName: 'e2e', path: '/tmp/wt_dl_resume.bin', name: 'wt_dl_resume.bin', size: 1000,
          etag: 'W/"1000-1"', mtime: 1, checkpoint: 400, created: now, updated: now })
        t.oncomplete = () => { rq.result.close(); res() }
        t.onerror = () => rej(t.error)
      }
      rq.onerror = () => rej(rq.error)
    })
  }, meUid)
  await page.reload({ waitUntil: 'domcontentloaded' })
  const intRow = await pollValue(() => page.evaluate(() => {
    const snap = window.__wtTransfers?.store?.snapshot?.()
    const j = snap ? [...snap.values()].find((x) => x.dir === 'down' && x.dest === '/tmp/wt_dl_resume.bin') : null
    return j ? `${j.state}:${j.pct}` : ''
  }), (v) => v !== '', 15000)
  check('download întrerupt: după reload apare în Transferuri ca „Interrupted" (40%)', intRow === 'orphan:40', intRow)
  const dlDiscard = page.locator('button[aria-label="Discard wt_dl_resume.bin"]')
  check('download întrerupt: rândul oferă Resume şi Discard',
    (await visible(page.locator('button[aria-label="Resume wt_dl_resume.bin"]'))) && (await visible(dlDiscard)))
  await dlDiscard.click()
  const dlLeft = await pollValue(() => page.evaluate(() => new Promise((res) => {
    const rq = indexedDB.open('webterm-transfers', 1)
    rq.onsuccess = () => { const g = rq.result.transaction('downloads').objectStore('downloads').count(); g.onsuccess = () => { rq.result.close(); res(g.result) } }
    rq.onerror = () => res(-1)
  })), (n) => n === 0, 5000)
  check('download întrerupt: Discard scoate rândul şi înregistrarea din IndexedDB',
    dlLeft === 0 && (await hidden(dlDiscard)), `idb=${dlLeft}`)

  check('fără erori JS în pagină', pageErrors.length === 0)
  if (pageErrors.length) console.error('pageerrors:', pageErrors)
} finally {
  await browser.close()
}

const failed = results.filter(([, ok]) => !ok)
console.log(`\n${results.length - failed.length}/${results.length} verificări trecute`)
process.exit(failed.length ? 1 : 0)
