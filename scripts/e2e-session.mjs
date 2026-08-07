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
const fail = (msg) => {
  console.error(`EROARE: ${msg}`)
  process.exit(1)
}

// -- 1. cont + host prin API (node fetch; cookie-ul se poartă manual) --------
const setupRes = await fetch(`${BASE}/api/setup`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD, setup_token: SETUP_TOKEN }),
})
if (!setupRes.ok) fail(`setup a eșuat: ${setupRes.status} ${await setupRes.text()}`)
const cookie = (setupRes.headers.get('set-cookie') ?? '').split(';')[0]
if (!cookie) fail('setup nu a întors cookie de sesiune')
check('setup cont prin API', true)

const hostRes = await fetch(`${BASE}/api/hosts`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({ name: 'ci-local', note: '', connection_type: 'agent', require_2fa: false }),
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
    if (hosts.some((h) => h.online)) break
    await new Promise((r) => setTimeout(r, 1000))
  }
  check('agent pornit extern și online', true)
} else {
  execFileSync('docker', ['exec', CONTAINER, 'sh', '-c',
    `mkdir -p /root/.webterm && printf '%s' '${agentCfg}' > /root/.webterm/agent.json`])
  execFileSync('docker', ['exec', '-d', '-e', 'HOME=/root', CONTAINER,
    'python3', '/srv/webterm/agent/ptyd.py', 'run'])
  check('agent pornit în container', true)
}

// -- 3. UI prin Playwright ----------------------------------------------------
const pageErrors = []
const browser = await chromium.launch()
try {
  // locale RO: UI-ul are i18n (auto-detect din navigator.language); testele selectează după
  // textul RO de referință, deci fixăm limba ca headless-ul (default EN) să nu comute pe engleză.
  const page = await browser.newPage({ viewport: { width: 1440, height: 860 }, locale: 'en-US' })
  page.on('pageerror', (e) => pageErrors.push(String(e)))

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
  await page.click('button[title="New session"]')
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
  await page.click('button[title="New session"]')
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

  // ── Valul 4: OSC 133 (comenzi ca obiecte) ──
  // sesiune nouă + activarea integrării shell din panoul de comenzi
  await goHome()
  await page.click('button[title="New session"]')
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1500)
  // stack-ul keep-alive ține montate și tab-urile ascunse → restrângem la panoul
  // VIZIBIL (altfel selectorul e ambiguu peste toate sesiunile deschise)
  const activePane = page.locator('div:not([aria-hidden="true"]) > .wt-window').last()
  await activePane.locator('button[title*="Commands —"], button[title*="Commands:"]').first().click()
  const cmdPanel = page.locator('aside[aria-label="Session commands"]').last()
  check('panoul de comenzi se deschide', await visible(cmdPanel))
  await cmdPanel.locator('button:has-text("Enable shell integration")').click()
  await page.waitForTimeout(3000)   // curl + source

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
  await page.waitForTimeout(500)
  const clip = await page.evaluate(() => navigator.clipboard.readText())
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
  await page.waitForTimeout(300)
  const clipCmd = await page.evaluate(() => navigator.clipboard.readText())
  check('copiază comanda → clipboardul are exact comanda', clipCmd.trim() === 'echo OSC_OK')
  // ca markdown: bloc ```console cu comandă + output
  await okCmd.hover()
  await okCmd.getByRole('button', { name: 'markdown', exact: true }).click()
  await page.waitForTimeout(300)
  const clipMd = await page.evaluate(() => navigator.clipboard.readText())
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

  // ── Faza 3 (Val 5): editor CodeMirror — deschide, editează, salvează pe host ──
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('printf "linia1\\nlinia2\\n" > /tmp/wt_edit.txt\n')
  await page.waitForTimeout(700)
  await filePanel.locator('button[title="Reload"]').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('wt_edit')
  await page.waitForTimeout(500)
  const editRow = filePanel.locator('div.group').filter({ hasText: 'wt_edit.txt' }).first()
  await editRow.hover()
  await editRow.locator('button[title="Edit"]').click()
  const cm = page.locator('.cm-content')
  await cm.waitFor({ state: 'visible', timeout: 10000 })
  check('editorul CodeMirror se deschide cu conținutul', ((await cm.textContent()) ?? '').includes('linia1'))
  await cm.click()
  await page.keyboard.press('Control+End')
  await page.keyboard.type('linia3noua')
  await page.locator('button:has-text("Save")').click()
  await page.waitForTimeout(1200)
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type('cat /tmp/wt_edit.txt\n')
  check('salvarea din editor a scris pe host', await waitScreen('linia3noua'))

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

  // ── Test #2: nume cu spații/paranteze/diacritice (encoding pe tot lanțul) ──
  const SPECIAL = 'raport ședință (2).txt'
  await activePane.locator('.xterm-screen').click()
  await page.keyboard.type(`printf salut > "/tmp/${SPECIAL}"\n`)
  await page.waitForTimeout(700)
  await filePanel.locator('button[title="Reload"]').click()
  await filePanel.locator('input[placeholder="filter…"]').fill('raport')
  await page.waitForTimeout(500)
  check('fișier cu spații/diacritice apare în listă', ((await filePanel.textContent()) ?? '').includes(SPECIAL))
  const spRow = filePanel.locator('div.group').filter({ hasText: SPECIAL }).first()
  await spRow.hover()
  await spRow.locator('button[title="Edit"]').click()
  const spCm = page.locator('.cm-content')
  await spCm.waitFor({ state: 'visible', timeout: 10000 })
  check('editorul deschide fișierul cu nume special (encoding preview)', ((await spCm.textContent()) ?? '').includes('salut'))
  await page.keyboard.press('Escape')
  await page.waitForTimeout(400)
  await spRow.hover()
  await spRow.locator('button[title="Delete"]').click()
  await filePanel.locator('button:has-text("Delete")').last().click()
  await page.waitForTimeout(800)
  check('ștergerea fișierului cu nume special reușește (encoding delete)', !((await filePanel.textContent()) ?? '').includes('raport ședință'))

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
  await page.locator('button[aria-label="Run across multiple hosts"]').click()
  const fleet = page.locator('div[aria-label="Run across multiple hosts"]')
  check('modalul de rulare pe flotă se deschide', await visible(fleet))
  await fleet.locator('textarea[aria-label="Command"]').fill('echo FLEET_OK')
  await fleet.getByRole('button', { name: /Continue/ }).click()
  await fleet.getByRole('button', { name: /Run on \d+ host/ }).click()
  await page.waitForTimeout(3500)
  const fleetText = (await fleet.textContent()) ?? ''
  check('rularea pe flotă întoarce exit 0', /exit 0/.test(fleetText))
  check('grila de flotă arată output-ul comenzii', fleetText.includes('FLEET_OK'))
  await page.keyboard.press('Escape')
  check('modalul de flotă se închide cu Escape (focus-trap)', await hidden(fleet))

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

  // ── Test #1: izolare cwd pe sesiune (mecanismul din spatele split-ului) ──
  // Fiecare panou de fișiere filtrează evenimentele OSC 7 după sid-ul sesiunii
  // lui. Un `cd` într-o sesiune NU trebuie să miște panoul altei sesiuni — la fel
  // în split (două panouri vizibile) ca și între taburi (keep-alive le ține montate).
  const vis = () => page.locator('div:not([aria-hidden="true"]) > .wt-window').last()
  const visPath = () => vis().locator('input[title*="Type a path"]').inputValue()
  await goHome()
  await page.click('button[title="New session"]')                     // X1 (integrată din ~/.bashrc)
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1300)
  const x1hash = await page.evaluate(() => location.hash)
  await vis().locator('.xterm-screen').click()
  await page.keyboard.type('cd /tmp\n')
  await page.waitForTimeout(800)
  await vis().locator('button[title^="Files"]').click()
  await page.waitForTimeout(800)
  check('X1: panoul urmărește cwd-ul lui (/tmp)', (await visPath()) === '/tmp')
  // agentul raportează cwd-ul sesiunii direct (fără shell integration) — calea
  // /proc pe backend pty; pane_current_path pe tmux. Așa panoul se deschide unde
  // ești, nu în ~, chiar dacă integrarea shell nu e activă pe host.
  const x1sid = (await page.evaluate(() => location.hash)).replace('#/s/', '')
  const cwdApi = await page.evaluate(async ([hid, sid]) => {
    const r = await fetch(`/api/hosts/${hid}/fs/cwd?sid=${sid}`, { credentials: 'same-origin' })
    return r.ok ? (await r.json()).cwd : `ERR ${r.status}`
  }, [host.id, x1sid])
  check('agentul raportează cwd-ul sesiunii pentru deschiderea panoului', cwdApi === '/tmp')

  await page.click('button[title="New session"]')                     // X2
  await page.waitForSelector('.xterm-screen', { timeout: 15000 })
  await page.waitForTimeout(1300)
  await vis().locator('.xterm-screen').click()
  await page.keyboard.type('cd /var\n')
  await page.waitForTimeout(800)
  await vis().locator('button[title^="Files"]').click()
  await page.waitForTimeout(800)
  check('X2: panoul urmărește cwd-ul lui (/var)', (await visPath()) === '/var')

  // înapoi la X1 — panoul lui trebuie să fie ÎNCĂ /tmp (n-a reacționat la cwd-ul lui X2)
  await page.evaluate((h) => { location.hash = h }, x1hash)
  await page.waitForTimeout(1000)
  check('izolare: X1 rămâne /tmp după ce X2 a făcut cd (fără cross-talk între sesiuni)',
    (await visPath()) === '/tmp')

  check('fără erori JS în pagină', pageErrors.length === 0)
  if (pageErrors.length) console.error('pageerrors:', pageErrors)
} finally {
  await browser.close()
}

const failed = results.filter(([, ok]) => !ok)
console.log(`\n${results.length - failed.length}/${results.length} verificări trecute`)
process.exit(failed.length ? 1 : 0)
