// Drag & drop pentru reordonarea tab-urilor: tragi ultimul tab peste primul → ordinea se
// schimbă, se persistă (localStorage wt_tabs) şi modul devine „manual".
import { chromium } from 'playwright'
import { execFileSync } from 'node:child_process'

const BASE = process.argv[2] ?? 'http://127.0.0.1:8000'
const CONTAINER = process.argv[3] ?? 'smoke'
const SETUP_TOKEN = process.env.E2E_SETUP_TOKEN ?? 'ci-e2e-token'
const EMAIL = 'u@e.co', PASSWORD = 'parola-de-test-1234'
let fails = 0
const check = (n,c,d='') => { console.log(`  ${c?'PASS':'FAIL'} ${n}${c?'':'  -- '+d}`); if(!c) fails++ }
const dexec = (...a) => execFileSync('docker',['exec',...a],{encoding:'utf8'})

const su = await fetch(`${BASE}/api/setup`,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({email:EMAIL,password:PASSWORD,setup_token:SETUP_TOKEN})})
const cookie=(su.headers.get('set-cookie')??'').split(';')[0]
const hr=await fetch(`${BASE}/api/hosts`,{method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie,Origin:BASE},
  body:JSON.stringify({name:'ci-local',note:'',connection_type:'agent',require_2fa:false})})
const host=await hr.json()
const enroll=host.install_command.match(/install\/([A-Za-z0-9_-]+)\.sh/)[1]
const sh=await (await fetch(`${BASE}/install/${enroll}.sh`)).text()
const tok=sh.match(/^TOKEN="([^"]+)"/m)[1]
const cfg=JSON.stringify({url:'ws://127.0.0.1:8000/agent/ws',token:tok,insecure:true})
dexec(CONTAINER,'sh','-c',`mkdir -p /root/.webterm && printf '%s' '${cfg}' > /root/.webterm/agent.json`)
dexec('-d',CONTAINER,'python3','/srv/webterm/agent/ptyd.py','run')

const browser=await chromium.launch()
try{
  const page=await browser.newPage({viewport:{width:1400,height:800},locale:'en-US'})
  await page.goto(BASE)
  await page.fill('input[type=email]',EMAIL); await page.fill('input[type=password]',PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"]',{timeout:10000})
  await page.waitForSelector('.dot-live',{timeout:30000})
  // 3 sesiuni → 3 taburi
  for (let i=0;i<3;i++){
    await page.click('button[title="Host actions"]')
    await page.click('button[title="New session"]')
    await page.waitForSelector('.xterm-screen',{timeout:15000})
    await page.waitForTimeout(800)
  }
  const order0 = await page.locator('[data-tab]').evaluateAll(els=>els.map(e=>e.getAttribute('data-tab')))
  check('3 taburi deschise', order0.length===3, JSON.stringify(order0))

  // tragem ultimul tab peste primul
  const tabs = page.locator('.wt-tab')
  await tabs.nth(2).dragTo(tabs.nth(0))
  await page.waitForTimeout(400)

  const order1 = await page.locator('[data-tab]').evaluateAll(els=>els.map(e=>e.getAttribute('data-tab')))
  check('ordinea s-a schimbat după drag', JSON.stringify(order1)!==JSON.stringify(order0), JSON.stringify(order1))
  check('ultimul tab a ajuns primul', order1[0]===order0[2], `${order0[2]} vs ${order1[0]}`)

  const stored = await page.evaluate(()=>JSON.parse(localStorage.getItem('wt_tabs')||'[]'))
  check('noua ordine e PERSISTATĂ (wt_tabs)', stored.slice(0,3).join(',')===order1.join(','), JSON.stringify(stored))
  const sortMode = await page.evaluate(()=>localStorage.getItem('wt_tabsort'))
  check('modul a devenit „manual" (nu re-mută pe activitate)', sortMode!=='activity', String(sortMode))

  console.log(`\n${fails===0?'ALL PASS':fails+' FAILED'}`)
} finally { await browser.close() }
process.exit(fails===0?0:1)
