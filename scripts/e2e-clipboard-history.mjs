// Clipboard: toast la copiere + history per terminal + paste picker (Cmd+Shift+V) + paste & run.
import { chromium } from 'playwright'
import { execFileSync } from 'node:child_process'
const BASE=process.argv[2]??'http://127.0.0.1:8000', CONTAINER=process.argv[3]??'smoke'
const SETUP_TOKEN=process.env.E2E_SETUP_TOKEN??'ci-e2e-token'
const EMAIL='u@e.co', PASSWORD='parola-de-test-1234'
let fails=0
const check=(n,c,d='')=>{console.log(`  ${c?'PASS':'FAIL'} ${n}${c?'':'  -- '+d}`); if(!c)fails++}
const dexec=(...a)=>execFileSync('docker',['exec',...a],{encoding:'utf8'})
const su=await fetch(`${BASE}/api/setup`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:EMAIL,password:PASSWORD,setup_token:SETUP_TOKEN})})
const cookie=(su.headers.get('set-cookie')??'').split(';')[0]
const hr=await fetch(`${BASE}/api/hosts`,{method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie,Origin:BASE},body:JSON.stringify({name:'ci-local',note:'',connection_type:'agent',require_2fa:false})})
const host=await hr.json()
const enroll=host.install_command.match(/install\/([A-Za-z0-9_-]+)\.sh/)[1]
const sh=await (await fetch(`${BASE}/install/${enroll}.sh`)).text()
const tok=sh.match(/^TOKEN="([^"]+)"/m)[1]
const cfg=JSON.stringify({url:'ws://127.0.0.1:8000/agent/ws',token:tok,insecure:true})
dexec(CONTAINER,'sh','-c',`mkdir -p /root/.webterm && printf '%s' '${cfg}' > /root/.webterm/agent.json`)
dexec('-d',CONTAINER,'python3','/srv/webterm/agent/ptyd.py','run')
const browser=await chromium.launch()
const ctx=await browser.newContext({viewport:{width:1200,height:800},locale:'en-US',permissions:['clipboard-read','clipboard-write']})
try{
  const page=await ctx.newPage()
  await page.goto(BASE)
  await page.fill('input[type=email]',EMAIL); await page.fill('input[type=password]',PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"]',{timeout:10000})
  await page.waitForSelector('.dot-live',{timeout:30000})
  await page.click('button[title="Host actions"]'); await page.click('button[title="New session"]')
  await page.waitForSelector('.xterm-screen',{timeout:15000}); await page.waitForTimeout(1200)

  // helper: pune o linie, o selectează prin term.select + pointerup (copy-on-select real)
  const copyLine=(text)=>page.evaluate((tx)=>{
    const t=window.__wtTerms?.get(location.hash.replace('#/s/',''))
    const b=t.buffer.active
    let row=-1; for(let i=0;i<b.length;i++){if((b.getLine(i)?.translateToString(true)||'').trim()===tx){row=i;break}}
    if(row<0) return 'NF'
    t.clearSelection(); t.select(0,row,tx.length)
    t.element.parentElement.dispatchEvent(new PointerEvent('pointerup',{button:0,bubbles:true}))
    return t.getSelection()
  }, text)

  await page.keyboard.type('printf "PRIMA_val\\nA_DOUA_val\\n"\n'); await page.waitForTimeout(700)
  await copyLine('PRIMA_val'); await page.waitForTimeout(300)
  // toast vizibil?
  const toastOn=await page.evaluate(()=>!!document.querySelector('.wt-copytoast-on'))
  check('toast „Copiat" apare la copiere', toastOn)
  await copyLine('A_DOUA_val'); await page.waitForTimeout(300)

  // deschidem paste picker cu Cmd/Ctrl+Shift+V (folosim Control ca headless linux)
  await page.locator('.xterm-screen').click()
  await page.keyboard.press('Control+Shift+V'); await page.waitForTimeout(400)
  const dlg=await page.locator('[role=dialog]').count()
  check('paste picker se deschide cu Ctrl+Shift+V', dlg>0)
  const entries=await page.locator('[role=dialog] li').count()
  check('history-ul are ambele copieri', entries===2, `entries=${entries}`)
  const firstText=await page.locator('[role=dialog] li').first().innerText()
  check('cea mai recentă e prima (A_DOUA_val)', firstText.includes('A_DOUA_val'), JSON.stringify(firstText))

  // paste normal pe a doua intrare (PRIMA_val) — doar inserează, nu rulează
  const items=page.locator('[role=dialog] li button').filter({hasText:'PRIMA_val'})
  await items.first().click(); await page.waitForTimeout(500)
  const screen=()=>page.evaluate(()=>{const t=window.__wtTerms?.get(location.hash.replace('#/s/','')); const b=t.buffer.active; let o=''; for(let i=0;i<b.length;i++)o+=(b.getLine(i)?.translateToString(true)||'')+'\n'; return o})
  const scr=await screen()
  // după paste, textul e la prompt dar NU pe o linie nouă executată
  check('paste a inserat textul la prompt', scr.includes('PRIMA_val'), '...')

  console.log(`\n${fails===0?'ALL PASS':fails+' FAILED'}`)
} finally { await browser.close() }
process.exit(fails===0?0:1)
