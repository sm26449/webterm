// Bug: la resync (schimbare de tab), un OSC 52 VECHI din transcript se rejoacă şi suprascrie
// clipboard-ul cu valoarea veche. Repro fidel:
//  1. printf un OSC 52 prin shell (intră în transcript) → clipboard = OLD
//  2. setăm clipboard = NEW (ca o copiere ulterioară)
//  3. Home + înapoi pe sesiune (resync → replay transcript cu OSC 52 vechi)
//  4. clipboard trebuie să rămână NEW (cu fix) / revine la OLD (fără fix)
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
  const clip=()=>page.evaluate(()=>navigator.clipboard.readText().catch(()=>'<err>'))
  await page.goto(BASE)
  await page.fill('input[type=email]',EMAIL); await page.fill('input[type=password]',PASSWORD)
  await page.click('button:has-text("Sign in")')
  await page.waitForSelector('[data-testid="dashboard"]',{timeout:10000})
  await page.waitForSelector('.dot-live',{timeout:30000})
  await page.click('button[title="Host actions"]'); await page.click('button[title="New session"]')
  await page.waitForSelector('.xterm-screen',{timeout:15000}); await page.waitForTimeout(1200)
  const theSid=await page.evaluate(()=>location.hash.replace('#/s/',''))

  // 1. OSC 52 prin shell (intră în transcript). base64 de „OLD_selectie_111".
  const b64old=Buffer.from('OLD_selectie_111').toString('base64')
  await page.keyboard.type(`printf '\\033]52;;${b64old}\\007'\n`)
  await page.waitForTimeout(800)
  const c0=await clip()
  check('setup: OSC 52 din shell a pus OLD în clipboard', c0==='OLD_selectie_111', JSON.stringify(c0))

  // 2. o copiere ulterioară pune NEW
  await page.evaluate(()=>navigator.clipboard.writeText('NEW_valoare_222'))

  // 3. Home + înapoi pe sesiune (resync → replay transcriptului, care conţine OSC 52 vechi)
  await page.locator('button[aria-label="Home"]').evaluate(el=>el.click()).catch(()=>{})
  await page.waitForTimeout(800)
  await page.evaluate((s)=>{location.hash='#/s/'+s}, theSid)
  await page.waitForSelector('.xterm-screen',{timeout:15000})
  await page.waitForTimeout(2500)  // lăsăm replay-ul să curgă

  // 4. verdictul
  const cFinal=await clip()
  check('după resync clipboard-ul rămâne NEW (OSC 52 vechi din replay e ignorat)',
        cFinal==='NEW_valoare_222', JSON.stringify(cFinal)+' (fără fix ar reveni la OLD_selectie_111)')

  console.log(`\n${fails===0?'ALL PASS':fails+' FAILED'}`)
} finally { await browser.close() }
process.exit(fails===0?0:1)
