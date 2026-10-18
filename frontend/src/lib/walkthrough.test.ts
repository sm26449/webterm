import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import type { MyPerms } from './perms'
import {
  PERMS_WAIT_MS,
  TOTAL_STEPS,
  WALKTHROUGH_DONE_KEY,
  buildSteps,
  clampStep,
  isWalkthroughDone,
  markWalkthroughDone,
  resetWalkthrough,
  setWalkthroughUser,
  shouldAutoOpen,
  shouldMarkDoneOnClose,
  stepOnArrow,
  waitForPerms,
  walkthroughDoneKey,
} from './walkthrough'

// Mediul de test e `node` (fără jsdom): lib/storage.ts atinge `window.localStorage`, deci îl
// stubuim ca în font.test.ts — fără dependenţă de jsdom pentru două globale.
class FakeStorage {
  private m = new Map<string, string>()
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
  setItem(k: string, v: string) { this.m.set(k, v) }
  removeItem(k: string) { this.m.delete(k) }
}
let storage: FakeStorage
beforeEach(() => {
  storage = new FakeStorage()
  vi.stubGlobal('window', { localStorage: storage })
  setWalkthroughUser(null)   // modulul ţine contul curent → fiecare test porneşte „deconectat"
})
afterEach(() => vi.unstubAllGlobals())

// Permisiuni-model (aceeaşi formă ca /api/me/permissions): Owner (totul, peste tot), Viewer
// (doar vizualizare pe toate hosturile — rolul predefinit din authz._VIEWER), Operator pe un
// singur host, rol custom „Files-only" (preset-ul din lib/perms) şi un cont fără nicio legătură.
const base: MyPerms = { global: [], all_hosts: [], hosts: {}, bindings: [], owner: false, epoch: 1, has_admins: true }
const bind = { id: 1, role: 'x', role_name: 'x', scope_kind: 'all' as const, scope_value: '', source: 'local', expires: null }
const OWNER: MyPerms = { ...base, owner: true, global: ['hosts.create', 'users.manage'],
  all_hosts: ['host.view', 'session.open', 'files.read', 'files.write', 'docker.view', 'services.view', 'forward.use', 'toolbox.use'],
  bindings: [bind] }
// exact _VIEWER din authz.py: are docker.view / services.view / forward.use (unelte din TOOL_PERMS),
// dar NU session.open — pasul „Session tools" trebuie să cadă pe poarta `shell`, nu pe lipsa uneltelor
const VIEWER: MyPerms = { ...base, bindings: [bind],
  all_hosts: ['host.view', 'host.diagnostics', 'session.watch', 'recording.view', 'docker.view', 'services.view', 'forward.use'] }
const OPERATOR_ONE_HOST: MyPerms = { ...base, hosts: { '7': ['host.view', 'session.open', 'files.read', 'files.write', 'run', 'docker.view'] },
  bindings: [{ ...bind, scope_kind: 'host', scope_value: '7' }] }
const SHELL_ONLY: MyPerms = { ...base, hosts: { '7': ['host.view', 'session.open'] }, bindings: [{ ...bind, scope_kind: 'host', scope_value: '7' }] }
const FILES_ONLY: MyPerms = { ...base, all_hosts: ['host.view', 'files.read', 'files.write'], bindings: [bind] }
const NO_ACCESS: MyPerms = { ...base }
const ids = (p: MyPerms | null) => buildSteps(p).map((s) => s.id)

describe('buildSteps — paşii urmează permisiunile (UI-06 / FL-11)', () => {
  it('Owner: turul complet, în ordinea istorică; TOTAL_STEPS = lungimea lui', () => {
    expect(ids(OWNER)).toEqual(['welcome', 'addHost', 'sessions', 'paste', 'tools', 'security', 'done'])
    expect(TOTAL_STEPS).toBe(7)
  })

  it('permisiuni necunoscute (null) = tur complet, ca „necunoscut = permis" din lib/perms', () => {
    expect(ids(null)).toEqual(ids(OWNER))
  })

  it('Viewer: fără „Add a host", fără sesiuni/paste/unelte; află că hosturile vin de la administrator', () => {
    // înainte: 7 paşi ficşi → „Install the agent…" şi „manage services and Docker" pentru un cont care nu poate
    expect(ids(VIEWER)).toEqual(['welcome', 'hostsByAdmin', 'security', 'done'])
    expect(ids(VIEWER)).not.toContain('addHost')
    expect(ids(VIEWER)).not.toContain('tools')
  })

  it('fără niciun host şi fără hosts.create: tur scurt care se încheie cu „le vei vedea aici"', () => {
    const got = ids(NO_ACCESS)
    expect(got).toEqual(['welcome', 'security', 'noHosts'])
    expect(got[got.length - 1]).toBe('noHosts')
    expect(got).not.toContain('done')
  })

  it('Operator pe un singur host: sesiuni, paste şi unelte (permisiunile cu scope pe host contează)', () => {
    expect(ids(OPERATOR_ONE_HOST)).toEqual(['welcome', 'hostsByAdmin', 'sessions', 'paste', 'tools', 'security', 'done'])
  })

  it('doar shell (session.open fără files.write / unelte): sesiuni da, paste şi unelte nu', () => {
    expect(ids(SHELL_ONLY)).toEqual(['welcome', 'hostsByAdmin', 'sessions', 'security', 'done'])
  })

  it('Files-only (rol custom fără session.open): niciun pas despre terminal', () => {
    expect(ids(FILES_ONLY)).toEqual(['welcome', 'hostsByAdmin', 'security', 'done'])
  })

  it('fiecare pas are titlu + corp în AMBELE cataloage (cheile sunt dinamice, i18n_catalog_test nu le vede)', () => {
    const all = new Set([OWNER, VIEWER, NO_ACCESS, OPERATOR_ONE_HOST, SHELL_ONLY, FILES_ONLY].flatMap((p) => buildSteps(p)).map((s) => s.key))
    expect(all.size).toBe(9)
    for (const k of all) {
      for (const cat of [en.strings, ro.strings]) {
        expect(cat[k + '.title'], k + '.title').toBeTruthy()
        expect(cat[k + '.body'], k + '.body').toBeTruthy()
      }
    }
  })
})

describe('clampStep', () => {
  it('ţine indexul în [0, total-1]', () => {
    expect(clampStep(-3, 7)).toBe(0)
    expect(clampStep(0, 7)).toBe(0)
    expect(clampStep(4, 7)).toBe(4)
    expect(clampStep(6, 7)).toBe(6)
    expect(clampStep(99, 7)).toBe(6)   // clic pe un dot inexistent / ← la capăt
  })

  it('trunchiază şi tratează valorile ne-finite', () => {
    expect(clampStep(2.9, 7)).toBe(2)
    expect(clampStep(NaN, 7)).toBe(0)
    expect(clampStep(5, 0)).toBe(0)    // fără paşi → 0, nu aruncă
  })
})

describe('stepOnArrow — tastele pornesc de la indexul afişat, nu de la o stare fantomă', () => {
  it('în interval: ±1, iar → pe ultimul pas = finalizare', () => {
    expect(stepOnArrow(0, 7, -1)).toBe(0)
    expect(stepOnArrow(2, 7, 1)).toBe(3)
    expect(stepOnArrow(2, 7, -1)).toBe(1)
    expect(stepOnArrow(6, 7, 1)).toBe('finish')
  })

  it('lista s-a scurtat după ce ai avansat (perms sosite târziu): ← se mişcă vizibil de la prima apăsare', () => {
    // starea brută 6 dintr-o listă de 7, lista acum are 4 (afişat 3): înainte ← dădea clampStep(5,4)=3 → nimic
    expect(stepOnArrow(6, 4, -1)).toBe(2)
    expect(stepOnArrow(6, 4, 1)).toBe('finish')   // afişat e ultimul → ca butonul „Get started"
    expect(stepOnArrow(5, 3, -1)).toBe(1)
  })
})

describe('persistenţă (window.localStorage stubuit)', () => {
  it('nemarcat la început; marcat după markWalkthroughDone', () => {
    expect(isWalkthroughDone()).toBe(false)
    markWalkthroughDone()
    expect(isWalkthroughDone()).toBe(true)
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBe('1')
  })

  it('doar exact „1" înseamnă gata', () => {
    storage.setItem(WALKTHROUGH_DONE_KEY, '0')
    expect(isWalkthroughDone()).toBe(false)
    storage.setItem(WALKTHROUGH_DONE_KEY, 'da')
    expect(isWalkthroughDone()).toBe(false)
  })

  it('reset readuce prima-rulare', () => {
    markWalkthroughDone()
    resetWalkthrough()
    expect(isWalkthroughDone()).toBe(false)
  })
})

describe('shouldAutoOpen', () => {
  it('se deschide la prima rulare doar dacă eşti autentificat', () => {
    expect(shouldAutoOpen(false)).toBe(false)   // ecran de login
    expect(shouldAutoOpen(true)).toBe(true)
  })

  it('nu se mai deschide după ce a fost marcat gata', () => {
    markWalkthroughDone()
    expect(shouldAutoOpen(true)).toBe(false)
  })
})

describe('cheia per cont (UI-06): al doilea cont de pe acelaşi browser îşi vede turul', () => {
  it('numele cheii: moştenită fără cont, `wt_walkthrough_done:<id>` cu cont', () => {
    expect(walkthroughDoneKey(null)).toBe('wt_walkthrough_done')
    expect(walkthroughDoneKey(undefined)).toBe('wt_walkthrough_done')
    expect(walkthroughDoneKey(42)).toBe('wt_walkthrough_done:42')
  })

  it('contul A termină turul → contul B (acelaşi browser) îl primeşte; A nu-l mai primeşte', () => {
    setWalkthroughUser(1)
    expect(shouldAutoOpen(true)).toBe(true)
    markWalkthroughDone()
    expect(storage.getItem('wt_walkthrough_done:1')).toBe('1')
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBeNull()   // nimic per browser
    // înainte: o singură cheie → false aici (B nu vedea turul niciodată)
    setWalkthroughUser(2)
    expect(shouldAutoOpen(true)).toBe(true)
    expect(isWalkthroughDone()).toBe(false)
    setWalkthroughUser(1)
    expect(shouldAutoOpen(true)).toBe(false)
    expect(isWalkthroughDone()).toBe(true)
  })

  it('shouldAutoOpen e un predicat pur: nu înregistrează şi nu migrează nimic', () => {
    storage.setItem(WALKTHROUGH_DONE_KEY, '1')
    expect(shouldAutoOpen(true)).toBe(false)                  // nimeni înregistrat → cheia moştenită
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBe('1')   // neatinsă: migrarea e treaba lui setWalkthroughUser
    expect(storage.getItem('wt_walkthrough_done:1')).toBeNull()
  })

  it('reset din Setări şterge DOAR cheia contului curent', () => {
    setWalkthroughUser(1); markWalkthroughDone()
    setWalkthroughUser(2); markWalkthroughDone()
    resetWalkthrough()
    expect(storage.getItem('wt_walkthrough_done:2')).toBeNull()
    expect(storage.getItem('wt_walkthrough_done:1')).toBe('1')
    expect(shouldAutoOpen(true)).toBe(true)                   // contul curent e 2
    setWalkthroughUser(1)
    expect(shouldAutoOpen(true)).toBe(false)
  })

  it('schimbarea contului în acelaşi tab (logout fără reload): Setări/bifa lucrează pe contul NOU', () => {
    setWalkthroughUser(1)
    markWalkthroughDone()
    setWalkthroughUser(2)
    expect(isWalkthroughDone()).toBe(false)                   // B nu vede starea lui A
    expect(storage.getItem('wt_walkthrough_done:1')).toBe('1')
    setWalkthroughUser(null)                                  // deconectat → cheia moştenită, goală
    expect(isWalkthroughDone()).toBe(false)
    setWalkthroughUser(1)
    expect(isWalkthroughDone()).toBe(true)
  })

  it('fără cont cunoscut (App nu a transmis user_id) totul cade pe cheia moştenită — ca înainte', () => {
    markWalkthroughDone()
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBe('1')
    expect(shouldAutoOpen(true)).toBe(false)
  })
})

describe('migrarea cheii moştenite: „gata" DOAR pentru contul curent, o singură dată', () => {
  it('cheia veche = 1 (e2e-urile o presetează) → contul care se autentifică e „gata", cheia veche dispare', () => {
    storage.setItem(WALKTHROUGH_DONE_KEY, '1')
    setWalkthroughUser(5)                                   // App, la autentificare
    expect(shouldAutoOpen(true)).toBe(false)                // fluxul e2e rămâne neatins
    expect(storage.getItem('wt_walkthrough_done:5')).toBe('1')
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBeNull()
  })

  it('cheia veche NU se propagă la alt cont de pe acelaşi browser', () => {
    storage.setItem(WALKTHROUGH_DONE_KEY, '1')
    setWalkthroughUser(5)
    setWalkthroughUser(6)
    expect(shouldAutoOpen(true)).toBe(true)      // înainte: false — B moştenea „gata" de la A
    expect(storage.getItem('wt_walkthrough_done:6')).toBeNull()
  })

  it('cheia veche cu altă valoare (0 / gunoi) nu marchează nimic, dar e curăţată', () => {
    storage.setItem(WALKTHROUGH_DONE_KEY, '0')
    setWalkthroughUser(5)
    expect(shouldAutoOpen(true)).toBe(true)
    expect(storage.getItem('wt_walkthrough_done:5')).toBeNull()
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBeNull()
  })

  it('o cheie per cont deja existentă nu e suprascrisă de cea veche (migrarea e o singură dată)', () => {
    storage.setItem('wt_walkthrough_done:5', '0')   // contul 5 are deja starea lui („nu e gata")
    storage.setItem(WALKTHROUGH_DONE_KEY, '1')
    setWalkthroughUser(5)
    expect(shouldAutoOpen(true)).toBe(true)
    expect(storage.getItem('wt_walkthrough_done:5')).toBe('0')
    expect(storage.getItem(WALKTHROUGH_DONE_KEY)).toBeNull()
    setWalkthroughUser(5)   // a doua apelare (poll / re-montare): nimic nu se schimbă
    expect(isWalkthroughDone()).toBe(false)
  })
})

describe('waitForPerms — auto-deschiderea aşteaptă permisiunile, dar niciodată la nesfârşit', () => {
  it('auto-open fără permisiuni: aşteaptă (înainte: dialogul se monta cu „Step 1 of 7" şi se scurta apoi)', () => {
    expect(waitForPerms(true, null, false)).toBe(true)
  })

  it('permisiunile au sosit → se montează; redeschiderea manuală nu aşteaptă niciodată', () => {
    expect(waitForPerms(true, VIEWER, false)).toBe(false)
    expect(waitForPerms(true, OWNER, false)).toBe(false)
    expect(waitForPerms(false, null, false)).toBe(false)
  })

  it('fetch eşuat: după expirare se montează turul complet (fail-open amânat, nu suprimat)', () => {
    expect(waitForPerms(true, null, true)).toBe(false)
    expect(PERMS_WAIT_MS).toBeGreaterThan(0)
    expect(PERMS_WAIT_MS).toBeLessThanOrEqual(3000)   // o aşteptare „invizibilă", nu un tur care nu mai vine
  })
})

describe('shouldMarkDoneOnClose', () => {
  it('bifa „nu mai arăta" marchează pe orice cale', () => {
    expect(shouldMarkDoneOnClose({ auto: true, reason: 'skip', dontShowAgain: true })).toBe(true)
    expect(shouldMarkDoneOnClose({ auto: false, reason: 'skip', dontShowAgain: true })).toBe(true)
  })

  it('auto + finalizare („Gata") marchează chiar fără bifă', () => {
    expect(shouldMarkDoneOnClose({ auto: true, reason: 'finish', dontShowAgain: false })).toBe(true)
  })

  it('auto + skip fără bifă NU marchează (reapare sesiunea următoare)', () => {
    expect(shouldMarkDoneOnClose({ auto: true, reason: 'skip', dontShowAgain: false })).toBe(false)
  })

  it('replay (auto=false) nu atinge starea fără bifă, nici la finalizare', () => {
    expect(shouldMarkDoneOnClose({ auto: false, reason: 'finish', dontShowAgain: false })).toBe(false)
    expect(shouldMarkDoneOnClose({ auto: false, reason: 'skip', dontShowAgain: false })).toBe(false)
  })
})
