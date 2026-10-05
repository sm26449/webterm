import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  WALKTHROUGH_DONE_KEY,
  clampStep,
  isWalkthroughDone,
  markWalkthroughDone,
  resetWalkthrough,
  shouldAutoOpen,
  shouldMarkDoneOnClose,
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
})
afterEach(() => vi.unstubAllGlobals())

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
