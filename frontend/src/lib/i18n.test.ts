import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LANG_META, LANG_ORDER, FALLBACK_LANG, loadLang, loaded, isLoaded } from '../lang'
import { tStatic } from './i18n'

// detectLang() reads navigator.languages (undefined on node:20) — stub it so tStatic can run
beforeEach(() => { vi.stubGlobal('navigator', { languages: ['en'], language: 'en' }) })
afterEach(() => { vi.unstubAllGlobals() })

// PF-11/UI-24: non-`en` catalogs load lazily (their own chunk). `en` is the synchronous fallback
// and must always be present. These assert the registry contract the lazy loading relies on.
describe('lazy language registry (PF-11)', () => {
  it('en (the fallback) is loaded eagerly; other languages are not', () => {
    expect(FALLBACK_LANG).toBe('en')
    expect(isLoaded('en')).toBe(true)
    expect(loaded('en')?.strings).toBeTypeOf('object')
    expect(isLoaded('ro')).toBe(false)        // not pulled into the initial bundle
  })

  it('LANG_META lists every language in LANG_ORDER with a flag + name, statically', () => {
    for (const code of LANG_ORDER) {
      expect(LANG_META[code]).toBeTruthy()
      expect(LANG_META[code].name).toBeTruthy()
      expect(LANG_META[code].flag).toBeTruthy()
    }
  })

  it('loadLang pulls a catalog on demand, and its meta matches the static LANG_META (no drift)', async () => {
    await loadLang('ro')
    expect(isLoaded('ro')).toBe(true)
    const ro = loaded('ro')!
    expect(Object.keys(ro.strings).length).toBeGreaterThan(100)
    // the static menu meta must stay in sync with the catalog's own meta
    expect(ro.meta).toEqual(LANG_META.ro)
  })

  it('loadLang is a no-op for en and for an unknown code', async () => {
    await loadLang('en')
    expect(isLoaded('en')).toBe(true)
    await loadLang('zz')                      // unknown → no throw, nothing loaded
    expect(isLoaded('zz')).toBe(false)
    expect(loaded('zz')).toBeUndefined()
  })

  it('tStatic falls back to the key name for a missing key (never throws)', () => {
    expect(tStatic('__definitely_not_a_key__')).toBe('__definitely_not_a_key__')
  })
})
