import { afterEach, describe, expect, it, vi } from 'vitest'
import { readLastSettingsCat, rememberSettingsCat, SETTINGS_LAST_KEY, settingsOpenTarget } from './settingsLast'

const all = () => true

describe('settingsOpenTarget', () => {
  it('defaults to Account when nothing was remembered', () => {
    expect(settingsOpenTarget(undefined, null, all)).toEqual({ cat: 'cont' })
  })

  it('opens the last category used', () => {
    expect(settingsOpenTarget(undefined, 'aspect', all)).toEqual({ cat: 'aspect' })
    expect(settingsOpenTarget(undefined, 'sanatate', all)).toEqual({ cat: 'sanatate' })
  })

  it('an explicit deep link always wins, section included', () => {
    expect(settingsOpenTarget({ cat: 'notificari', section: 'alertPrefs' }, 'aspect', all))
      .toEqual({ cat: 'notificari', section: 'alertPrefs' })
    expect(settingsOpenTarget({ cat: 'autentificare', section: 'totp' }, null, all))
      .toEqual({ cat: 'autentificare', section: 'totp' })
  })

  it('ignores an unknown or corrupt stored value', () => {
    expect(settingsOpenTarget(undefined, 'securitate', all)).toEqual({ cat: 'cont' })
    expect(settingsOpenTarget(undefined, '', all)).toEqual({ cat: 'cont' })
    expect(settingsOpenTarget(undefined, '{"cat":"backup"}', all)).toEqual({ cat: 'cont' })
  })

  it('falls back to Account when the remembered tab is no longer visible', () => {
    const visible = (c: string) => c !== 'backup'
    expect(settingsOpenTarget(undefined, 'backup', visible)).toEqual({ cat: 'cont' })
  })
})

describe('remember / read', () => {
  afterEach(() => { vi.unstubAllGlobals() })

  it('round-trips through localStorage', () => {
    const store = new Map<string, string>()
    vi.stubGlobal('window', { localStorage: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => { store.set(k, v) },
      removeItem: (k: string) => { store.delete(k) },
    } })
    expect(readLastSettingsCat()).toBeNull()
    rememberSettingsCat('preferinte')
    expect(store.get(SETTINGS_LAST_KEY)).toBe('preferinte')
    expect(readLastSettingsCat()).toBe('preferinte')
  })

  it('a blocked localStorage reads as nothing and never throws', () => {
    vi.stubGlobal('window', { get localStorage(): Storage { throw new Error('SecurityError') } })
    expect(readLastSettingsCat()).toBeNull()
    expect(() => rememberSettingsCat('aspect')).not.toThrow()
  })
})
