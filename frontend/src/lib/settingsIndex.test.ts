import { describe, expect, it } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import { catOfSection, fold, groupHits, searchSettings, SETTINGS_CATS, SETTINGS_INDEX, SettingsCat } from './settingsIndex'

// t() minimal peste un catalog (fără React): aceeaşi cădere pe `en` ca lib/i18n
const tFor = (strings: Record<string, string>) => (key: string) => strings[key] ?? en.strings[key] ?? key
const tEn = tFor(en.strings)
const tRo = tFor(ro.strings)
const ids = (q: string, t = tEn) => searchSettings(q, t).map((h) => h.section.id)

// Sursa fiecărui tab, ca text: integritatea index ↔ UI se verifică pe atributele `data-setting-id`
const sources = import.meta.glob('../components/settings/*Tab.tsx', {
  query: '?raw', import: 'default', eager: true,
}) as Record<string, string>
const TAB_FILE: Record<SettingsCat, string> = {
  cont: 'AccountTab', autentificare: 'SignInTab', infrastructura: 'InfrastructureTab', audit: 'AuditTab',
  aspect: 'AppearanceTab', notificari: 'NotificationsTab', backup: 'BackupTab', preferinte: 'PreferencesTab',
}
const renderedIds = (file: string) => {
  const src = sources[`../components/settings/${file}.tsx`]
  if (!src) throw new Error(`lipseşte ${file}.tsx`)
  return [...src.matchAll(/data-setting-id="([^"]+)"/g)].map((m) => m[1])
}

describe('settings index: integritate', () => {
  it('fiecare tab are etichetă în en şi ro, iar id-urile sunt unice', () => {
    expect(new Set(SETTINGS_CATS.map((c) => c.id)).size).toBe(SETTINGS_CATS.length)
    for (const c of SETTINGS_CATS) {
      expect(en.strings[c.labelKey], c.labelKey).toBeTruthy()
      expect(ro.strings[c.labelKey], c.labelKey).toBeTruthy()
    }
  })

  it.each(SETTINGS_INDEX.map((s) => [s.id, s] as const))('%s: titlu/hint în en+ro, tab existent, cuvinte-cheie', (_id, s) => {
    expect(SETTINGS_CATS.some((c) => c.id === s.cat)).toBe(true)
    for (const strings of [en.strings, ro.strings]) {
      expect(strings[s.titleKey], s.titleKey).toBeTruthy()
      if (s.hintKey) expect(strings[s.hintKey], s.hintKey).toBeTruthy()
    }
    expect(s.keywords.trim().split(/\s+/).length).toBeGreaterThanOrEqual(3)
    expect(catOfSection(s.id)).toBe(s.cat)
  })

  it('id-urile din index sunt unice', () => {
    expect(new Set(SETTINGS_INDEX.map((s) => s.id)).size).toBe(SETTINGS_INDEX.length)
  })

  // o secţiune adăugată într-un tab fără intrare în index (sau invers) ar fi invizibilă căutării
  it.each(SETTINGS_CATS.map((c) => [c.id] as const))('tab-ul %s randează exact secţiunile din index', (cat) => {
    const expected = SETTINGS_INDEX.filter((s) => s.cat === cat).map((s) => s.id).sort()
    expect(renderedIds(TAB_FILE[cat]).sort()).toEqual(expected)
  })

  it('niciun tab nu e gol, iar fostul SecurityTab nu mai există', () => {
    for (const c of SETTINGS_CATS) expect(SETTINGS_INDEX.some((s) => s.cat === c.id), c.id).toBe(true)
    expect(Object.keys(sources).some((p) => p.endsWith('/SecurityTab.tsx'))).toBe(false)
  })
})

describe('settings index: împărţirea fostului tab Securitate', () => {
  it('autentificarea (passkeys, TOTP, dispozitive) e pe „Sign-in & 2FA"', () => {
    for (const id of ['passkeys', 'totp', 'devices']) expect(catOfSection(id)).toBe('autentificare')
  })
  it('infrastructura (token-uri, înrolare, cheie de semnare, guardrail, deploy keys) e pe „Infrastructure & tokens"', () => {
    for (const id of ['tokens', 'enrollGroups', 'signingKey', 'guardrail', 'deployKeyPolicy']) {
      expect(catOfSection(id)).toBe('infrastructura')
    }
  })
  it('numele tab-urilor', () => {
    expect(en.strings['settings.cat.signin']).toBe('Sign-in & 2FA')
    expect(en.strings['settings.cat.infra']).toBe('Infrastructure & tokens')
    expect(ro.strings['settings.cat.signin']).toBe('Autentificare și 2FA')
    expect(ro.strings['settings.cat.infra']).toBe('Infrastructură și tokenuri')
  })
})

describe('searchSettings', () => {
  it('fold scoate diacriticele (inclusiv ş cu sedilă şi ș cu virgulă)', () => {
    expect(fold('Setări Ştiinţă ștergere ÎNROLARE')).toBe('setari stiinta stergere inrolare')
  })

  it('gol sau doar spaţii → niciun rezultat', () => {
    expect(ids('')).toEqual([])
    expect(ids('   ')).toEqual([])
  })

  it('EN: titlul câştigă', () => {
    expect(ids('webhook')[0]).toBe('webhook')
    expect(ids('passkey')[0]).toBe('passkeys')
    expect(ids('guardrail')[0]).toBe('guardrail')
    expect(ids('time zone')[0]).toBe('timezone')
  })

  it('cuvintele-cheie găsesc sinonimele', () => {
    expect(ids('slack')).toContain('webhook')
    expect(ids('yubikey')[0]).toBe('passkeys')
    expect(ids('bearer')[0]).toBe('tokens')
    expect(ids('smtp')[0]).toBe('smtp')
    expect(ids('dropbox')[0]).toBe('backupCloud')
    expect(ids('tz')[0]).toBe('timezone')
  })

  it('RO: titlurile traduse, cu şi fără diacritice', () => {
    expect(ids('fus orar', tRo)[0]).toBe('timezone')
    expect(ids('Înrolare', tRo)[0]).toBe('enrollGroups')
    expect(ids('inrolare', tRo)[0]).toBe('enrollGroups')
    expect(ids('chei de acces', tRo)[0]).toBe('passkeys')
    expect(ids('filigran', tRo)[0]).toBe('watermark')
  })

  it('cuvintele-cheie în română merg şi din interfaţa engleză (şi invers)', () => {
    expect(ids('fus orar', tEn)[0]).toBe('timezone')
    expect(ids('webhook', tRo)[0]).toBe('webhook')
    expect(ids('passkey', tRo)[0]).toBe('passkeys')
  })

  it('toate cuvintele trebuie să se potrivească', () => {
    expect(ids('webhook discord')).toEqual(['webhook'])
    expect(ids('webhook xyzzy')).toEqual([])
  })

  it('numele tab-ului găseşte secţiunile lui', () => {
    const r = ids('infrastructure')
    for (const id of ['tokens', 'enrollGroups', 'signingKey', 'guardrail', 'deployKeyPolicy']) expect(r).toContain(id)
  })

  it('nimic → listă goală', () => {
    expect(ids('qwertyuiop')).toEqual([])
  })

  it('groupHits grupează pe tab, în ordinea celui mai bun rezultat', () => {
    const groups = groupHits(searchSettings('alert', tEn))
    expect(groups[0].cat).toBe('notificari')
    expect(new Set(groups.map((g) => g.cat)).size).toBe(groups.length)
    expect(groups.flatMap((g) => g.hits).length).toBe(searchSettings('alert', tEn).length)
  })
})
