import { describe, expect, it } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import { catOfSection, fold, groupHits, LEGACY_CATS, resolveCat, resolveSettingsTarget, searchSettings, sectionVisible,
  SETTINGS_CATS, SETTINGS_GROUPS, SETTINGS_INDEX, SettingsCat, visibleCats, visibleGroups } from './settingsIndex'

// t() minimal peste un catalog (fără React): aceeaşi cădere pe `en` ca lib/i18n
const tFor = (strings: Record<string, string>) => (key: string) => strings[key] ?? en.strings[key] ?? key
const tEn = tFor(en.strings)
const tRo = tFor(ro.strings)
const ids = (q: string, t = tEn) => searchSettings(q, t).map((h) => h.section.id)

// Sursa fiecărui tab, ca text: integritatea index ↔ UI se verifică pe atributele `data-setting-id`
const sources = import.meta.glob('../components/settings/*Tab.tsx', {
  query: '?raw', import: 'default', eager: true,
}) as Record<string, string>
// un tab al modalului poate fi compus din mai multe fişiere (3.7.1: Account & security = Account +
// Sign-in + Your access); un fişier aparţine unui singur tab
const TAB_FILES: Record<SettingsCat, string[]> = {
  cont: ['AccountTab', 'SignInTab', 'MyAccessTab'], aspect: ['AppearanceTab'], preferinte: ['PreferencesTab'],
  notificari: ['MyNotificationsTab'],
  utilizatori: ['UsersTab'], acces: ['AccessTab'], politici: ['SecurityPolicyTab'], retea: ['NetworkTab'],
  alerte: ['AlertDeliveryTab'], backup: ['BackupTab'], actualizari: ['UpdatesTab'],
  sanatate: ['HealthTab'], audit: ['AuditTab'],
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
    expect(TAB_FILES[cat].flatMap(renderedIds).sort()).toEqual(expected)
  })

  it('fiecare *Tab.tsx care randează secţiuni aparţine exact unui tab', () => {
    const owned = Object.values(TAB_FILES).flat()
    expect(new Set(owned).size).toBe(owned.length)
    for (const path of Object.keys(sources)) {
      const name = path.replace(/^.*\/(\w+)\.tsx$/, '$1')
      if (renderedIds(name).length) expect(owned, name).toContain(name)
    }
  })

  it('niciun tab nu e gol, iar fostele SecurityTab / InfrastructureTab / NotificationsTab nu mai există', () => {
    for (const c of SETTINGS_CATS) expect(SETTINGS_INDEX.some((s) => s.cat === c.id), c.id).toBe(true)
    for (const gone of ['SecurityTab', 'InfrastructureTab', 'NotificationsTab']) {
      expect(Object.keys(sources).some((p) => p.endsWith(`/${gone}.tsx`)), gone).toBe(false)
    }
  })

  it('fiecare categorie e într-un grup cunoscut, iar grupurile au etichetă în en şi ro', () => {
    for (const c of SETTINGS_CATS) expect(SETTINGS_GROUPS.some((g) => g.id === c.group), c.id).toBe(true)
    for (const g of SETTINGS_GROUPS) {
      expect(en.strings[g.labelKey], g.labelKey).toBeTruthy()
      expect(ro.strings[g.labelKey], g.labelKey).toBeTruthy()
    }
  })
})

describe('settings index: regruparea pe intenţie (3.7.1, auditul UX Setări §2.3)', () => {
  it('Account & security: contul, autentificarea şi accesul tău', () => {
    for (const id of ['account', 'passkeys', 'totp', 'devices', 'myAccess']) expect(catOfSection(id)).toBe('cont')
  })
  it('fostul „Infrastructure & tokens" e spart în Access & automation, Security policy, Network & certificates', () => {
    for (const id of ['tokens', 'enrollGroups', 'signingKey']) expect(catOfSection(id)).toBe('acces')
    for (const id of ['guardrail', 'deployKeyPolicy', 'watermark']) expect(catOfSection(id)).toBe('politici')
    for (const id of ['certificates', 'forwardDomain']) expect(catOfSection(id)).toBe('retea')
  })
  it('notificările mele sunt separate de livrarea alertelor; versiunea are tab-ul ei', () => {
    for (const id of ['alertPrefs', 'taskNotify']) expect(catOfSection(id)).toBe('notificari')
    for (const id of ['smtp', 'webhook', 'resourceAlerts']) expect(catOfSection(id)).toBe('alerte')
    expect(catOfSection('appUpdate')).toBe('actualizari')
  })
  it('grupurile: Personal, Administrare, Operare — în ordinea rail-ului', () => {
    expect(SETTINGS_GROUPS.map((g) => g.id)).toEqual(['personal', 'admin', 'ops'])
    const byGroup = (g: string) => SETTINGS_CATS.filter((c) => c.group === g).map((c) => c.id)
    expect(byGroup('personal')).toEqual(['cont', 'aspect', 'preferinte', 'notificari'])
    expect(byGroup('admin')).toEqual(['utilizatori', 'acces', 'politici', 'retea', 'alerte', 'backup', 'actualizari'])
    expect(byGroup('ops')).toEqual(['sanatate', 'audit'])
    // ordinea rail-ului = grupurile în ordine (un grup nu se rupe în două)
    expect(SETTINGS_CATS.map((c) => c.group)).toEqual([...byGroup('personal').map(() => 'personal'),
      ...byGroup('admin').map(() => 'admin'), ...byGroup('ops').map(() => 'ops')])
  })
  it('numele tab-urilor (en + ro), scurte ca rail-ul să nu se rupă', () => {
    expect(en.strings['settings.cat.account']).toBe('Account & security')
    expect(en.strings['settings.cat.access']).toBe('Access & automation')
    expect(ro.strings['settings.cat.account']).toBe('Cont și securitate')
    expect(ro.strings['settings.cat.policy']).toBe('Politici de securitate')
    for (const c of SETTINGS_CATS) {
      for (const strings of [en.strings, ro.strings]) {
        expect(strings[c.labelKey].split(/\s+/).length, c.labelKey).toBeLessThanOrEqual(3)
        expect(strings[c.labelKey].length, c.labelKey).toBeLessThanOrEqual(22)
      }
    }
  })
})

describe('settings index: id-uri vechi şi linkuri adânci (nu se rup niciodată)', () => {
  // id-urile de dinainte de 3.7.1: persistate în localStorage (wt_settings_last), sessionStorage
  // (revenirea din step-up SSO) şi în ţintele linkurilor adânci
  const OLD: Record<string, SettingsCat> = {
    cont: 'cont', sanatate: 'sanatate', utilizatori: 'utilizatori', autentificare: 'cont', infrastructura: 'acces',
    audit: 'audit', aspect: 'aspect', notificari: 'notificari', backup: 'backup', preferinte: 'preferinte',
  }
  it.each(Object.entries(OLD))('id-ul vechi %s rămâne valid (→ %s)', (old, now) => {
    expect(resolveCat(old)).toBe(now)
    expect(resolveSettingsTarget({ cat: old })).toEqual({ cat: now })
  })
  it('alias-urile duc doar la categorii existente şi nu umbresc un id curent', () => {
    for (const [old, now] of Object.entries(LEGACY_CATS)) {
      expect(SETTINGS_CATS.some((c) => c.id === now), old).toBe(true)
      expect(SETTINGS_CATS.some((c) => c.id === old), old).toBe(false)
    }
  })
  it('cu secţiune, categoria e cea care o randează acum — indiferent de categoria cerută', () => {
    expect(resolveSettingsTarget({ cat: 'autentificare', section: 'totp' })).toEqual({ cat: 'cont', section: 'totp' })
    expect(resolveSettingsTarget({ cat: 'infrastructura', section: 'guardrail' })).toEqual({ cat: 'politici', section: 'guardrail' })
    expect(resolveSettingsTarget({ cat: 'infrastructura', section: 'certificates' })).toEqual({ cat: 'retea', section: 'certificates' })
    expect(resolveSettingsTarget({ cat: 'notificari', section: 'smtp' })).toEqual({ cat: 'alerte', section: 'smtp' })
    expect(resolveSettingsTarget({ cat: 'preferinte', section: 'appUpdate' })).toEqual({ cat: 'actualizari', section: 'appUpdate' })
    expect(resolveSettingsTarget({ cat: 'preferinte', section: 'taskNotify' })).toEqual({ cat: 'notificari', section: 'taskNotify' })
    expect(resolveSettingsTarget({ cat: 'aspect', section: 'watermark' })).toEqual({ cat: 'politici', section: 'watermark' })
    expect(resolveSettingsTarget({ cat: 'utilizatori', section: 'myAccess' })).toEqual({ cat: 'cont', section: 'myAccess' })
    expect(resolveSettingsTarget({ section: 'passkeys' })).toEqual({ cat: 'cont', section: 'passkeys' })
  })
  it('ţinte de nerecunoscut → undefined (apelantul cade pe implicit), fără excepţii', () => {
    for (const bad of [null, undefined, 'cont', 42, {}, { cat: 'xyz' }, { cat: '__proto__' }, { cat: 'toString' },
      { cat: 'constructor', section: 'nope' }]) {
      expect(resolveSettingsTarget(bad), JSON.stringify(bad)).toBeUndefined()
    }
    expect(resolveCat('hasOwnProperty')).toBeUndefined()
    // secţiune necunoscută + categorie validă → doar categoria
    expect(resolveSettingsTarget({ cat: 'autentificare', section: 'gone' })).toEqual({ cat: 'cont' })
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
    const r = ids('automation')
    for (const id of ['tokens', 'enrollGroups', 'signingKey']) expect(r).toContain(id)
    const p = ids('security policy')
    for (const id of ['guardrail', 'deployKeyPolicy', 'watermark']) expect(p).toContain(id)
    expect(ids('livrarea alertelor', tRo)).toEqual(expect.arrayContaining(['smtp', 'webhook', 'resourceAlerts']))
  })

  it('nimic → listă goală', () => {
    expect(ids('qwertyuiop')).toEqual([])
  })

  // 3.7.1 (audit UX Setări M5): ce tastează oamenii şi nu găseau
  it.each(['mTLS', 'client certificate', 'token only', 'handshake', 'refused'])('„%s" găseşte agenţii conectaţi / conexiunile refuzate', (q) => {
    for (const t of [tEn, tRo]) {
      const r = ids(q, t)
      expect(r.some((id) => id === 'connectedAgents' || id === 'edgeRefusals'), q).toBe(true)
      expect(r[0] === 'connectedAgents' || r[0] === 'edgeRefusals', `${q}: ${r[0]}`).toBe(true)
    }
  })
  it('mTLS găseşte ambele blocuri; refused / handshake duc întâi la conexiunile refuzate', () => {
    expect(ids('mtls')).toEqual(expect.arrayContaining(['connectedAgents', 'edgeRefusals']))
    expect(ids('refused')[0]).toBe('edgeRefusals')
    expect(ids('handshake')[0]).toBe('edgeRefusals')
    expect(ids('connected agents')[0]).toBe('connectedAgents')
    expect(ids('agenti conectati', tRo)[0]).toBe('connectedAgents')
    expect(ids('conexiuni refuzate', tRo)[0]).toBe('edgeRefusals')
    expect(ids('certificat client', tRo)).toEqual(expect.arrayContaining(['connectedAgents', 'edgeRefusals']))
  })
  it('„email alerts" găseşte Alert events şi SMTP (en şi ro)', () => {
    for (const [q, t] of [['email alerts', tEn], ['email alerts', tRo], ['alerte email', tRo], ['alerte pe email', tRo],
      ['alerte email', tEn], ['alerte pe email', tEn]] as const) {
      expect(ids(q, t), `${q}`).toEqual(expect.arrayContaining(['alertPrefs', 'smtp']))
    }
  })
  it('potrivire pe prefix şi pe forma flexionată, fiecare cuvânt tot obligatoriu', () => {
    expect(ids('alert')).toContain('alertPrefs')
    expect(ids('alerts')).toContain('alertPrefs')
    expect(ids('cert')[0]).toBe('certificates')
    expect(ids('certificates')).toContain('certificates')
    expect(ids('webh')[0]).toBe('webhook')
    expect(ids('alerts xyzzy')).toEqual([])
    // o literă în plus nu face din orice cuvânt scurt o potrivire
    expect(ids('pe')).not.toContain('timezone')
  })
  it('căutarea în română e fără diacritice în ambele sensuri', () => {
    expect(ids('alerte', tRo)).toContain('alertPrefs')
    expect(ids('notificări', tRo)).toContain('alertPrefs')
    expect(ids('notificari', tRo)).toContain('alertPrefs')
  })

  it('groupHits grupează pe tab (categoriile noi), în ordinea celui mai bun rezultat', () => {
    const groups = groupHits(searchSettings('alert', tEn))
    expect(groups[0].cat).toBe('notificari')
    expect(groups.map((g) => g.cat)).toContain('alerte')
    expect(new Set(groups.map((g) => g.cat)).size).toBe(groups.length)
    expect(groups.flatMap((g) => g.hits).length).toBe(searchSettings('alert', tEn).length)
  })
})

describe('settings index: roluri (3.6) — ce vede un cont fără permisiuni globale', () => {
  const none = () => false
  const all = () => true
  it('Owner (toate permisiunile): toate tab-urile şi toate secţiunile', () => {
    expect(visibleCats(all).map((c) => c.id)).toEqual(SETTINGS_CATS.map((c) => c.id))
    for (const s of SETTINGS_INDEX) expect(sectionVisible(s.id, all)).toBe(true)
  })
  it('fără permisiuni globale (Viewer): doar Personal + Audit; Administrarea dispare cu totul', () => {
    const ids = visibleCats(none).map((c) => c.id)
    expect(ids).toEqual(['cont', 'aspect', 'preferinte', 'notificari', 'audit'])
    expect(visibleGroups(none).map((g) => g.id)).toEqual(['personal', 'ops'])
    expect(sectionVisible('myAccess', none)).toBe(true)
    expect(sectionVisible('users', none)).toBe(false)
    expect(sectionVisible('smtp', none)).toBe(false)
    expect(sectionVisible('alertPrefs', none)).toBe(true)
    // 3.6.6: tab-ul Roles se vede şi doar cu users.manage (citire) — căutarea trebuie să-l găsească
    expect(sectionVisible('roles', (p) => p === 'users.manage')).toBe(true)
    expect(sectionVisible('roles', (p) => p === 'roles.manage')).toBe(true)
    expect(sectionVisible('roles', none)).toBe(false)
    // audit 3.6.3 #3: maparea SSO nu apare în căutare cu SSO oprit (tab-ul n-o randează)
    expect(sectionVisible('ssoMapping', all, { sso: false })).toBe(false)
    expect(sectionVisible('ssoMapping', all, { sso: true })).toBe(true)
    expect(sectionVisible('ssoMapping', all)).toBe(true)   // necunoscut → vizibilă (tab-ul arată eroarea)
  })
  it('secţiunile cu permisiune folosesc doar id-uri din catalogul global', () => {
    const GLOBAL = ['hosts.create', 'hosts.export', 'settings.manage', 'users.manage', 'roles.manage', 'tokens.create',
      'tokens.manage', 'shares.manage', 'snippets.manage', 'history.clear', 'audit.view', 'security.view',
      'backups.manage', 'signing.manage']
    for (const s of SETTINGS_INDEX) if (s.perm) for (const p of [s.perm].flat()) expect(GLOBAL, s.id).toContain(p)
  })
  // ce vede fiecare rol nu s-a schimbat la regruparea din 3.7.1 — doar unde stă (auditul UX Setări §2.1)
  const ROLE_PERMS: Record<string, string[]> = {
    admin: ['hosts.create', 'hosts.export', 'settings.manage', 'users.manage', 'roles.manage', 'tokens.create',
      'tokens.manage', 'shares.manage', 'snippets.manage', 'audit.view', 'security.view'],   // authz._ADMIN
    operator: ['tokens.create'],
    viewer: [],
  }
  const asRole = (r: string) => (p: string) => ROLE_PERMS[r].includes(p)
  const visibleSections = (has: (p: string) => boolean) => SETTINGS_INDEX.filter((s) => sectionVisible(s.id, has)).map((s) => s.id).sort()
  it('Admin: totul în afară de Backup şi cheia de semnare', () => {
    const cats = visibleCats(asRole('admin')).map((c) => c.id)
    expect(cats).not.toContain('backup')
    expect(cats).toEqual(expect.arrayContaining(['utilizatori', 'acces', 'politici', 'retea', 'alerte', 'actualizari', 'sanatate']))
    expect(visibleSections(asRole('admin'))).toEqual(SETTINGS_INDEX
      .filter((s) => !s.id.startsWith('backup') && s.id !== 'signingKey').map((s) => s.id).sort())
    expect(visibleGroups(asRole('admin')).map((g) => g.id)).toEqual(['personal', 'admin', 'ops'])
  })
  it('Operator: Personal + Access & automation (doar token-urile lui) + Audit', () => {
    expect(visibleCats(asRole('operator')).map((c) => c.id)).toEqual(['cont', 'aspect', 'preferinte', 'notificari', 'acces', 'audit'])
    const sec = visibleSections(asRole('operator'))
    expect(sec).toContain('tokens')
    for (const id of ['signingKey', 'enrollGroups', 'guardrail', 'users', 'smtp', 'appUpdate']) expect(sec).not.toContain(id)
    // secţiunile personale sunt toate acolo, inclusiv accesul propriu şi notificările de task
    for (const id of ['account', 'devices', 'passkeys', 'totp', 'myAccess', 'alertPrefs', 'taskNotify', 'timezone', 'audit']) {
      expect(sec).toContain(id)
    }
  })
  it('Viewer: aceleaşi secţiuni personale ca înainte de regrupare', () => {
    expect(visibleSections(asRole('viewer'))).toEqual(SETTINGS_INDEX.filter((s) => !s.perm).map((s) => s.id).sort())
    expect(visibleSections(asRole('viewer'))).toEqual(['accessibility', 'account', 'alertPrefs', 'audit', 'devices', 'language',
      'myAccess', 'passkeys', 'taskNotify', 'termColors', 'terminal', 'theme', 'themeMode', 'timezone', 'tips', 'totp',
      'transfers', 'updatesBadge', 'walkthrough'])
  })
  it('„Your access" e găsit după rol / permisiune', () => {
    expect(ids('roles')).toContain('myAccess')
    expect(ids('roluri', tRo)).toContain('myAccess')
  })
})
