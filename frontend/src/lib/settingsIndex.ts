/* Indexul căutării din Setări (3.5.9) — o singură sursă pentru „ce secţiuni există, pe ce tab
   stau şi după ce cuvinte le găseşti".

   Fiecare intrare e o SECŢIUNE a unui tab, nu un câmp: titlul şi textul explicativ vin din
   catalogul i18n (deci căutarea merge în limba interfeţei), iar `keywords` e o listă explicită,
   în engleză ŞI română, cu sinonimele pe care omul chiar le tastează („webhook slack",
   „fus orar", „yubikey"). Potrivirea e fără diacritice (ca în CommandPalette): „setari" = „setări".

   Contractul cu UI-ul: secţiunea randată poartă `data-setting-id="<id>"` (în settings/*Tab.tsx).
   settingsIndex.test.ts pică dacă un id din index nu e randat de tab-ul declarat, sau dacă un tab
   randează un id care lipseşte din index — o secţiune nouă fără intrare aici e o regresie. */

/** id-urile tab-urilor din modalul de Setări (rămân în română, ca înainte de 3.5.9).
    `securitate` a fost spart în `autentificare` + `infrastructura`. */
export type SettingsCat =
  | 'cont' | 'utilizatori' | 'autentificare' | 'infrastructura' | 'audit' | 'aspect' | 'notificari' | 'backup' | 'preferinte'

/** ordinea din rail-ul modalului */
export const SETTINGS_CATS: readonly { id: SettingsCat; labelKey: string }[] = [
  { id: 'cont', labelKey: 'settings.cat.account' },
  { id: 'utilizatori', labelKey: 'settings.cat.users' },
  { id: 'autentificare', labelKey: 'settings.cat.signin' },
  { id: 'infrastructura', labelKey: 'settings.cat.infra' },
  { id: 'audit', labelKey: 'settings.cat.audit' },
  { id: 'aspect', labelKey: 'settings.cat.appearance' },
  { id: 'notificari', labelKey: 'settings.cat.notifications' },
  { id: 'backup', labelKey: 'settings.cat.backup' },
  { id: 'preferinte', labelKey: 'settings.cat.preferences' },
]

/** Un link adânc în Setări: tab-ul şi, opţional, secţiunea (derulată + evidenţiată la deschidere). */
export type SettingsTarget = { cat: SettingsCat; section?: string }

export interface SettingSection {
  id: string
  cat: SettingsCat
  titleKey: string
  hintKey?: string
  /** sinonime EN + RO, separate prin spaţiu; se caută împreună cu titlul şi textul tradus */
  keywords: string
  /** permisiunea GLOBALĂ fără de care secţiunea e ascunsă (3.6, roluri; cosmetic — serverul
      refuză oricum). Lipsă = secţiune self-service, vizibilă oricui. */
  perm?: string
}

export const SETTINGS_INDEX: readonly SettingSection[] = [
  // ── Cont ──
  { id: 'account', cat: 'cont', titleKey: 'settings.account',
    keywords: 'email password change parola schimba profile profil' },
  // ── Utilizatori şi roluri (3.6) ──
  { id: 'myAccess', cat: 'utilizatori', titleKey: 'roles.myAccess', hintKey: 'roles.myAccessHint',
    keywords: 'role roles access permissions owner admin operator viewer scope rol roluri acces permisiuni' },
  { id: 'users', cat: 'utilizatori', titleKey: 'settings.users.title', hintKey: 'settings.users.hint',
    keywords: 'users accounts people team invite admin bindings utilizatori conturi echipa oameni legaturi',
    perm: 'users.manage' },
  // ── Autentificare şi 2FA ──
  { id: 'devices', cat: 'autentificare', titleKey: 'settings.devices', hintKey: 'settings.devicesHint',
    keywords: 'devices sessions browsers sign out logout revoke dispozitive sesiuni deconectare' },
  { id: 'passkeys', cat: 'autentificare', titleKey: 'settings.passkeys', hintKey: 'settings.passkeysAvailable',
    keywords: 'passkey webauthn fido yubikey security key hardware fingerprint face id touch id cheie amprenta' },
  { id: 'totp', cat: 'autentificare', titleKey: 'settings.totp.title', hintKey: 'settings.totp.hint',
    keywords: '2fa mfa otp totp authenticator recovery codes doi pasi coduri recuperare' },
  // ── Infrastructură şi tokenuri ──
  { id: 'signingKey', cat: 'infrastructura', titleKey: 'settings.signingKey',
    keywords: 'signing key ed25519 agent update signature pem semnare cheie semnatura', perm: 'signing.manage' },
  { id: 'tokens', cat: 'infrastructura', titleKey: 'settings.tokens.title', hintKey: 'settings.tokens.hint',
    keywords: 'token api bearer cron ci automation script monitoring tokenuri automatizare', perm: 'tokens.create' },
  { id: 'enrollGroups', cat: 'infrastructura', titleKey: 'settings.enrollGroups.title', hintKey: 'settings.enrollGroups.hint',
    keywords: 'bulk enrollment group token onboarding fleet many machines inrolare masa grup flota', perm: 'hosts.create' },
  { id: 'deployKeyPolicy', cat: 'infrastructura', titleKey: 'settings.dkpolicy.title', hintKey: 'settings.dkpolicy.hint',
    keywords: 'deploy key ssh policy restrict host to host chei politica', perm: 'settings.manage' },
  { id: 'guardrail', cat: 'infrastructura', titleKey: 'settings.guardrail', hintKey: 'settings.guardrailHint',
    keywords: 'guardrail dangerous commands block confirm regex rm -rf rules comenzi periculoase reguli blocare', perm: 'settings.manage' },
  // ── Audit ──
  { id: 'audit', cat: 'audit', titleKey: 'settings.audit.title', hintKey: 'settings.audit.hint',
    keywords: 'audit log history who did what jurnal istoric' },
  // ── Aspect ──
  { id: 'language', cat: 'aspect', titleKey: 'settings.language', hintKey: 'settings.languageHint',
    keywords: 'language english romanian locale limba engleza romana' },
  { id: 'theme', cat: 'aspect', titleKey: 'settings.theme',
    keywords: 'theme dark light mode midnight aurora tema intunecat luminos' },
  { id: 'termColors', cat: 'aspect', titleKey: 'settings.termColors',
    keywords: 'terminal colors color scheme palette iterm vscode import culori schema paleta' },
  { id: 'watermark', cat: 'aspect', titleKey: 'settings.watermark', hintKey: 'settings.watermarkHint',
    keywords: 'watermark screenshot traceability filigran captura', perm: 'settings.manage' },
  // ── Notificări ──
  { id: 'forwardDomain', cat: 'notificari', titleKey: 'settings.forward.title',
    keywords: 'port forwarding domain dns wildcard certificate tls subdomain domeniu certificat', perm: 'settings.manage' },
  { id: 'smtp', cat: 'notificari', titleKey: 'settings.smtp.title', hintKey: 'settings.smtp.hint',
    keywords: 'smtp email mail alert notification alerte notificari', perm: 'settings.manage' },
  { id: 'webhook', cat: 'notificari', titleKey: 'settings.smtp.webhook', hintKey: 'settings.smtp.webhookHint',
    keywords: 'webhook slack discord teams ntfy chat alerts alerte', perm: 'settings.manage' },
  { id: 'resourceAlerts', cat: 'notificari', titleKey: 'settings.alerts.title', hintKey: 'settings.alerts.hint',
    keywords: 'cpu ram memory disk threshold load alerts prag memorie resurse', perm: 'settings.manage' },
  { id: 'alertPrefs', cat: 'notificari', titleKey: 'settings.alertPrefs.title', hintKey: 'settings.alertPrefs.hint',
    keywords: 'alert events notifications bell history in-app email toggle mute security clopotel istoric evenimente notificari alerte' },
  // ── Backup ──
  { id: 'backupDownload', cat: 'backup', titleKey: 'settings.backup.downloadTitle',
    keywords: 'backup download export archive copie descarca arhiva', perm: 'backups.manage' },
  { id: 'backupAuto', cat: 'backup', titleKey: 'settings.backup.autoTitle',
    keywords: 'automatic scheduled backup snapshot retention automat programat', perm: 'backups.manage' },
  { id: 'backupCloud', cat: 'backup', titleKey: 'settings.cloud.title', hintKey: 'settings.cloud.hint',
    keywords: 'cloud google drive dropbox offsite off-host', perm: 'backups.manage' },
  { id: 'backupRestore', cat: 'backup', titleKey: 'settings.backup.restoreTitle',
    keywords: 'restore import recover restaurare recuperare', perm: 'backups.manage' },
  // ── Preferinţe ──
  { id: 'timezone', cat: 'preferinte', titleKey: 'settings.timezone',
    keywords: 'timezone tz time clock utc fus orar ora ceas' },
  { id: 'accessibility', cat: 'preferinte', titleKey: 'settings.accessibility', hintKey: 'settings.screenReaderMode',
    keywords: 'accessibility a11y screen reader nvda voiceover orca accesibilitate cititor ecran' },
  { id: 'walkthrough', cat: 'preferinte', titleKey: 'walkthrough.settingsTitle',
    keywords: 'walkthrough tour welcome onboarding tur bun venit' },
  { id: 'tips', cat: 'preferinte', titleKey: 'tips.resetTitle', hintKey: 'tips.resetDesc',
    keywords: 'tips hints reset sfaturi indicii' },
  { id: 'terminal', cat: 'preferinte', titleKey: 'settings.terminal',
    keywords: 'terminal unicode emoji wide characters xterm caractere late' },
  { id: 'transfers', cat: 'preferinte', titleKey: 'transfers.settingsTitle', hintKey: 'transfers.pasteDestHint',
    keywords: 'transfers upload paste inbox images files transferuri incarcare lipire fisiere' },
  { id: 'updatesBadge', cat: 'preferinte', titleKey: 'updates.prefTitle', hintKey: 'updates.prefDesc',
    keywords: 'os updates badge apt dnf packages actualizari insigna pachete' },
  { id: 'appUpdate', cat: 'preferinte', titleKey: 'settings.update.title', hintKey: 'settings.update.hint',
    keywords: 'version update new release github versiune actualizare', perm: 'settings.manage' },
]

const BY_ID = new Map(SETTINGS_INDEX.map((s) => [s.id, s]))

/** Secţiunea e vizibilă contului? `has` = verificarea permisiunii globale (lib/perms `can`). */
export function sectionVisible(id: string, has: (perm: string) => boolean): boolean {
  const s = BY_ID.get(id)
  return !s?.perm || has(s.perm)
}

/** Tab-urile cu MĂCAR o secţiune vizibilă (un tab gol nu apare în rail). */
export function visibleCats(has: (perm: string) => boolean): readonly { id: SettingsCat; labelKey: string }[] {
  return SETTINGS_CATS.filter((c) => SETTINGS_INDEX.some((s) => s.cat === c.id && sectionVisible(s.id, has)))
}

/** tab-ul unei secţiuni (undefined = id necunoscut) */
export function catOfSection(id: string): SettingsCat | undefined {
  return BY_ID.get(id)?.cat
}

/** litere mici, fără diacritice (ă→a, ș/ş→s): aceeaşi regulă ca în CommandPalette */
export const fold = (s: string) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()

export interface SettingHit {
  section: SettingSection
  title: string
  hint: string
  score: number
}

/** Caută în index. Fiecare cuvânt din întrebare trebuie să apară undeva (titlu, cuvinte-cheie,
    numele tab-ului, textul explicativ); scorul favorizează titlul, apoi cuvintele-cheie. Nu e
    potrivire „fuzzy" pe subsecvenţe ca în paletă: pe texte lungi (hint-urile) aceea găseşte orice. */
export function searchSettings(query: string, t: (key: string) => string): SettingHit[] {
  const words = fold(query).split(/\s+/).filter(Boolean)
  if (words.length === 0) return []
  const catLabel = new Map(SETTINGS_CATS.map((c) => [c.id, fold(t(c.labelKey))]))
  const hits: SettingHit[] = []
  SETTINGS_INDEX.forEach((s, order) => {
    const title = t(s.titleKey)
    const hint = s.hintKey ? t(s.hintKey) : ''
    const ft = fold(title), fk = fold(s.keywords), fh = fold(hint), fc = catLabel.get(s.cat) ?? ''
    let score = 0
    for (const w of words) {
      const atWordStart = (txt: string) => txt.startsWith(w) || txt.includes(' ' + w)
      if (atWordStart(ft)) score += 40
      else if (ft.includes(w)) score += 30
      else if (atWordStart(fk)) score += 20
      else if (fk.includes(w)) score += 15
      else if (fc.includes(w)) score += 10
      else if (fh.includes(w)) score += 5
      else return   // un cuvânt negăsit = secţiunea nu se potriveşte
    }
    // la egalitate rămâne ordinea din index (= ordinea din UI)
    hits.push({ section: s, title, hint, score: score * 100 - order })
  })
  return hits.sort((a, b) => b.score - a.score)
}

/** Rezultatele grupate pe tab, în ordinea celui mai bun rezultat al fiecărui tab. */
export function groupHits(hits: SettingHit[]): { cat: SettingsCat; hits: SettingHit[] }[] {
  const groups: { cat: SettingsCat; hits: SettingHit[] }[] = []
  for (const h of hits) {
    const g = groups.find((x) => x.cat === h.section.cat)
    if (g) g.hits.push(h)
    else groups.push({ cat: h.section.cat, hits: [h] })
  }
  return groups
}
