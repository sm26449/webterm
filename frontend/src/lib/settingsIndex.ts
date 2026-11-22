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
    `securitate` a fost spart în `autentificare` + `infrastructura` (3.5.9); în 3.7.1 (auditul UX
    Setări, varianta minimă) categoriile s-au regrupat după intenţie: `autentificare` s-a unit cu
    `cont`, iar `infrastructura` s-a spart în `acces` + `politici` + `retea`. Id-urile vechi rămân
    valide PENTRU TOTDEAUNA prin `LEGACY_CATS` (sunt persistate: sessionStorage la revenirea din
    step-up SSO, localStorage „ultima categorie", linkuri adânci). */
export type SettingsCat =
  | 'cont' | 'aspect' | 'preferinte' | 'notificari'
  | 'utilizatori' | 'acces' | 'politici' | 'retea' | 'alerte' | 'backup' | 'actualizari'
  | 'sanatate' | 'audit'

/** Grupurile rail-ului: „al cui e lucrul ăsta?" înainte de „ce e?" (audit UX Setări §2.3). */
export type SettingsGroup = 'personal' | 'admin' | 'ops'
export const SETTINGS_GROUPS: readonly { id: SettingsGroup; labelKey: string }[] = [
  { id: 'personal', labelKey: 'settings.group.personal' },
  { id: 'admin', labelKey: 'settings.group.admin' },
  { id: 'ops', labelKey: 'settings.group.ops' },
]

/** ordinea din rail-ul modalului (în cadrul grupului) */
export const SETTINGS_CATS: readonly { id: SettingsCat; labelKey: string; group: SettingsGroup }[] = [
  // ── Personal: oricine, doar despre contul şi browserul tău ──
  { id: 'cont', labelKey: 'settings.cat.account', group: 'personal' },
  { id: 'aspect', labelKey: 'settings.cat.appearance', group: 'personal' },
  { id: 'preferinte', labelKey: 'settings.cat.preferences', group: 'personal' },
  { id: 'notificari', labelKey: 'settings.cat.notifications', group: 'personal' },
  // ── Administrare: setări ale instanţei, ascunse fără permisiune ──
  { id: 'utilizatori', labelKey: 'settings.cat.users', group: 'admin' },
  { id: 'acces', labelKey: 'settings.cat.access', group: 'admin' },
  { id: 'politici', labelKey: 'settings.cat.policy', group: 'admin' },
  { id: 'retea', labelKey: 'settings.cat.network', group: 'admin' },
  { id: 'alerte', labelKey: 'settings.cat.alertDelivery', group: 'admin' },
  { id: 'backup', labelKey: 'settings.cat.backup', group: 'admin' },
  { id: 'actualizari', labelKey: 'settings.cat.updates', group: 'admin' },
  // ── Operare: ce se întâmplă acum (3.6.8: System health) ──
  { id: 'sanatate', labelKey: 'settings.cat.health', group: 'ops' },
  { id: 'audit', labelKey: 'settings.cat.audit', group: 'ops' },
]

/** Id-uri de categorie retrase → categoria care le-a preluat. Doar adăugări aici, niciodată
    ştergeri: un id vechi poate sta luni de zile în localStorage sau într-un link salvat. */
export const LEGACY_CATS: Readonly<Record<string, SettingsCat>> = {
  autentificare: 'cont',        // 3.7.1: „Sign-in & 2FA" s-a unit cu Account → „Account & security"
  infrastructura: 'acces',      // 3.7.1: „Infrastructure & tokens" → Access & automation (+ Security policy, Network)
  securitate: 'cont',           // înainte de 3.5.9 (spart atunci în autentificare + infrastructura)
}

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
      refuză oricum). Lipsă = secţiune self-service, vizibilă oricui. Listă = ajunge ORICARE
      (ex. rolurile custom: tab-ul Roles se vede şi doar cu `users.manage`, citire). */
  perm?: string | string[]
  /** condiţia de RUNTIME fără de care tab-ul nu randează secţiunea (ex. maparea SSO doar cu SSO
      activ). Căutarea n-are voie să găsească o secţiune pe care tab-ul o ascunde — Enter nu ducea
      nicăieri (audit funcţional 3.6.3, #3). */
  requires?: RuntimeFlag
}

/** Stări ale instanţei cunoscute abia la rulare; `false` = sigur oprit, lipsă = necunoscut (vizibil). */
export type RuntimeFlag = 'sso'
export type RuntimeFlags = Partial<Record<RuntimeFlag, boolean>>

export const SETTINGS_INDEX: readonly SettingSection[] = [
  // ── Cont şi securitate (3.7.1: Account + Sign-in & 2FA + „Your access") ──
  { id: 'account', cat: 'cont', titleKey: 'settings.account',
    keywords: 'email password change parola schimba profile profil' },
  { id: 'devices', cat: 'cont', titleKey: 'settings.devices', hintKey: 'settings.devicesHint',
    keywords: 'devices sessions browsers sign out logout revoke dispozitive sesiuni deconectare' },
  { id: 'passkeys', cat: 'cont', titleKey: 'settings.passkeys', hintKey: 'settings.passkeysAvailable',
    keywords: 'passkey webauthn fido yubikey security key hardware fingerprint face id touch id cheie amprenta' },
  { id: 'totp', cat: 'cont', titleKey: 'settings.totp.title', hintKey: 'settings.totp.hint',
    keywords: '2fa mfa otp totp authenticator recovery codes doi pasi coduri recuperare' },
  { id: 'myAccess', cat: 'cont', titleKey: 'roles.myAccess', hintKey: 'roles.myAccessHint',
    keywords: 'role roles access permissions owner admin operator viewer scope rol roluri acces permisiuni' },
  // ── Aspect ──
  { id: 'language', cat: 'aspect', titleKey: 'settings.language', hintKey: 'settings.languageHint',
    keywords: 'language english romanian locale limba engleza romana' },
  { id: 'theme', cat: 'aspect', titleKey: 'settings.theme', hintKey: 'theme.styleHint',
    keywords: 'theme style look appearance midnight aurora macos mac apple windows win11 fluent mica '
      + 'gnome adwaita libadwaita linux ubuntu vibrancy kde plasma breeze kubuntu tema stil aspect' },
  { id: 'themeMode', cat: 'aspect', titleKey: 'theme.mode',
    keywords: 'dark light mode auto system night day appearance mod intunecat luminos noapte zi sistem' },
  { id: 'termColors', cat: 'aspect', titleKey: 'settings.termColors',
    keywords: 'terminal colors color scheme palette iterm vscode import culori schema paleta' },
  // ── Terminal şi spaţiu de lucru (fostele Preferinţe) ──
  { id: 'timezone', cat: 'preferinte', titleKey: 'settings.timezone',
    keywords: 'timezone tz time clock utc fus orar ora ceas' },
  { id: 'accessibility', cat: 'preferinte', titleKey: 'settings.accessibility', hintKey: 'settings.screenReaderMode',
    keywords: 'accessibility a11y screen reader nvda voiceover orca accesibilitate cititor ecran' },
  { id: 'walkthrough', cat: 'preferinte', titleKey: 'walkthrough.settingsTitle',
    keywords: 'walkthrough tour welcome onboarding tur bun venit' },
  { id: 'tips', cat: 'preferinte', titleKey: 'tips.resetTitle', hintKey: 'tips.resetDesc',
    keywords: 'tips hints reset sfaturi indicii' },
  { id: 'askNewSession', cat: 'preferinte', titleKey: 'settings.askNewSessionTitle', hintKey: 'settings.askNewSession',
    keywords: 'new session ask launcher reuse continue existing open sessions sesiune noua intreaba refoloseste continua deschise' },
  { id: 'terminal', cat: 'preferinte', titleKey: 'settings.terminal',
    keywords: 'terminal unicode emoji wide characters xterm caractere late' },
  { id: 'transfers', cat: 'preferinte', titleKey: 'transfers.settingsTitle', hintKey: 'transfers.pasteDestHint',
    keywords: 'transfers upload paste inbox images files transferuri incarcare lipire fisiere' },
  { id: 'updatesBadge', cat: 'preferinte', titleKey: 'updates.prefTitle', hintKey: 'updates.prefDesc',
    keywords: 'os updates badge apt dnf packages actualizari insigna pachete' },
  // ── Notificările mele ──
  { id: 'alertPrefs', cat: 'notificari', titleKey: 'settings.alertPrefs.title', hintKey: 'settings.alertPrefs.hint',
    keywords: 'alert alerts events notifications bell history in-app email emails mail toggle mute security which choose '
      + 'clopotel istoric evenimente notificari alerte alerta pe email mail aleg ce primesc' },
  { id: 'taskNotify', cat: 'notificari', titleKey: 'settings.taskNotify', hintKey: 'settings.taskNotifyHint',
    keywords: 'notifications task done finished failed command agent push notificari task terminat esuat comanda agent' },
  // ── Oameni şi roluri (3.6) ──
  { id: 'users', cat: 'utilizatori', titleKey: 'settings.users.title', hintKey: 'settings.users.hint',
    keywords: 'users accounts people team invite admin bindings utilizatori conturi echipa oameni legaturi',
    perm: 'users.manage' },
  { id: 'roles', cat: 'utilizatori', titleKey: 'roles.custom.title', hintKey: 'roles.custom.hint',
    keywords: 'custom roles permissions editor role create edit auditor files-only roluri custom permisiuni editor',
    perm: ['roles.manage', 'users.manage'] },
  { id: 'ssoMapping', cat: 'utilizatori', titleKey: 'roles.sso.title', hintKey: 'roles.sso.hint',
    keywords: 'sso oidc authentik groups claim mapping group role idp grupuri mapare grup scim provisioning deprovisioning provizionare token',
    perm: 'users.manage', requires: 'sso' },
  // ── Acces şi automatizare ──
  { id: 'signingKey', cat: 'acces', titleKey: 'settings.signingKey',
    keywords: 'signing key ed25519 agent update signature pem encrypted download export semnare cheie semnatura criptata descarca', perm: 'signing.manage' },
  { id: 'tokens', cat: 'acces', titleKey: 'settings.tokens.title', hintKey: 'settings.tokens.hint',
    keywords: 'token api bearer cron ci automation script monitoring tokenuri automatizare', perm: 'tokens.create' },
  { id: 'enrollGroups', cat: 'acces', titleKey: 'settings.enrollGroups.title', hintKey: 'settings.enrollGroups.hint',
    keywords: 'bulk enrollment group token onboarding fleet many machines inrolare masa grup flota', perm: 'hosts.create' },
  // ── Politici de securitate ──
  { id: 'guardrail', cat: 'politici', titleKey: 'settings.guardrail', hintKey: 'settings.guardrailHint',
    keywords: 'guardrail dangerous commands block confirm regex rm -rf rules comenzi periculoase reguli blocare', perm: 'settings.manage' },
  { id: 'deployKeyPolicy', cat: 'politici', titleKey: 'settings.dkpolicy.title', hintKey: 'settings.dkpolicy.hint',
    keywords: 'deploy key ssh policy restrict host to host chei politica', perm: 'settings.manage' },
  { id: 'idleSessions', cat: 'politici', titleKey: 'settings.idle.title', hintKey: 'settings.idle.desc',
    keywords: 'idle inactive stale unused abandoned sessions notify notice keep open '
      + 'inactiv inactive nefolosite sesiuni notificare anunt pastreaza deschisa', perm: 'settings.manage' },
  { id: 'watermark', cat: 'politici', titleKey: 'settings.watermark', hintKey: 'settings.watermarkHint',
    keywords: 'watermark screenshot traceability filigran captura', perm: 'settings.manage' },
  // ── Reţea şi certificate ──
  { id: 'certificates', cat: 'retea', titleKey: 'settings.certs.title',
    keywords: 'tls ssl https certificate certificates cert expiry expires renew renewal lets encrypt acme traefik wildcard dns-01 http-01 '
      + 'certificat certificate expirare expira reinnoire reinnoieste', perm: 'settings.manage' },
  { id: 'forwardDomain', cat: 'retea', titleKey: 'settings.forward.title',
    keywords: 'port forwarding domain dns wildcard certificate tls subdomain domeniu certificat', perm: 'settings.manage' },
  // ── Livrarea alertelor (instanţă) ──
  { id: 'smtp', cat: 'alerte', titleKey: 'settings.smtp.title', hintKey: 'settings.smtp.hint',
    keywords: 'smtp email mail alert alerts notification notifications server outgoing alerte notificari pe email posta server', perm: 'settings.manage' },
  { id: 'webhook', cat: 'alerte', titleKey: 'settings.smtp.webhook', hintKey: 'settings.smtp.webhookHint',
    keywords: 'webhook slack discord teams ntfy chat alerts alerte', perm: 'settings.manage' },
  { id: 'resourceAlerts', cat: 'alerte', titleKey: 'settings.alerts.title', hintKey: 'settings.alerts.hint',
    keywords: 'cpu ram memory disk threshold load alerts prag memorie resurse', perm: 'settings.manage' },
  // ── Backup ──
  { id: 'backupDownload', cat: 'backup', titleKey: 'settings.backup.downloadTitle',
    keywords: 'backup download export archive copie descarca arhiva', perm: 'backups.manage' },
  { id: 'backupAuto', cat: 'backup', titleKey: 'settings.backup.autoTitle',
    keywords: 'automatic scheduled backup snapshot retention automat programat', perm: 'backups.manage' },
  { id: 'backupCloud', cat: 'backup', titleKey: 'settings.cloud.title', hintKey: 'settings.cloud.hint',
    keywords: 'cloud google drive dropbox offsite off-host external destination destinatie externa', perm: 'backups.manage' },
  { id: 'backupRestore', cat: 'backup', titleKey: 'settings.backup.restoreTitle',
    keywords: 'restore import recover restaurare recuperare', perm: 'backups.manage' },
  // ── Actualizări ──
  { id: 'appUpdate', cat: 'actualizari', titleKey: 'settings.update.title', hintKey: 'settings.update.hint',
    keywords: 'version update new release github versiune actualizare', perm: 'settings.manage' },
  // ── Sănătatea sistemului (3.6.8) ──
  { id: 'systemHealth', cat: 'sanatate', titleKey: 'health.title', hintKey: 'health.hint',
    keywords: 'system health status problems attention checks alerts timer backup cloudflare token authentik disk '
      + 'sso clock heartbeat dead man switch cleanup docker janitor database vacuum '
      + 'sanatate sistem probleme verificari atentie ceas disc curatare baza de date', perm: 'security.view' },
  // 3.7.1 (audit UX Setări M5): sub-blocurile din Health au intrări proprii — „mTLS" dădea 0 rezultate
  { id: 'edgeRefusals', cat: 'sanatate', titleKey: 'health.edge.title',
    keywords: 'refused rejected blocked connections handshake handshakes mtls client certificate token only sign-ins login failures '
      + 'traefik allow deny list ip episodes brute force '
      + 'refuzate respinse blocate conexiuni autentificari esuate certificat client lista adrese', perm: 'security.view' },
  { id: 'connectedAgents', cat: 'sanatate', titleKey: 'health.agents.title', hintKey: 'health.agents.hint',
    keywords: 'connected agents online offline mtls client certificate token only route version fleet connection log '
      + 'agenti conectati certificat client ruta versiune flota jurnal conexiune', perm: 'security.view' },
  // ── Audit ──
  { id: 'audit', cat: 'audit', titleKey: 'settings.audit.title', hintKey: 'settings.audit.hint',
    keywords: 'audit log history who did what activity my actions instance jurnal istoric activitatea mea instanta' },
]

const BY_ID = new Map(SETTINGS_INDEX.map((s) => [s.id, s]))

/** Secţiunea e vizibilă contului? `has` = verificarea permisiunii globale (lib/perms `can`). */
export function sectionVisible(id: string, has: (perm: string) => boolean, runtime: RuntimeFlags = {}): boolean {
  const s = BY_ID.get(id)
  if (s?.requires && runtime[s.requires] === false) return false
  if (!s?.perm) return true
  return (Array.isArray(s.perm) ? s.perm : [s.perm]).some(has)
}

/** Tab-urile cu MĂCAR o secţiune vizibilă (un tab gol nu apare în rail). */
export function visibleCats(has: (perm: string) => boolean): readonly { id: SettingsCat; labelKey: string; group: SettingsGroup }[] {
  return SETTINGS_CATS.filter((c) => SETTINGS_INDEX.some((s) => s.cat === c.id && sectionVisible(s.id, has)))
}

/** Rail-ul pe grupuri: un grup apare doar cu măcar o categorie vizibilă (Viewer: doar „Personal"
    şi „Operare" → Audit, cu rândurile proprii). */
export function visibleGroups(has: (perm: string) => boolean) {
  const cats = visibleCats(has)
  return SETTINGS_GROUPS
    .map((g) => ({ ...g, cats: cats.filter((c) => c.group === g.id) }))
    .filter((g) => g.cats.length > 0)
}

/** tab-ul unei secţiuni (undefined = id necunoscut) */
export function catOfSection(id: string): SettingsCat | undefined {
  return BY_ID.get(id)?.cat
}

/** Un id de categorie venit din afară (localStorage, sessionStorage, catalogul de Health, un link
    adânc): id-ul curent, id-ul care a preluat un id retras (`LEGACY_CATS`), sau undefined. */
export function resolveCat(v: unknown): SettingsCat | undefined {
  if (typeof v !== 'string' || !v) return undefined
  if (SETTINGS_CATS.some((c) => c.id === v)) return v as SettingsCat
  return Object.prototype.hasOwnProperty.call(LEGACY_CATS, v) ? LEGACY_CATS[v] : undefined
}

/** Normalizează o ţintă de Setări venită din afară. Cu o secţiune cunoscută, categoria e cea care
    o randează ACUM (indexul e singura sursă: o secţiune mutată între categorii nu rupe linkurile
    vechi de tip `{cat:'infrastructura', section:'guardrail'}`); fără secţiune, id-ul (eventual vechi)
    al categoriei. O ţintă de nerecunoscut → undefined (apelantul cade pe implicit). */
export function resolveSettingsTarget(raw: unknown): SettingsTarget | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const { cat, section } = raw as { cat?: unknown; section?: unknown }
  const known = typeof section === 'string' ? BY_ID.get(section) : undefined
  if (known) return { cat: known.cat, section: known.id }
  const c = resolveCat(cat)
  return c ? { cat: c } : undefined
}

/** litere mici, fără diacritice (ă→a, ș/ş→s): aceeaşi regulă ca în CommandPalette */
export const fold = (s: string) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()

export interface SettingHit {
  section: SettingSection
  title: string
  hint: string
  score: number
}

/** Potrivirea unui cuvânt din întrebare într-un text deja „împăturit" (fold):
    3 = un cuvânt din text ÎNCEPE cu el („alert" → „alerts", „cert" → „certificate");
    2 = o formă flexionată: un cuvânt din text (≥ 4 litere) e începutul lui, cu cel mult 3 litere în
        plus („alerts"/„alerte"/„alertele" → „alert", „certificates" → „certificate");
    1 = apare în interiorul unui cuvânt („key" în „passkey") — păstrat de dinainte, cu scor mic;
    0 = nicăieri. */
function matchWord(txt: string, w: string): number {
  if (!txt) return 0
  let best = 0
  for (const tok of txt.split(/[^a-z0-9]+/)) {
    if (!tok) continue
    if (tok.startsWith(w)) return 3
    if (best < 2 && tok.length >= 4 && w.startsWith(tok) && w.length - tok.length <= 3) best = 2
  }
  if (best) return best
  return txt.includes(w) ? 1 : 0
}

/** Caută în index. Fiecare cuvânt din întrebare trebuie să se potrivească undeva (titlu,
    cuvinte-cheie, numele tab-ului, textul explicativ), pe PREFIX de cuvânt sau formă flexionată
    (3.7.1, auditul UX Setări M5: „email alerts" nu găsea „Alert events", fiindcă „alerts" nu era
    scris nicăieri). Scorul favorizează titlul, apoi cuvintele-cheie. Nu e potrivire „fuzzy" pe
    subsecvenţe ca în paletă: pe texte lungi (hint-urile) aceea găseşte orice. */
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
      const mt = matchWord(ft, w), mk = matchWord(fk, w)
      if (mt === 3) score += 40
      else if (mt === 2) score += 35
      else if (mt === 1) score += 30
      else if (mk === 3) score += 20
      else if (mk === 2) score += 18
      else if (mk === 1) score += 15
      else if (matchWord(fc, w)) score += 10
      else if (matchWord(fh, w)) score += 5
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
