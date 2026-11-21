import { KeyboardEvent, ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { groupHits, resolveSettingsTarget, searchSettings, sectionVisible, SETTINGS_CATS, SettingsCat, visibleGroups, type RuntimeFlags } from '../lib/settingsIndex'
import { api } from '../lib/api'
import { rememberSettingsCat } from '../lib/settingsLast'
import { escapeAction, initialPhoneScreen, railKeyTarget, railTabStop, settingsLayout, type PhoneScreen } from '../lib/settingsNav'
import { PHONE_QUERY, useMediaQuery } from '../lib/sheet'
import { can, usePerms } from '../lib/perms'
import AccountTab from './settings/AccountTab'
import SignInTab from './settings/SignInTab'
import MyAccessTab from './settings/MyAccessTab'
import AppearanceTab from './settings/AppearanceTab'
import PreferencesTab from './settings/PreferencesTab'
import MyNotificationsTab from './settings/MyNotificationsTab'
import UsersTab from './settings/UsersTab'
import AccessTab from './settings/AccessTab'
import SecurityPolicyTab from './settings/SecurityPolicyTab'
import NetworkTab from './settings/NetworkTab'
import AlertDeliveryTab from './settings/AlertDeliveryTab'
import BackupTab from './settings/BackupTab'
import UpdatesTab from './settings/UpdatesTab'
import HealthTab from './settings/HealthTab'
import AuditTab from './settings/AuditTab'
import { EmptyState, eyebrow, IconButton } from './ui'
import { ArrowLeftIcon, ChevronIcon, CloseIcon, SearchIcon } from './Icons'

/** ţinta e un câmp în care se scrie: acolo „/" e text, nu scurtătură */
const isTypingTarget = (el: EventTarget | null) =>
  el instanceof HTMLElement && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))

const prefersReducedMotion = () =>
  typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

/** Derulează secţiunea în vedere, îi mută focusul (cititorul de ecran ajunge unde a ajuns şi ochiul)
    şi o încadrează scurt (.wt-setting-flash, index.css: conturul se stinge; fără animaţie la
    prefers-reduced-motion, doar dispare după câteva secunde). */
/** Derulează DOAR panoul de conţinut până la secţiune. `scrollIntoView` derula şi strămoşii —
    inclusiv cadrul dialogului (overflow-hidden, dar tot derulabil programatic): deschis dintr-un
    link adânc (Dashboard → „Alert channels", Alerte → „Notification settings"), antetul cu căutarea
    şi × ieşeau din ecran (scrollTop≈57). Audit funcţional 3.6.3, #2. */
export function scrollWithin(container: HTMLElement, el: HTMLElement, smooth: boolean): void {
  const top = container.scrollTop + el.getBoundingClientRect().top - container.getBoundingClientRect().top - 12
  if (typeof container.scrollTo === 'function') container.scrollTo({ top: Math.max(0, top), behavior: smooth ? 'smooth' : 'auto' })
  else container.scrollTop = Math.max(0, top)
}

function flashSection(el: HTMLElement, container: HTMLElement | null) {
  if (container) scrollWithin(container, el, !prefersReducedMotion())
  if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1')
  el.focus({ preventScroll: true })
  el.classList.remove('wt-setting-flash')
  void el.offsetWidth   // reflow: re-porneşte animaţia dacă aceeaşi secţiune e aleasă de două ori
  el.classList.add('wt-setting-flash')
  window.setTimeout(() => el.classList.remove('wt-setting-flash'), 2400)
  // Un tab abia montat îşi încarcă datele după primul cadru (liste de dispozitive, token-uri…),
  // deci conţinutul de DEASUPRA secţiunii poate creşte şi o împinge în jos. O re-aliniem o dată.
  window.setTimeout(() => {
    if (!container || !el.isConnected) return
    const off = el.getBoundingClientRect().top - container.getBoundingClientRect().top
    if (Math.abs(off) > 32) scrollWithin(container, el, false)
  }, 450)
}

// Cadrul modalului de Setări: antet (cu căutarea), rail-ul de categorii şi dispecerizarea tab-ului
// activ. God-component-ul de odinioară a fost spart pe tab-uri în ./settings/*Tab.tsx — fiecare îşi
// ţine starea şi se încarcă singur la montare (= la deschiderea secţiunii). Aici nu trăieşte logica
// setărilor, doar navigarea: tab, căutare (lib/settingsIndex.ts) şi saltul la o secţiune.
export default function SettingsModal(props: {
  email: string | null
  webauthnAvailable: boolean
  initialCat?: SettingsCat
  /** secţiunea (data-setting-id) la care se sare la deschidere — link adânc din Dashboard/Sidebar */
  initialSection?: string
  onClose: () => void
  onAccountChanged: () => void   // refetch /api/state (refolosit și după salvarea watermark-ului)
  /** 3.7.1: ţinta a fost cerută explicit (link adânc, căutare, revenire după step-up) — pe telefon
      se deschide direct categoria; rotiţa simplă deschide lista categoriilor (lib/settingsNav) */
  explicitTarget?: boolean
  /** 3.6.8: câte verificări din System health cer atenţie (contorul de pe rail) */
  healthAttention?: number
}) {
  const { t } = useI18n()
  // 3.6: tab-urile/secţiunile pentru care contul n-are permisiunea globală nu apar (cosmetic —
  // serverul refuză oricum); un tab fără nicio secţiune vizibilă dispare din rail şi din căutare
  const perms = usePerms()
  const has = (p: string) => can(perms, p)
  const groups = visibleGroups(has)
  // categoria activă: modalul nu mai e un scroll lung — arată o secțiune odată. Cu o secţiune cerută,
  // tab-ul e cel care o randează ACUM (indexul ştie unde stă fiecare; 3.7.1 a mutat secţiuni între
  // tab-uri), iar un id de categorie retras trece prin LEGACY_CATS — vezi resolveSettingsTarget.
  const initial = resolveSettingsTarget({ cat: props.initialCat, section: props.initialSection })
  const firstCat: SettingsCat = initial?.cat ?? 'cont'
  const [cat, setCatRaw] = useState<SettingsCat>(firstCat)
  // Tab-urile VIZITATE rămân montate (ascunse cu `hidden`), ca o editare nesalvată să supravieţuiască
  // unei schimbări de categorie — înainte se monta doar tab-ul activ şi un formular pe jumătate
  // completat (SMTP, backup, parolă) dispărea tăcut la un click pe rail. Am ales asta în locul unui
  // avertisment „ai modificări nesalvate": acela ar cere fiecărui tab să-şi raporteze corect starea
  // „murdară" (risc de fals-pozitive/negative pe fiecare câmp); aici fiecare tab rămâne exact cum
  // era, se schimbă doar cadrul. Tab-urile nevizitate tot nu se montează (încărcare leneşă).
  const [visited, setVisited] = useState<Set<SettingsCat>>(() => new Set([firstCat]))
  const setCat = (c: SettingsCat) => { setCatRaw(c); setVisited((v) => (v.has(c) ? v : new Set(v).add(c))) }
  const pane = (c: SettingsCat, node: ReactNode) => visited.has(c) ? <div hidden={cat !== c}>{node}</div> : null
  // 3.7.1: rotiţa redeschide ultimul tab folosit (lib/settingsLast) — orice tab ajuns activ, din rail,
  // din căutare sau dintr-un link adânc, e „ultimul folosit"
  useEffect(() => { rememberSettingsCat(cat) }, [cat])
  // PWA (3.7.1-rc3, raportat): un element prea lat din Setări (sau scrollIntoView pe o secţiune) muta
  // pagina din spate pe orizontală, iar deplasarea rămânea şi după închidere. Pagina nu are niciodată
  // scroll orizontal legitim: o readucem la 0 la deschidere şi la închidere.
  useEffect(() => {
    const reset = () => { if (window.scrollX) window.scrollTo(0, window.scrollY) }
    reset()
    return reset
  }, [])

  // ── Căutarea ──
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const searching = query.trim() !== ''
  // telefon (sub `sm`): ecranul listei sau al categoriei — vezi mai jos, „Telefon: listă → categorie"
  const phone = useMediaQuery(PHONE_QUERY)
  const [screen, setScreen] = useState<PhoneScreen>(() => initialPhoneScreen(!!props.explicitTarget))
  // condiţiile de runtime ale secţiunilor (lib/settingsIndex `requires`): maparea SSO există doar cu
  // SSO activ. Necunoscut (încă se încarcă / a picat) = vizibilă — tab-ul îşi arată atunci eroarea.
  const [runtime, setRuntime] = useState<RuntimeFlags>({})
  const canUsers = has('users.manage')
  useEffect(() => {
    if (!canUsers) return
    api<{ enabled: boolean }>('/api/settings/oidc-roles')
      .then((r) => setRuntime((x) => ({ ...x, sso: !!r.enabled }))).catch(() => { /* necunoscut */ })
  }, [canUsers])
  const hits = useMemo(() => searchSettings(query, t).filter((h) => sectionVisible(h.section.id, (p) => can(perms, p), runtime)),
    [query, t, perms, runtime])
  const hitGroups = useMemo(() => groupHits(hits), [hits])
  const flat = useMemo(() => hitGroups.flatMap((g) => g.hits), [hitGroups])   // ordinea afişată = ordinea tastelor
  const listId = useId()
  const railId = useId()
  const optId = (i: number) => `${listId}-opt-${i}`
  const searchRef = useRef<HTMLInputElement>(null)
  const contentRef = useRef<HTMLDivElement>(null)

  // Saltul la o secţiune: aşteptăm cadrul în care tab-ul ei e montat ŞI vizibil (offsetParent).
  // `n` face ca alegerea aceleiaşi secţiuni de două ori să re-declanşeze efectul.
  const [jump, setJump] = useState<{ id: string; n: number } | null>(
    () => (initial?.section ? { id: initial.section, n: 0 } : null))
  useEffect(() => {
    if (!jump) return
    let raf = 0
    let tries = 0
    const go = () => {
      const el = contentRef.current?.querySelector<HTMLElement>(`[data-setting-id="${jump.id}"]`)
      if (!el || el.offsetParent === null) {
        if (tries++ < 30) raf = requestAnimationFrame(go)
        return
      }
      flashSection(el, contentRef.current)
    }
    go()
    return () => cancelAnimationFrame(raf)
  }, [jump])

  const pick = (i: number) => {
    const h = flat[i]
    if (!h) return
    setQuery('')
    setActive(0)
    setCat(h.section.cat)
    setScreen('cat')
    setJump((j) => ({ id: h.section.id, n: (j?.n ?? 0) + 1 }))
  }

  const onSearchKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(flat.length - 1, a + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)) }
    else if (e.key === 'Home' && searching) { e.preventDefault(); setActive(0) }
    else if (e.key === 'End' && searching) { e.preventDefault(); setActive(Math.max(0, flat.length - 1)) }
    else if (e.key === 'Enter') { e.preventDefault(); pick(active) }
    else if (e.key === 'Escape' && query) {
      // Escape goleşte întâi căutarea; abia al doilea Escape închide modalul (useFocusTrap ascultă
      // pe document, deci oprim propagarea doar când avem ce goli)
      e.preventDefault(); e.stopPropagation()
      setQuery(''); setActive(0)
    }
  }

  // opţiunea activă rămâne vizibilă când lista e mai lungă decât ecranul
  useEffect(() => {
    if (!searching) return
    document.getElementById(optId(active))?.scrollIntoView({ block: 'nearest' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, searching])

  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  // ── Telefon: listă → categorie (3.7.1, auditul UX Setări C3) ──
  // Decizia „ce se vede" e în lib/settingsNav (testată); aici doar o aplicăm. Pragul e acelaşi cu al
  // clasei `sm:` (PHONE_QUERY), deci stilurile `sm:` şi structura nu se pot contrazice.
  const layout = settingsLayout(phone, screen, searching)
  const navRef = useRef<HTMLElement>(null)
  const catTitleRef = useRef<HTMLHeadingElement>(null)
  const openCat = (c: SettingsCat) => { setQuery(''); setCat(c); setScreen('cat') }
  // Focusul urmează ecranul: intrat în categorie → titlul ei (cititorul de ecran anunţă unde a ajuns;
  // un salt la secţiune îl mută apoi pe secţiune); înapoi pe listă → rândul categoriei din care vii.
  const prevScreen = useRef(screen)
  useEffect(() => {
    if (prevScreen.current === screen) return
    prevScreen.current = screen
    if (!phone) return
    if (screen === 'cat') {
      if (contentRef.current) contentRef.current.scrollTop = 0
      catTitleRef.current?.focus({ preventScroll: true })
    } else {
      navRef.current?.querySelector<HTMLElement>(`[data-settings-cat="${cat}"]`)?.focus()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen])

  // ── Rail-ul de desktop: o singură oprire de Tab, săgeţile între categorii (auditul Me6) ──
  // Rămâne `nav` cu butoane + aria-current, nu `tablist`: grupurile cu titlu (role=group) nu sunt
  // copii permişi ai unui tablist (axe: aria-required-children), iar butoanele se activează nativ
  // cu Enter/Space — săgeţile doar mută focusul (roving tabindex), deci nimic nu se schimbă singur.
  const railIds = groups.flatMap((g) => g.cats.map((c) => c.id))
  const [railFocus, setRailFocus] = useState<SettingsCat | null>(null)
  const tabStop = railTabStop(railIds, railFocus ?? cat)
  const onRailKey = (e: KeyboardEvent<HTMLElement>) => {
    const id = (e.target as HTMLElement).closest<HTMLElement>('[data-settings-cat]')?.dataset.settingsCat
    const next = railKeyTarget(e.key, railIds.indexOf(id as SettingsCat), railIds.length)
    if (next === null || e.altKey || e.ctrlKey || e.metaKey) return
    e.preventDefault()
    navRef.current?.querySelector<HTMLElement>(`[data-settings-cat="${railIds[next]}"]`)?.focus()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-hidden overscroll-none bg-black/50 sm:p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('settings.title')}
        onKeyDown={(e) => {
          if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !isTypingTarget(e.target)) {
            e.preventDefault()
            // pe telefon căutarea stă pe ecranul listei: ne întoarcem acolo, apoi focusăm câmpul
            // (acolo câmpul e încă ascuns în cadrul ăsta); altfel focus imediat, ca până acum
            const focusSearch = () => { searchRef.current?.focus(); searchRef.current?.select() }
            if (phone && screen === 'cat') { setScreen('list'); requestAnimationFrame(focusSearch) }
            else focusSearch()
            return
          }
          // Escape pe telefon, din categorie: înapoi la listă, nu închiderea Setărilor. Doar pentru
          // evenimente din DOM-ul dialogului — un modal portalat peste noi (jurnalul unui agent,
          // o confirmare) primeşte evenimentul prin arborele React, dar Escape-ul e al lui.
          if (e.key === 'Escape' && dialogRef.current?.contains(e.target as Node)
            && escapeAction(phone, screen, searching) === 'back') {
            e.preventDefault(); e.stopPropagation()
            setScreen('list')
          }
        }}
        className="wt-settings-frame glass flex h-full w-full flex-col overflow-hidden sm:h-[88vh] sm:max-w-2xl sm:rounded-2xl lg:max-w-4xl xl:max-w-5xl">
        {/* antet fix: titlu, căutare, închidere. În DOM „Închide" vine ÎNAINTEA căutării: useFocusTrap
            pune focusul pe primul element focusabil, iar pe telefon un câmp focusat la deschidere ar
            scoate tastatura de fiecare dată (focusul rămâne pe Închide, ca înainte; „/" duce la
            căutare). Vizual: pe telefon căutarea are rândul ei, sub titlu (la 320px n-ar încăpea
            lângă el); de la `sm` stă între titlu şi Închide. Pe telefon, într-o categorie, titlul
            devine „‹ Settings" + numele categoriei (butonul Back nu e un câmp: tastatura nu apare). */}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-ink-800 px-4 py-3 sm:flex-nowrap sm:px-5">
          {layout.showBack ? (<>
            <button type="button" data-testid="settings-back" onClick={() => setScreen('list')}
              aria-label={t('settings.backAria')}
              className="wt-touch order-1 -ml-2 flex shrink-0 items-center gap-1.5 rounded-md px-2 text-sm font-medium wt-link hover:bg-ink-800">
              <ArrowLeftIcon /> {t('settings.title')}
            </button>
            <h2 ref={catTitleRef} tabIndex={-1} data-settings-current
              className="order-1 min-w-0 flex-1 truncate text-right text-base font-semibold outline-none">
              {t(SETTINGS_CATS.find((c) => c.id === cat)?.labelKey ?? 'settings.title')}
            </h2>
          </>) : (
            <h2 className="order-1 shrink-0 text-lg font-semibold">{t('settings.title')}</h2>
          )}
          <IconButton size="md" onClick={props.onClose} label={t('settings.close')}
            className="order-2 ml-auto sm:order-3 sm:ml-0">
            <CloseIcon size={14} />
          </IconButton>
          <div role="search" className={`${layout.showSearch ? '' : 'hidden'} relative order-3 w-full min-w-0 sm:order-2 sm:ml-auto sm:w-auto sm:max-w-xs sm:flex-1`}>
            <span aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">
              <SearchIcon size={14} />
            </span>
            <input
              ref={searchRef}
              type="text"
              role="combobox"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setActive(0) }}
              onKeyDown={onSearchKey}
              placeholder={t('settings.search.placeholder')}
              aria-label={t('settings.search.label')}
              aria-keyshortcuts="/"
              aria-autocomplete="list"
              aria-expanded={searching && flat.length > 0}
              // aria-controls doar cât lista există (un id inexistent e o referinţă ARIA ruptă)
              aria-controls={searching && flat.length > 0 ? listId : undefined}
              aria-activedescendant={searching && flat[active] ? optId(active) : undefined}
              autoComplete="off"
              spellCheck={false}
              enterKeyHint="go"
              className="w-full rounded-md bg-ink-800 py-1.5 pl-8 pr-8 text-base text-slate-200 sm:text-sm placeholder-slate-500 ring-1 ring-[rgb(var(--field-border))] focus:ring-sky-500"
            />
            {!query && (
              <kbd aria-hidden="true"
                className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 rounded-md bg-ink-700 px-1.5 text-2xs text-slate-400 sm:block">/</kbd>
            )}
          </div>
        </div>

        <div className="flex min-h-0 flex-1 flex-col sm:flex-row">
          {/* rail de categorii: coloană pe desktop; pe telefon e ecranul 1 — lista întreagă, pe rânduri
              de 44px cu chevron (lista → detaliu). 3.7.1 (auditul UX Setări §2.3): categoriile stau în
              grupuri cu titlu — Personal / Administrare / Operare — ca să se vadă al cui e lucrul
              înainte de ce e; un grup fără nicio categorie vizibilă nu apare. Pe telefon categoria
              curentă nu e evidenţiată: lista e un cuprins, nu o selecţie (aria-current rămâne). */}
          <nav ref={navRef} aria-label={t('settings.categoriesNav')}
            onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setRailFocus(null) }}
            className={`${layout.showNav ? 'flex' : 'hidden'} min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-2 sm:w-48 sm:flex-none sm:shrink-0 sm:gap-3 sm:border-r sm:border-ink-800 lg:w-56`}>
            {groups.map((g) => (
              <div key={g.id} role="group" aria-labelledby={`${railId}-${g.id}`}
                className="flex flex-col gap-0.5 sm:gap-1">
                <div id={`${railId}-${g.id}`}
                  className={`${eyebrow} px-3 pb-0.5 pt-1`}>{t(g.labelKey)}</div>
                {g.cats.map((c) => {
                  const sel = !searching && cat === c.id
                  return (
                    <button
                      key={c.id}
                      type="button"
                      data-settings-cat={c.id}
                      tabIndex={c.id === tabStop ? 0 : -1}
                      onFocus={() => setRailFocus(c.id)}
                      onKeyDown={onRailKey}
                      onClick={() => openCat(c.id)}
                      aria-current={sel ? 'true' : undefined}
                      className={`wt-touch flex min-h-[44px] w-full items-center gap-2 rounded-md px-3 py-2 text-left text-base sm:min-h-0 sm:text-sm ${
                        sel ? 'text-slate-200 hover:bg-ink-800 sm:bg-ink-800 sm:font-medium sm:text-slate-100 sm:shadow-[inset_3px_0_0_rgb(var(--accent))]' : 'text-slate-300 hover:bg-ink-800'
                      }`}
                    >
                      <span className="min-w-0 flex-1">{t(c.labelKey)}</span>
                      {c.id === 'sanatate' && !!props.healthAttention && (
                        <span className={`shrink-0 rounded-full px-1.5 text-2xs font-semibold ${
                          'bg-warn/10 text-warn'}`}>
                          <span aria-hidden="true">{props.healthAttention}</span>
                          <span className="sr-only">{t('health.attention', { count: props.healthAttention })}</span>
                        </span>
                      )}
                      <span aria-hidden="true" className="shrink-0 text-slate-500 sm:hidden"><ChevronIcon /></span>
                    </button>
                  )
                })}
              </div>
            ))}
          </nav>

          {/* conținut: categoria activă vizibilă (cele vizitate stau montate, ascunse), scrollabil */}
          <div ref={contentRef} data-settings-content className={`${layout.showContent ? 'block' : 'hidden'} min-h-0 min-w-0 flex-1 overflow-y-auto overflow-x-hidden px-4 py-4 sm:px-5`}>
            {/* rezultatele căutării: un listbox grupat pe tab-uri. Tab-urile rămân montate dedesubt
                (doar ascunse), deci o căutare nu pierde nimic din ce era nesalvat. */}
            <span role="status" className="sr-only">
              {searching ? t('settings.search.count', { n: flat.length }) : ''}
            </span>
            {searching && (flat.length === 0 ? (
              <EmptyState
                icon={<SearchIcon />}
                tone="neutral"
                title={t('settings.search.none', { query: query.trim() })}
                body={t('settings.search.noneHint')}
              />
            ) : (
              <div id={listId} role="listbox" aria-label={t('settings.search.results')} className="flex max-w-3xl flex-col gap-4">
                {hitGroups.map((g) => {
                  const label = t(SETTINGS_CATS.find((c) => c.id === g.cat)?.labelKey ?? '')
                  const gid = `${listId}-g-${g.cat}`
                  return (
                    <div key={g.cat} role="group" aria-labelledby={gid}>
                      <div id={gid} className={`${eyebrow} px-1 pb-1`}>{label}</div>
                      <div className="flex flex-col gap-1">
                        {g.hits.map((h) => {
                          const i = flat.indexOf(h)
                          return (
                            <div
                              key={h.section.id}
                              id={optId(i)}
                              role="option"
                              // focusul rămâne în câmp (aria-activedescendant); -1 doar ca opţiunea să fie focusabilă la clic
                              tabIndex={-1}
                              aria-selected={i === active}
                              data-setting-result={h.section.id}
                              onMouseMove={() => setActive(i)}
                              // mousedown: focusul rămâne în câmpul de căutare până la alegere
                              onMouseDown={(e) => e.preventDefault()}
                              onClick={() => pick(i)}
                              className={`cursor-pointer rounded-md px-3 py-2 ring-1 ${
                                i === active ? 'bg-sky-500/15 ring-sky-500/40' : 'ring-ink-800 hover:bg-ink-800'
                              }`}
                            >
                              <div className="text-sm text-slate-200">{h.title}</div>
                              {/* slate-400, nu 500: pe fundalul opţiunii active (sky/15) 500 pica sub 4,5:1 în tema dark */}
                              {h.hint && <div className="mt-0.5 line-clamp-2 text-xs text-slate-400">{h.hint}</div>}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )
                })}
              </div>
            ))}

            {/* coloană de lectură: peste ~70ch textul devine greu de urmărit;
                secţiunile cu liste (audit, backup) folosesc toată lăţimea */}
            <div hidden={searching} className={cat === 'audit' || cat === 'backup' ? '' : 'max-w-3xl'}>

        {/* Personal. „Account & security" (3.7.1, auditul UX Setări M1) = Account + fostul tab Sign-in & 2FA
            + „Your access" (mutat din Users & roles): trei fişiere *Tab.tsx în acelaşi panou, fiecare cu
            secţiunile lui (settingsIndex.test.ts verifică exact maparea asta). */}
        {pane('cont', <>
          <AccountTab email={props.email} onAccountChanged={props.onAccountChanged} />
          <div className="mt-6"><SignInTab webauthnAvailable={props.webauthnAvailable} /></div>
          <MyAccessTab />
        </>)}

        {pane('aspect', <AppearanceTab />)}

        {pane('preferinte', <PreferencesTab />)}

        {pane('notificari', <MyNotificationsTab />)}

        {/* Administrare */}
        {/* `jump`: sub-tab-ul secţiunii căutate (Accounts / Roles / SSO groups) se deschide înainte de salt */}
        {pane('utilizatori', <UsersTab jump={jump} />)}

        {pane('acces', <AccessTab onAccountChanged={props.onAccountChanged} />)}

        {pane('politici', <SecurityPolicyTab onAccountChanged={props.onAccountChanged} />)}

        {pane('retea', <NetworkTab />)}

        {pane('alerte', <AlertDeliveryTab />)}

        {pane('backup', <BackupTab onAccountChanged={props.onAccountChanged} />)}

        {pane('actualizari', <UpdatesTab />)}

        {/* Operare. 3.6.8: un rând de System health poate trimite la secţiunea care îl rezolvă */}
        {pane('sanatate', <HealthTab onChanged={props.onAccountChanged} onJump={(c, section) => {
          // ţinta trece prin acelaşi normalizator ca orice link adânc (id-uri retrase, secţiuni mutate)
          const target = resolveSettingsTarget({ cat: c, section })
          if (!target) return
          setCat(target.cat)
          if (target.section) setJump((j) => ({ id: target.section!, n: (j?.n ?? 0) + 1 }))
        }} />)}

        {pane('audit', <AuditTab />)}
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
