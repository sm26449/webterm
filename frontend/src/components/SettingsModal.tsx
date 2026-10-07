import { KeyboardEvent, ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { catOfSection, groupHits, searchSettings, SETTINGS_CATS, SettingsCat } from '../lib/settingsIndex'
import AccountTab from './settings/AccountTab'
import SignInTab from './settings/SignInTab'
import InfrastructureTab from './settings/InfrastructureTab'
import AuditTab from './settings/AuditTab'
import AppearanceTab from './settings/AppearanceTab'
import NotificationsTab from './settings/NotificationsTab'
import BackupTab from './settings/BackupTab'
import PreferencesTab from './settings/PreferencesTab'
import { EmptyState, eyebrow, IconButton } from './ui'
import { CloseIcon, SearchIcon } from './Icons'

/** ţinta e un câmp în care se scrie: acolo „/" e text, nu scurtătură */
const isTypingTarget = (el: EventTarget | null) =>
  el instanceof HTMLElement && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))

const prefersReducedMotion = () =>
  typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

/** Derulează secţiunea în vedere, îi mută focusul (cititorul de ecran ajunge unde a ajuns şi ochiul)
    şi o încadrează scurt (.wt-setting-flash, index.css: conturul se stinge; fără animaţie la
    prefers-reduced-motion, doar dispare după câteva secunde). */
function flashSection(el: HTMLElement, container: HTMLElement | null) {
  el.scrollIntoView({ block: 'start', behavior: prefersReducedMotion() ? 'auto' : 'smooth' })
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
    if (Math.abs(off) > 32) el.scrollIntoView({ block: 'start' })
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
}) {
  const { t } = useI18n()
  // categoria activă: modalul nu mai e un scroll lung — arată o secțiune odată. Cu o secţiune cerută
  // şi fără tab explicit, tab-ul e cel al secţiunii (indexul ştie unde stă fiecare).
  const firstCat: SettingsCat = props.initialCat
    ?? (props.initialSection ? catOfSection(props.initialSection) : undefined) ?? 'cont'
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

  // ── Căutarea ──
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const searching = query.trim() !== ''
  const hits = useMemo(() => searchSettings(query, t), [query, t])
  const groups = useMemo(() => groupHits(hits), [hits])
  const flat = useMemo(() => groups.flatMap((g) => g.hits), [groups])   // ordinea afişată = ordinea tastelor
  const listId = useId()
  const optId = (i: number) => `${listId}-opt-${i}`
  const searchRef = useRef<HTMLInputElement>(null)
  const contentRef = useRef<HTMLDivElement>(null)

  // Saltul la o secţiune: aşteptăm cadrul în care tab-ul ei e montat ŞI vizibil (offsetParent).
  // `n` face ca alegerea aceleiaşi secţiuni de două ori să re-declanşeze efectul.
  const [jump, setJump] = useState<{ id: string; n: number } | null>(
    () => (props.initialSection ? { id: props.initialSection, n: 0 } : null))
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('settings.title')}
        onKeyDown={(e) => {
          if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !isTypingTarget(e.target)) {
            e.preventDefault()
            searchRef.current?.focus()
            searchRef.current?.select()
          }
        }}
        className="glass flex h-[92vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl sm:h-[88vh] lg:max-w-4xl xl:max-w-5xl">
        {/* antet fix: titlu, căutare, închidere. În DOM „Închide" vine ÎNAINTEA căutării: useFocusTrap
            pune focusul pe primul element focusabil, iar pe telefon un câmp focusat la deschidere ar
            scoate tastatura de fiecare dată (focusul rămâne pe Închide, ca înainte; „/" duce la
            căutare). Vizual: pe telefon căutarea are rândul ei, sub titlu (la 320px n-ar încăpea
            lângă el); de la `sm` stă între titlu şi Închide. */}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-ink-800 px-4 py-3 sm:flex-nowrap sm:px-5">
          <h2 className="order-1 shrink-0 text-lg font-semibold">{t('settings.title')}</h2>
          <IconButton size="md" onClick={props.onClose} label={t('settings.close')}
            className="order-2 ml-auto sm:order-3 sm:ml-0">
            <CloseIcon size={14} />
          </IconButton>
          <div role="search" className="relative order-3 w-full min-w-0 sm:order-2 sm:ml-auto sm:w-auto sm:max-w-xs sm:flex-1">
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
              aria-controls={listId}
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
          {/* rail de categorii: coloană pe desktop, bandă orizontală pe mobil */}
          <nav aria-label={t('settings.categoriesNav')}
            className="flex shrink-0 gap-1 overflow-x-auto border-b border-ink-800 p-2 sm:w-44 lg:w-52 sm:flex-col sm:overflow-x-visible sm:border-b-0 sm:border-r">
            {SETTINGS_CATS.map((c) => (
              <button
                key={c.id}
                onClick={() => { setQuery(''); setCat(c.id) }}
                aria-current={!searching && cat === c.id ? 'true' : undefined}
                className={`wt-touch shrink-0 rounded-md px-3 py-2 text-left text-sm sm:w-full ${
                  !searching && cat === c.id ? 'bg-sky-600 text-white' : 'text-slate-300 hover:bg-ink-800'
                }`}
              >
                {t(c.labelKey)}
              </button>
            ))}
          </nav>

          {/* conținut: categoria activă vizibilă (cele vizitate stau montate, ascunse), scrollabil */}
          <div ref={contentRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-5">
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
                {groups.map((g) => {
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
                              {h.hint && <div className="mt-0.5 line-clamp-2 text-xs text-slate-500">{h.hint}</div>}
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

        {pane('cont', <AccountTab email={props.email} onAccountChanged={props.onAccountChanged} />)}

        {pane('preferinte', <PreferencesTab />)}

        {pane('aspect', <AppearanceTab onAccountChanged={props.onAccountChanged} />)}

        {pane('autentificare', <SignInTab webauthnAvailable={props.webauthnAvailable} />)}

        {pane('infrastructura', <InfrastructureTab onAccountChanged={props.onAccountChanged} />)}

        {pane('audit', <AuditTab />)}

        {pane('notificari', <NotificationsTab />)}

        {pane('backup', <BackupTab onAccountChanged={props.onAccountChanged} />)}
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
