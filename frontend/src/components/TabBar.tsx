import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { isSessionLive, Host, Session } from '../lib/api'
import { hostColor } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { PHONE_QUERY, useMediaQuery } from '../lib/sheet'
import { isOverflowing, menuNav, showAllTabsButton, tabState } from '../lib/tablist'
import { CloseIcon, HomeIcon, KeyboardIcon, PencilIcon, PlusIcon } from './Icons'

/** Sesiunile deschise ca tab-uri (setul de lucru), pe cromul întunecat.
   Fiecare tab arată host-ul (nume + culoare stabilă) ca să distingi instant
   „htop pe core-rtr-01" de „htop pe edge-fw-01". */
export default function TabBar(props: {
  tabs: Session[]
  activeSid: string | null
  activity: Set<string>
  hosts: Host[]
  sort: 'manual' | 'activity'
  onToggleSort: () => void
  onHome: () => void
  onSelect: (sid: string) => void
  onClose: (sid: string) => void
  /** noua ordine a tab-urilor după drag & drop (App o persistă + comută pe „manual") */
  onReorder: (orderedSids: string[]) => void
  /** split-views: chip-uri denumite lângă taburi + „+" (creare) şi, când unul e activ,
      controalele compacte (broadcast / ieşire). Chip-urile sunt „taburi" pentru layout-uri. */
  split?: {
    views: { id: number; name: string }[]
    activeId: number | null
    broadcast: boolean
    onSelect: (id: number) => void
    onCreate: () => void
    onEdit: (id: number) => void
    onDelete: (id: number) => void
    onBroadcast: () => void
    onExit: () => void
  }
}) {
  const { t } = useI18n()
  // drag & drop pentru reordonarea manuală: `drag` = tab-ul mutat, `over` = ţinta curentă
  const [drag, setDrag] = useState<string | null>(null)
  const [over, setOver] = useState<string | null>(null)
  // anunţ pentru cititoare după o mutare din tastatură (regiune live, sr-only)
  const [announce, setAnnounce] = useState('')

  // Reordonare FĂRĂ mouse (WCAG 2.1.1 — drag & drop n-are echivalent de tastatură):
  // Alt+Shift+←/→ mută tabul focalizat cu o poziţie. Alt+←/→ simplu rămâne „tabul
  // următor/anterior" (handlerul global din App îl lasă să treacă atunci când e Shift).
  // Săgeţile simple mută doar FOCUSUL între taburi (roving tabindex), Home/End la capete.
  const tabButtons = (el: HTMLElement) =>
    Array.from(el.closest('[role="toolbar"]')?.querySelectorAll<HTMLButtonElement>('button[data-tab]') ?? [])
  const moveTab = (sid: string, dir: -1 | 1) => {
    const order = props.tabs.map((s) => s.id)
    const from = order.indexOf(sid)
    const to = from + dir
    if (from < 0 || to < 0 || to >= order.length) return
    order.splice(to, 0, order.splice(from, 1)[0])
    props.onReorder(order)
    setAnnounce(t('tabbar.moved', { n: to + 1, total: order.length }))
    // după re-randare tabul e alt nod în DOM — îl re-focalizăm după id, nu după referinţă
    requestAnimationFrame(() => document.querySelector<HTMLButtonElement>(`button[data-tab="${sid}"]`)?.focus())
  }
  const onTabKey = (e: React.KeyboardEvent<HTMLButtonElement>, sid: string) => {
    const horiz = e.key === 'ArrowLeft' ? -1 : e.key === 'ArrowRight' ? 1 : 0
    if (horiz && e.altKey && e.shiftKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault(); e.stopPropagation()
      moveTab(sid, horiz)
      return
    }
    if (e.altKey || e.ctrlKey || e.metaKey) return
    const btns = tabButtons(e.currentTarget)
    const i = btns.indexOf(e.currentTarget)
    let next = -1
    if (horiz) next = (i + horiz + btns.length) % btns.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = btns.length - 1
    if (next < 0 || !btns[next]) return
    e.preventDefault()
    btns[next].focus()
  }
  // roving tabindex: un singur tab e în ordinea de Tab — cel activ, sau primul când eşti pe Acasă
  const focusIdx = Math.max(0, props.tabs.findIndex((s) => s.id === props.activeSid))

  // „Toate taburile": pe telefon se văd 2–3 taburi de ~148px şi nimic nu spune că mai sunt.
  // Butonul stă ÎN AFARA zonei care derulează (altfel ar derula şi el din ecran) şi apare sub `sm`
  // sau oriunde taburile nu încap (ResizeObserver pe zona derulantă + pe rândul de taburi).
  const phone = useMediaQuery(PHONE_QUERY)
  const scrollRef = useRef<HTMLDivElement>(null)
  const rowRef = useRef<HTMLDivElement>(null)
  const listBtnRef = useRef<HTMLButtonElement>(null)
  const [overflowing, setOverflowing] = useState(false)
  const [listOpen, setListOpen] = useState(false)
  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const upd = () => setOverflowing(isOverflowing(el.scrollWidth, el.clientWidth))
    upd()
    const ro = new ResizeObserver(upd)
    ro.observe(el)
    if (rowRef.current) ro.observe(rowRef.current)
    return () => ro.disconnect()
  }, [props.tabs.length, props.split?.views.length])
  const showListBtn = showAllTabsButton(props.tabs.length, phone, overflowing)
  // lista se închide singură când nu mai are ce arăta (ultimul tab închis / butonul a dispărut)
  useEffect(() => { if (listOpen && !showListBtn) setListOpen(false) }, [listOpen, showListBtn])
  const dismissList = (refocus: boolean) => {
    setListOpen(false)
    if (refocus) requestAnimationFrame(() => listBtnRef.current?.focus())
  }

  const drop = () => {
    if (drag && over && drag !== over) {
      const order = props.tabs.map((s) => s.id)
      const from = order.indexOf(drag)
      const to = order.indexOf(over)
      if (from >= 0 && to >= 0) {
        order.splice(to, 0, order.splice(from, 1)[0])
        props.onReorder(order)
      }
    }
    setDrag(null)
    setOver(null)
  }
  return (
    <nav aria-label={t('tabbar.openSessions')} className="wt-tabstrip flex items-stretch pt-1.5">
    <div ref={scrollRef} className="flex min-w-0 flex-1 items-stretch gap-0.5 overflow-x-auto px-2">
      <button
        onClick={props.onHome}
        title={t('tabbar.home')}
        aria-label={t('tabbar.home')}
        className={`wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center justify-center rounded-lg px-2.5 py-1.5 ${
          props.activeSid === null ? 'is-active' : ''
        }`}
      >
        <HomeIcon />
      </button>
      {/* ordinea taburilor DESCHISE: manual (stabil) ↔ activitate (ultima folosire). Opt-in. */}
      {props.tabs.length > 1 && (
        <button
          onClick={props.onToggleSort}
          title={props.sort === 'activity'
            ? t('tabbar.sortByActivityTitle')
            : t('tabbar.sortManualTitle')}
          aria-label={t('tabbar.toggleSort')}
          aria-pressed={props.sort === 'activity'}
          className={`wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center gap-1 rounded-lg px-2 py-1.5 text-[11px] ${
            props.sort === 'activity' ? 'is-active' : 'text-slate-500'}`}
        >
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"
            strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M4 3v10M4 3 2 5.2M4 3l2 2.2M12 13V3M12 13l-2-2.2M12 13l2-2.2" />
          </svg>
          {props.sort === 'activity' ? t('tabbar.activity') : t('tabbar.manual')}
        </button>
      )}
      <span className="mx-1 my-2 w-px shrink-0 bg-white/10" aria-hidden="true" />
      {/* instrucţiunea de reordonare, o singură dată, referită de fiecare tab prin aria-describedby */}
      <span id="wt-tab-reorder-hint" className="sr-only">{t('tabbar.reorderHint')}</span>
      <span aria-live="polite" className="sr-only">{announce}</span>
      {/* `toolbar`, nu `tablist`: ARIA cere ca un tablist să conţină DOAR `tab`-uri, iar aici fiecare
          tab vine cu butonul lui de închidere ca frate (axe: aria-required-children, critic, pe
          fiecare pagină). Toolbar-ul acceptă orice controale, păstrează navigarea cu săgeţi
          (roving tabindex) şi `aria-current="page"` spune care tab e activ. */}
      <div ref={rowRef} role="toolbar" aria-label={t('tabbar.sessionTabs')} aria-orientation="horizontal" className="flex items-stretch gap-0.5">
        {props.tabs.map((s, idx) => {
          const active = s.id === props.activeSid
          const hasActivity = !active && props.activity.has(s.id)
          const live = isSessionLive(s, props.hosts)
          const host = props.hosts.find((h) => h.id === s.host_id)
          const color = host ? hostColor(host) : '#64748b'
          // sesiune închisă cu exit ≠ 0: punct roșu, nu gri — o comandă care a
          // eșuat nu arată la fel ca una terminată normal
          const failed = !live && s.exit_status != null && s.exit_status !== 0
          const stateDot = live ? 'dot-live' : (s.state === 'lost' || failed) ? 'bg-rose-500' : ''
          return (
            <div
              key={s.id}
              draggable
              onDragStart={(e) => { setDrag(s.id); e.dataTransfer.effectAllowed = 'move' }}
              onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; if (over !== s.id) setOver(s.id) }}
              onDrop={(e) => { e.preventDefault(); drop() }}
              onDragEnd={drop}
              style={active ? { background: `color-mix(in srgb, ${color} 18%, var(--chrome-elev))` } : undefined}
              className={`wt-tab group mb-1.5 flex shrink-0 items-stretch rounded-lg ${active ? 'is-active' : ''} ${
                drag === s.id ? 'opacity-40' : ''} ${
                over === s.id && drag && drag !== s.id ? 'ring-2 ring-sky-400/70' : ''} ${
                drag ? 'cursor-grabbing' : 'cursor-grab'}`}
            >
              {/* accent vertical = identitatea host-ului (estompat când nu e activ) */}
              <span
                className={`my-[7px] ml-1.5 w-[3px] shrink-0 rounded-full transition-opacity ${active ? '' : 'opacity-45 group-hover:opacity-80'}`}
                style={{ background: color }}
                aria-hidden="true"
              />
              <button
                data-tab={s.id}
                aria-current={active ? 'page' : undefined}
                aria-roledescription={t('tabbar.tabRole')}
                aria-describedby="wt-tab-reorder-hint"
                tabIndex={idx === focusIdx ? 0 : -1}
                onKeyDown={(e) => onTabKey(e, s.id)}
                onClick={() => props.onSelect(s.id)}
                title={`${s.title || t('tabbar.session')}${host ? ` · ${host.name}` : ''}${hasActivity ? ` · ${t('tabbar.newOutput')}` : ''}${failed ? ` · exit ${s.exit_status}` : ''}`}
                className="flex min-w-0 flex-col justify-center py-1 pl-2 pr-1 text-left"
              >
                <span className="flex items-center gap-1.5 text-sm leading-tight">
                  {/* starea nu e doar culoare: vie = punct rotund (culoarea hostului), închisă = gri,
                      pierdută/exit≠0 = PĂTRAT roşu; textul pentru cititoare e în span-ul sr-only */}
                  <span
                    aria-hidden="true"
                    className={`h-1.5 w-1.5 shrink-0 ${(s.state === 'lost' || failed) ? 'rounded-sm' : 'rounded-full'} ${stateDot}`}
                    title={failed ? t('tabbar.closedWithExit', { code: s.exit_status ?? '' }) : undefined}
                    style={live ? { background: color } : (s.state === 'lost' || failed) ? undefined : { background: '#475569' }}
                  />
                  <span className="sr-only">
                    {failed ? t('tabbar.closedWithExit', { code: s.exit_status ?? '' })
                      : s.state === 'lost' ? t('host.stateLost')
                      : live ? t('host.stateActive') : t('host.stateClosed')}{' — '}
                  </span>
                  <span className="max-w-[148px] truncate">{s.title || t('tabbar.session')}</span>
                  {/* output sosit cât tab-ul era în fundal (ambră ≠ culorile de host) */}
                  {hasActivity && (
                    <span data-activity className="h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400"
                      role="status" aria-label={t('tabbar.newOutput')} />
                  )}
                </span>
                {host && (
                  <span className="mt-0.5 max-w-[160px] truncate text-[11px] font-medium leading-none" style={{ color }}>
                    {host.name}
                  </span>
                )}
              </button>
              <button
                onClick={() => props.onClose(s.id)}
                title={t('tabbar.closeTabTitle')}
                aria-label={t('tabbar.closeTab')}
                className="wt-touch wt-tabbtn mr-1 mt-0.5 grid shrink-0 place-items-center self-start rounded p-1.5 opacity-0 focus-visible:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100 [@media(hover:none)]:opacity-100"
              >
                <CloseIcon size={13} />
              </button>
            </div>
          )
        })}
      </div>
      {/* transferuri: mutat în widgetul plutitor jos-dreapta (TransfersWidget) — chip-ul de aici
          înghesuia bara de taburi şi se suprapunea peste ele când erau multe. */}
      {/* split-views: chip-uri denumite (comută între layout-uri ca între taburi) + „+" (creare) şi,
          când unul e activ, broadcast + ieşire. `ml-auto` le ţine la dreapta (înainte venea de la
          chip-ul de transferuri, acum dispărut). */}
      {props.split && (props.split.views.length > 0 || props.tabs.length >= 2) && (() => {
        const sp = props.split
        return (
        <div className="ml-auto flex shrink-0 items-center gap-0.5 pl-1">
          {sp.views.map((v) => {
            const active = v.id === sp.activeId
            return (
              <div key={v.id}
                className={`wt-tab group mb-1.5 flex shrink-0 items-stretch rounded-lg ${active ? 'is-active' : ''}`}>
                <button onClick={() => sp.onSelect(v.id)} aria-pressed={active}
                  title={t('split.switchTo', { name: v.name })}
                  className={`flex min-w-0 items-center gap-1.5 py-1.5 pl-2 pr-1 text-sm ${active ? '' : 'text-slate-400'}`}>
                  <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"
                    strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
                    <rect x="1.5" y="2.5" width="13" height="11" rx="1.5" /><path d="M8 2.5v11" />
                  </svg>
                  <span className="max-w-[120px] truncate">{v.name}</span>
                </button>
                <button onClick={() => sp.onEdit(v.id)} title={t('split.edit')} aria-label={t('split.edit')}
                  className="wt-tabbtn mt-0.5 grid shrink-0 place-items-center self-start rounded p-1.5 opacity-0 focus-visible:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100 [@media(hover:none)]:opacity-100">
                  <PencilIcon size={12} />
                </button>
                <button onClick={() => sp.onDelete(v.id)} title={t('split.delete')} aria-label={t('split.delete')}
                  className="wt-tabbtn mr-1 mt-0.5 grid shrink-0 place-items-center self-start rounded p-1.5 opacity-0 hover:text-rose-300 focus-visible:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100 [@media(hover:none)]:opacity-100">
                  <CloseIcon size={12} />
                </button>
              </div>
            )
          })}
          {props.tabs.length >= 2 && (
            <button onClick={sp.onCreate} title={t('split.create')} aria-label={t('split.create')}
              className="wt-accent wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center gap-1 rounded-lg px-2 py-1.5 hover:bg-ink-800">
              <PlusIcon />
              {/* etichetă la prima folosire (fără split-uri încă) — altfel „+" gol nu se citea ca „split" */}
              {sp.views.length === 0 && <span className="text-[11px] font-medium">{t('split.title')}</span>}
            </button>
          )}
          {sp.activeId != null && (
            <>
              <button onClick={sp.onBroadcast}
                title={sp.broadcast ? t('grid.broadcastOnBtn') : t('grid.broadcastOff')}
                aria-label={sp.broadcast ? t('grid.broadcastOnBtn') : t('grid.broadcastOff')}
                aria-pressed={sp.broadcast}
                className={`wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center justify-center rounded-lg px-2 py-1.5 text-[12px] font-semibold ${
                  sp.broadcast ? 'bg-amber-500 !text-ink-950' : 'text-slate-500'}`}
              ><KeyboardIcon /></button>
              <button onClick={sp.onExit} title={t('grid.exit')} aria-label={t('grid.exit')}
                className="wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center justify-center rounded-lg px-2 py-1.5 text-slate-500"
              ><CloseIcon size={13} /></button>
            </>
          )}
        </div>
        )
      })()}
    </div>
      {showListBtn && (
        <button
          ref={listBtnRef}
          data-testid="all-tabs"
          onClick={() => setListOpen((v) => !v)}
          aria-haspopup="menu"
          aria-expanded={listOpen}
          aria-label={t('tabbar.allTabsTitle', { count: props.tabs.length })}
          title={t('tabbar.allTabsTitle', { count: props.tabs.length })}
          className={`wt-touch wt-tabbtn mb-1.5 mr-2 flex shrink-0 items-center justify-center gap-1 rounded-lg border-l border-white/10 px-2 py-1.5 text-[12px] font-medium tabular-nums ${
            listOpen ? 'is-active' : ''}`}
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor"
            strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="1.5" y="4.5" width="10" height="9" rx="1.5" /><path d="M4.5 2.5h8a2 2 0 0 1 2 2v7" />
          </svg>
          {props.tabs.length}
        </button>
      )}
      {listOpen && (
        <AllTabsMenu
          tabs={props.tabs}
          activeSid={props.activeSid}
          activity={props.activity}
          hosts={props.hosts}
          phone={phone}
          anchor={listBtnRef.current?.getBoundingClientRect() ?? null}
          onSelect={(sid) => { dismissList(false); props.onSelect(sid) }}
          onCloseTab={props.onClose}
          onDismiss={() => dismissList(true)}
        />
      )}
    </nav>
  )
}

/** Lista TUTUROR taburilor deschise (butonul de la capătul barei). Meniu WAI-ARIA: fiecare rând =
    un `menuitemradio` (comută; `aria-checked` = tabul curent) + un `menuitem` de închidere (detach:
    sesiunea rulează mai departe). ↑/↓/Home/End mută focusul prin toţi itemii, Escape închide şi
    întoarce focusul pe buton, Tab iese (ca la orice meniu). Pe telefon = foaie de jos; altfel
    dropdown ancorat sub buton. Portat în <body>: cromul poate avea `backdrop-filter`, care ar
    transforma `position: fixed` în „fixed faţă de bară". */
function AllTabsMenu(props: {
  tabs: Session[]
  activeSid: string | null
  activity: Set<string>
  hosts: Host[]
  phone: boolean
  anchor: DOMRect | null
  onSelect: (sid: string) => void
  onCloseTab: (sid: string) => void
  onDismiss: () => void
}) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  const items = () => Array.from(ref.current?.querySelectorAll<HTMLElement>('[role="menuitemradio"],[role="menuitem"]') ?? [])
  useEffect(() => {
    const cur = ref.current?.querySelector<HTMLElement>('[aria-checked="true"]')
      ?? ref.current?.querySelector<HTMLElement>('[role="menuitemradio"]')
    cur?.focus()
  }, [])
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); props.onDismiss(); return }
    if (e.key === 'Tab') { e.preventDefault(); props.onDismiss(); return }
    const list = items()
    const next = menuNav(e.key, list.indexOf(document.activeElement as HTMLElement), list.length)
    if (next === null) return
    e.preventDefault()
    list[next]?.focus()
  }
  const closeTab = (sid: string, idx: number) => {
    props.onCloseTab(sid)
    // rândul dispare: focusul trece pe rândul care i-a luat locul (sau pe ultimul), nu pe <body>
    requestAnimationFrame(() => {
      const rows = Array.from(ref.current?.querySelectorAll<HTMLElement>('[role="menuitemradio"]') ?? [])
      rows[Math.min(idx, rows.length - 1)]?.focus()
    })
  }
  const a = props.anchor
  const sheet = props.phone || !a
  const placement = sheet
    ? 'inset-x-0 bottom-0 max-h-[70dvh] rounded-t-2xl pb-[max(0.5rem,env(safe-area-inset-bottom))]'
    : 'w-80 max-h-[60vh] rounded-xl'
  const style = !sheet && a ? { top: a.bottom + 4, right: Math.max(8, window.innerWidth - a.right) } : undefined

  return createPortal(
    <>
      <div className="fixed inset-0 z-50 bg-black/40" onClick={props.onDismiss} aria-hidden="true" />
      {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions -- navigarea din tastatură a meniului (↑/↓/Escape) e pe container, nu pe fiecare item */}
      <div ref={ref} onKeyDown={onKeyDown} style={style} data-testid="all-tabs-menu"
        className={`fixed z-50 flex flex-col overflow-hidden border border-ink-700 bg-ink-900 shadow-2xl ${placement}`}>
        <p id="wt-alltabs-title" className="shrink-0 border-b border-ink-800 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
          {t('tabbar.listTitle')} · {props.tabs.length}
        </p>
        <div role="menu" aria-labelledby="wt-alltabs-title" className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-1">
          {props.tabs.map((s, idx) => {
            const active = s.id === props.activeSid
            const live = isSessionLive(s, props.hosts)
            const host = props.hosts.find((h) => h.id === s.host_id)
            const color = host ? hostColor(host) : '#64748b'
            const st = tabState(s, live)
            const hasActivity = !active && props.activity.has(s.id)
            const title = s.title || t('tabbar.session')
            const stateText = st === 'live' ? t('host.stateActive') : st === 'lost' ? t('host.stateLost')
              : st === 'failed' ? t('tabbar.closedWithExit', { code: s.exit_status ?? '' }) : t('host.stateClosed')
            return (
              <div key={s.id} role="none" className="flex items-stretch gap-1">
                <button
                  role="menuitemradio"
                  aria-checked={active}
                  tabIndex={-1}
                  data-tab-item={s.id}
                  onClick={() => props.onSelect(s.id)}
                  className={`flex min-h-[44px] min-w-0 flex-1 items-center gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-ink-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400 ${
                    active ? 'bg-ink-800 ring-1 ring-sky-500/50' : ''}`}
                >
                  <span className="w-[3px] shrink-0 self-stretch rounded-full" style={{ background: color }} aria-hidden="true" />
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="flex items-center gap-1.5 text-sm text-slate-200">
                      {/* starea nu e doar culoare: vie = rotund, pierdută/exit≠0 = PĂTRAT roşu, + textul de dedesubt */}
                      <span aria-hidden="true"
                        className={`h-1.5 w-1.5 shrink-0 ${st === 'lost' || st === 'failed' ? 'rounded-sm bg-rose-500' : 'rounded-full'} ${st === 'live' ? 'dot-live' : ''}`}
                        style={st === 'live' ? { background: color } : st === 'closed' ? { background: '#475569' } : undefined} />
                      <span className="truncate">{title}</span>
                      {hasActivity && <span data-activity className="h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" aria-hidden="true" />}
                    </span>
                    <span className="mt-0.5 flex min-w-0 items-center gap-1 text-[11px] leading-tight">
                      {host && <span className="truncate font-medium" style={{ color }}>{host.name}</span>}
                      {host && <span className="text-slate-600" aria-hidden="true">·</span>}
                      <span className={`shrink-0 ${st === 'live' ? 'wt-good' : st === 'closed' ? 'text-slate-500' : 'wt-danger'}`}>{stateText}</span>
                      {hasActivity && <span className="shrink-0 wt-warn">· {t('tabbar.newOutput')}</span>}
                    </span>
                  </span>
                  {active && <span className="shrink-0 text-[10px] font-medium uppercase tracking-wide wt-link">{t('tabbar.current')}</span>}
                </button>
                <button
                  role="menuitem"
                  tabIndex={-1}
                  onClick={() => closeTab(s.id, idx)}
                  aria-label={`${t('tabbar.closeTabTitle')} — ${title}`}
                  title={t('tabbar.closeTabTitle')}
                  className="wt-touch grid min-h-[44px] min-w-[44px] shrink-0 place-items-center rounded-lg text-slate-400 hover:bg-ink-800 hover:text-slate-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400"
                >
                  <CloseIcon size={14} />
                </button>
              </div>
            )
          })}
        </div>
      </div>
    </>,
    document.body,
  )
}
