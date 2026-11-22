import { useEffect, useRef, useState } from 'react'
import type { Host, Session } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS, useSheetMode } from '../lib/sheet'
import { sessionTitle } from '../lib/sessionTitle'
import {
  askHostEnabled, cardFacts, chooserNavTarget, durationParts, idleCandidates, LAUNCHER_VISIBLE, setAskHost,
} from '../lib/sessionChooser'
import HelpTip from './HelpTip'
import { ArrowLeftIcon, PlusIcon, TerminalPromptIcon } from './Icons'
import { Badge, Button, ErrorState, cardClass, eyebrow } from './ui'

/* Tab-ul de lansare (3.7.1, decizia proprietarului; design în .audit/2026-11-21-session-flow.md §5–6).

   De ce un TAB opac şi nu un dialog: rezultatul apare exact unde va trăi terminalul, restul aplicaţiei
   (bara laterală, alertele, transferurile) rămâne viu, iar shell-ul se creează ABIA după alegere — sub
   el nu e nimic, deci nimic semitransparent care să sugereze un terminal care nu există.

   Componenta e doar prezentare + tastatură; decizia „apare sau nu", starea tab-ului şi crearea /
   ataşarea sunt în App (connectHost), logica pură în lib/sessionChooser.ts. Serverul rămâne cel care
   decide accesul la ataşare (`_ws_access`) şi la kill (`require_session_control` + step-up). */

export default function NewSessionLauncher(props: {
  host: Host
  /** TOATE sesiunile tale vii de pe host: întâi cele care nu sunt într-un tab aici, apoi cele deschise
      deja aici (lib/sessionChooser.launcherSessions) */
  cards: Session[]
  /** id-urile deschise deja ca tab în fereastra asta: insignă, alegerea doar comută pe tab */
  openHere: readonly string[]
  /** lista de sesiuni n-a putut fi încărcată: eroare ≠ gol */
  loadError: string | null
  /** hostul poate primi o sesiune nouă acum (online + drept) */
  canOpen: boolean
  /** creşte la fiecare cerere repetată pentru acelaşi host → focus înapoi pe „New session" */
  focusNonce: number
  onNew: () => Promise<void>
  onPick: (s: Session) => void
  onClose: () => void
  onCloseIdle: (list: Session[]) => Promise<void>
  onRetry: () => void
}) {
  const { t } = useI18n()
  const sheet = useSheetMode()
  const { host, cards } = props
  const openHere = new Set(props.openHere)
  const newRef = useRef<HTMLButtonElement>(null)
  const listRef = useRef<HTMLUListElement>(null)
  const [busy, setBusy] = useState(false)
  const [all, setAll] = useState(false)
  const [askHere, setAskHere] = useState(() => askHostEnabled(host.id))
  const [announce, setAnnounce] = useState('')
  const now = Date.now() / 1000

  // focusul intră pe „New session" (Enter = ce făcea clicul înainte)
  useEffect(() => { newRef.current?.focus() }, [props.focusNonce, host.id])
  useEffect(() => { setAskHere(askHostEnabled(host.id)); setAll(false) }, [host.id])

  // o sesiune s-a încheiat cât lansatorul era deschis: cardul dispare, anunţat politicos; dacă focusul
  // era pe el (acum scos din DOM), revine pe „New session"
  const prevCount = useRef(cards.length)
  useEffect(() => {
    const gone = prevCount.current - cards.length
    prevCount.current = cards.length
    if (gone > 0) {
      setAnnounce(t('launcher.ended', { count: gone }))
      if (!document.activeElement || document.activeElement === document.body) newRef.current?.focus()
    }
  }, [cards.length, t])

  const limit = sheet ? LAUNCHER_VISIBLE.phone : LAUNCHER_VISIBLE.desktop
  const shown = all ? cards : cards.slice(0, limit)
  const idle = idleCandidates(cards, now, props.openHere)
  const dur = (secs: number) => {
    const d = durationParts(secs)
    return d.unit === 'min' ? t('launcher.dur.min', { count: d.n })
      : d.unit === 'h' ? t('launcher.dur.h', { count: d.n })
        : t('launcher.dur.d', { count: d.n })
  }

  const createNew = async () => {
    if (busy || !props.canOpen) return
    setBusy(true)
    try { await props.onNew() } finally { setBusy(false) }
  }

  // tastele: ↑/↓/Home/End între „New session" şi carduri (Escape: mai jos, în captură). O apăsare ŢINUTĂ
  // (auto-repeat) a Enter-ului care a deschis lansatorul (din paletă, de pe un buton) n-are voie să
  // activeze ce primeşte focusul — contează doar apăsările care încep aici (e.repeat = false).
  const onKeyDownCapture = (e: React.KeyboardEvent) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.repeat) { e.preventDefault(); e.stopPropagation() }
  }
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.altKey || e.ctrlKey || e.metaKey) return
    const items = [newRef.current, ...Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>('button[data-card]') ?? [])]
      .filter((x): x is HTMLButtonElement => !!x && !x.disabled)
    const cur = items.indexOf(document.activeElement as HTMLButtonElement)
    if (cur < 0) return
    const next = chooserNavTarget(items.length, cur, e.key)
    if (next == null) return
    e.preventDefault()
    items[next].focus()
  }

  // Escape: pe `window`, în faza de CAPTURĂ — primul ascultător care-l vede. Altfel un ascultător pe
  // document (ex. un sfat contextual rămas montat în terminalul ascuns din spate, care îşi înghite
  // Escape-ul) îl oprea înainte să ajungă la lansator. Doar cu focusul în lansator sau nicăieri (clic
  // pe un spaţiu gol → body) şi fără un dialog modal deschis peste el.
  const rootRef = useRef<HTMLElement>(null)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented) return
      const a = document.activeElement
      if (a && a !== document.body && !rootRef.current?.contains(a)) return
      if (document.querySelector('[aria-modal="true"]')) return
      e.preventDefault()
      e.stopPropagation()
      props.onClose()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [props.onClose])   // eslint-disable-line react-hooks/exhaustive-deps

  const heading = cards.length ? t('launcher.heading', { host: host.name, count: cards.length })
    : t('launcher.headingEmpty', { host: host.name })

  const body = (
    <div className={`mx-auto flex w-full max-w-2xl flex-col ${sheet ? 'px-4 pb-6 pt-4' : 'px-6 pb-10 pt-10'}`}>
      <div className="flex items-start gap-2">
        <h1 className={`min-w-0 flex-1 text-lg font-semibold text-slate-100 ${sheet ? 'leading-snug' : ''}`}>{heading}</h1>
        <HelpTip id="launcher" className="mt-0.5 shrink-0" />
      </div>
      <p className="mt-1 text-sm text-slate-400">{t('launcher.sub')}</p>
      {!props.canOpen && (
        <p role="status" className="wt-warn mt-3 text-sm">{t('launcher.offline', { host: host.name })}</p>
      )}

      <Button ref={newRef} type="button" variant="primary" size="lg" data-testid="launcher-new"
        className={`mt-5 w-full justify-between ${sheet ? 'min-h-[56px]' : 'min-h-[44px]'}`}
        disabled={!props.canOpen} loading={busy}
        onClick={() => { void createNew() }}>
        <span className="flex items-center gap-2"><PlusIcon /> {t('launcher.new')}</span>
        {!sheet && <kbd aria-hidden="true" className="rounded-md border border-current px-1.5 text-2xs">Enter</kbd>}
      </Button>

      <h2 className={`${eyebrow} mt-6`}>{t('launcher.continue')}</h2>
      <span aria-live="polite" className="sr-only">{announce}</span>
      {props.loadError ? (
        <div className={`${cardClass} mt-2`}>
          <ErrorState title={t('launcher.loadFailed')} message={props.loadError} onRetry={props.onRetry} compact />
        </div>
      ) : (
        <ul ref={listRef} aria-label={t('launcher.listAria', { host: host.name })} className="mt-2 flex flex-col gap-2">
          {shown.map((s) => {
            const here = openHere.has(s.id)
            const f = cardFacts(s, now, here)
            const title = sessionTitle(s.title, t) || t('app.untitledSession')
            const activity = f.starting ? t('launcher.starting')
              : f.idle ? t('launcher.idleFor', { ago: dur(f.idleSecs) })
                : f.idleSecs < 60 ? t('launcher.activeNow') : t('launcher.activeAgo', { ago: dur(f.idleSecs) })
            const opened = f.ageSecs < 60 ? t('launcher.openedNow') : t('launcher.openedAgo', { ago: dur(f.ageSecs) })
            const badges = (
              <>
                {here && <Badge tone="info" data-open-here="">{t('launcher.badge.openHere')}</Badge>}
                {f.others > 0 && <Badge tone="info">{t('launcher.others', { count: f.others })}</Badge>}
                {f.shared && <Badge tone="warn">{t('launcher.shared')}</Badge>}
                {f.keepOpen && <Badge>{t('launcher.keepOpen')}</Badge>}
                {f.idleNotice && <Badge tone="warn">{t('launcher.idleNotice')}</Badge>}
              </>
            )
            const hasBadges = here || f.others > 0 || f.shared || f.keepOpen || f.idleNotice
            return (
              <li key={s.id}>
                {/* deja tab aici: comutarea pe el nu creează/ataşează nimic, deci merge şi cu hostul offline */}
                <button type="button" data-card={s.id} disabled={!props.canOpen && !here}
                  onClick={() => props.onPick(s)}
                  className={`${cardClass} wt-touch flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-ink-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[rgb(var(--focus))] ${sheet ? 'min-h-[56px]' : 'min-h-[60px]'}`}>
                  {!sheet && (
                    <span aria-hidden="true" className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-ink-700/60 text-slate-300">
                      <TerminalPromptIcon />
                    </span>
                  )}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-slate-100">{title}</span>
                    <span className={`block truncate text-xs ${f.idle ? 'text-slate-500' : 'text-slate-400'}`}>
                      {activity}{sheet ? '' : ` · ${opened}`}
                    </span>
                    {sheet && hasBadges && <span className="mt-1 flex flex-wrap gap-1">{badges}</span>}
                  </span>
                  {!sheet && hasBadges && <span className="flex shrink-0 flex-wrap justify-end gap-1">{badges}</span>}
                </button>
              </li>
            )
          })}
        </ul>
      )}

      <div className={`mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm ${sheet ? 'flex-col items-stretch' : 'justify-between'}`}>
        {cards.length > limit ? (
          <button type="button" data-testid="launcher-view-all" onClick={() => setAll((v) => !v)} aria-expanded={all}
            className="wt-touch min-h-[44px] rounded-md text-left wt-link hover:underline">
            {all ? t('launcher.showFewer') : t('launcher.viewAll', { count: cards.length })}
          </button>
        ) : <span />}
        {idle.length > 0 && (
          <span className="flex flex-wrap items-center gap-x-1 text-slate-400">
            {t('launcher.idleCount', { count: idle.length })} ·
            <button type="button" data-testid="launcher-close-idle"
              onClick={() => { void props.onCloseIdle(idle) }}
              className="wt-touch min-h-[44px] rounded-md wt-link hover:underline">
              {t('launcher.closeIdle')}
            </button>
          </span>
        )}
      </div>

      <div className={`mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-400 ${sheet ? 'wt-sheet-bottom' : 'justify-between'}`}>
        <label className="wt-touch flex min-h-[44px] cursor-pointer items-center gap-2">
          <input type="checkbox" checked={!askHere}
            onChange={(e) => { const ask = !e.target.checked; setAskHere(ask); setAskHost(host.id, ask) }}
            className="h-4 w-4 cursor-pointer accent-sky-500 [@media(pointer:coarse)]:h-6 [@media(pointer:coarse)]:w-6" />
          {t('launcher.dontAsk', { host: host.name })}
        </label>
        {!sheet && <span>{t('launcher.escHint')}</span>}
      </div>
      {!sheet && <p className="mt-1 text-xs text-slate-500">{t('launcher.shiftHint')}</p>}
    </div>
  )

  if (sheet) {
    return (
      // foaia de telefon: acelaşi conţinut, pe tot ecranul. Back (al browserului) = Escape: tab-ul are
      // propria intrare de istoric (#/new/<id>), deci butonul Înapoi al Android-ului îl închide singur.
      // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- navigarea din tastatură (↑/↓/Escape) e pe container, nu pe fiecare buton
      <section ref={rootRef} aria-label={t('launcher.tabAria', { host: host.name })} data-testid="launcher"
        className={SHEET_CLS} onKeyDownCapture={onKeyDownCapture} onKeyDown={onKeyDown}>
        <div className="flex shrink-0 items-center gap-2 border-b border-ink-800 bg-ink-900 px-2 py-1">
          <button type="button" onClick={props.onClose}
            className="wt-touch flex min-h-[44px] shrink-0 items-center gap-1.5 rounded-md px-2 text-sm font-medium wt-link hover:bg-ink-800">
            <ArrowLeftIcon /> {t('launcher.back')}
          </button>
          <span className="min-w-0 flex-1 truncate text-right text-sm font-semibold text-slate-200">{host.name}</span>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">{body}</div>
      </section>
    )
  }
  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- navigarea din tastatură (↑/↓/Escape) e pe container, nu pe fiecare buton
    <section ref={rootRef} aria-label={t('launcher.tabAria', { host: host.name })} data-testid="launcher"
      className="wt-canvas h-full w-full overflow-y-auto" onKeyDownCapture={onKeyDownCapture} onKeyDown={onKeyDown}>
      {body}
    </section>
  )
}
