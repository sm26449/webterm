import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Host, Session } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { fmtTime, fmtTs } from '../lib/tz'
import {
  AgentEvent, fmtOfflineDuration, offlineActions, offlineMode, offlineReason, offlineSince,
  offlineTarget, OfflineMode, sinceNeedsDate,
} from '../lib/hostOffline'
import { wakeHost } from '../lib/wake'
import DiagnosticModal from './DiagnosticModal'
import { CheckIcon, PowerIcon, RefreshIcon, WarningIcon } from './Icons'

// cât rămâne vizibilă confirmarea „din nou online" (se estompează în ultima secundă)
const BACK_MS = 6000

/** Overlay NE-modal peste terminal când hostul sesiunii a căzut. Până aici singurul semnal era
    textul de 11px din bara de stare („Host offline — reconnecting"), ascunsă complet în landscape
    compact; terminalul doar nu mai făcea ecou. Ancorat SUS (ultimul output e jos, la prompt),
    îngust, fără focus automat (tastele rămân în terminal), cu „Ascunde" valabil doar pentru
    căderea curentă. La revenire dispare singur şi anunţă scurt „din nou online" (aria-live).
    Logica (variantă, de când, motiv, acţiuni) e pură, în lib/hostOffline. */
export default function HostOfflineOverlay(props: {
  session: Session
  host?: Host
  viaHost?: Host
  /** motivul `lost` primit pe WS (nu `exited`) — varianta SSH/telnet „conexiune pierdută" */
  lostReason?: string | null
  /** navigare la pagina hostului; lipsă (fereastra pop-out) → link care deschide aplicaţia */
  onOpenHost?: (id: number) => void
  onReconnect?: () => void
  reconnecting?: boolean
}) {
  const { t } = useI18n()
  const { session, host, viaHost } = props
  const mode: OfflineMode | null = offlineMode({ session, host, viaHost, lostReason: props.lostReason })
  const target = mode && host ? offlineTarget(mode, host, viaHost) : null

  // momentul în care PAGINA a văzut căderea: cheia căderii (Ascunde ţine până la următoarea) şi
  // rezerva pentru „de când", când serverul nu ştie mai bine
  const [observedAt, setObservedAt] = useState<number | null>(null)
  const [dismissedAt, setDismissedAt] = useState<number | null>(null)
  const [events, setEvents] = useState<AgentEvent[] | null>(null)
  const [back, setBack] = useState<{ name: string; fading: boolean } | null>(null)
  const [live, setLive] = useState('')
  const [diagOpen, setDiagOpen] = useState(false)
  const [waking, setWaking] = useState(false)
  const [, tick] = useState(0)
  const prev = useRef<{ mode: OfflineMode | null; name: string }>({ mode: null, name: '' })

  // tranziţiile: apariţie (notăm momentul) şi dispariţie (confirmarea „din nou online")
  useEffect(() => {
    const was = prev.current.mode
    if (mode && !was) {
      setObservedAt(Date.now() / 1000)
      setEvents(null)
      setBack(null)
    } else if (!mode && was) {
      setObservedAt(null)
      setDismissedAt(null)
      // sesiune închisă normal între timp (exit) = nu e o revenire, nu anunţăm nimic
      if (session.state !== 'closed') {
        const name = prev.current.name
        setBack({ name, fading: false })
        setLive(t('hostOffline.backOnline', { host: name }))
      }
    }
    prev.current = { mode, name: target?.name ?? prev.current.name }
  }, [mode, target?.name, session.state, t])

  // confirmarea „din nou online": vizibilă BACK_MS, estompată în ultima secundă, apoi dispare
  useEffect(() => {
    if (!back || back.fading) return
    const a = window.setTimeout(() => setBack((b) => (b ? { ...b, fading: true } : b)), BACK_MS - 1000)
    return () => clearTimeout(a)
  }, [back])
  useEffect(() => {
    if (!back?.fading) return
    const b = window.setTimeout(() => { setBack(null); setLive('') }, 1000)
    return () => clearTimeout(b)
  }, [back?.fading])

  // jurnalul agentului (motivul + momentul exact al deconectării), O DATĂ pe cădere. `fetch` brut,
  // nu `api()`: pe un host cu 2FA, `api()` ar deschide ceremonia de step-up din senin — aici motivul
  // e un bonus, nu merită un prompt. Refuzat/eşuat = fără motiv (overlay-ul nu ghiceşte).
  const targetId = target?.id
  const needEvents = mode === 'agent' || mode === 'via'
  useEffect(() => {
    if (!needEvents || targetId == null || observedAt == null) return
    let alive = true
    fetch(`/api/hosts/${targetId}/events`, { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (alive && d && Array.isArray(d.events)) setEvents(d.events) })
      .catch(() => { /* fără jurnal: rămâne heartbeat-ul */ })
    return () => { alive = false }
  }, [needEvents, targetId, observedAt])

  // durata curge; 10s: în primul minut afişăm secunde (un „0s" îngheţat 30s arăta a defect)
  useEffect(() => {
    if (!mode) return
    const iv = window.setInterval(() => tick((n) => n + 1), 10000)
    return () => clearInterval(iv)
  }, [mode])

  const now = Date.now() / 1000
  const since = mode && target ? offlineSince(mode, target, events, session, observedAt ?? now) : null
  const sinceText = since == null ? '' : sinceNeedsDate(since, now) ? fmtTs(since) : fmtTime(since)
  const durText = since == null ? '' : fmtOfflineDuration(now - since, t)
  const reasonKey = (mode === 'agent' || mode === 'via') && target ? offlineReason(target, events) : null
  const title = !mode || !target ? ''
    : mode === 'agent' ? t('hostOffline.title', { host: target.name })
    : mode === 'via' ? t('hostOffline.viaTitle', { host: target.name })
    : t('hostOffline.connLostTitle', { host: target.name })
  const sinceLine = !mode ? '' : t(mode === 'connLost' ? 'hostOffline.lostSince' : 'hostOffline.since',
    { time: sinceText, duration: durText })

  // anunţul de apariţie: o propoziţie scurtă în regiunea live, nu tot cardul cu butoane cu tot
  useEffect(() => {
    if (mode && title) setLive(`${title}. ${sinceLine}`)
    // doar la apariţie / schimbarea variantei, nu la fiecare tick al duratei
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, title])

  const visible = !!mode && !!target && observedAt != null && dismissedAt !== observedAt
  const actions = mode && target ? offlineActions(mode, target, session) : null

  const btn = 'inline-flex min-h-8 items-center rounded-md px-2.5 py-1 text-xs font-medium ring-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500'
  const secondary = `${btn} bg-ink-800 text-slate-200 ring-ink-600 hover:bg-ink-700`

  return (
    // evenimentele NU urcă în div-ul terminalului: click-dreapta / apăsarea lungă de acolo
    // deschid meniul contextual al terminalului (React le propagă şi prin portal)
    <div className="contents" onContextMenu={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
      {/* regiune live PERMANENT montată (o regiune creată odată cu textul ei nu e anunţată de
          toate cititoarele); conţine doar propoziţia, nu butoanele */}
      <div className="sr-only" role="status" aria-live="polite" data-testid="host-offline-live">{live}</div>
      {(visible || back) && (
        <div className="pointer-events-none absolute inset-x-2 top-2 z-20 flex justify-center">
          {visible && target && actions ? (
            <div data-testid="host-offline"
              role="group" aria-labelledby={`wt-off-${session.id}`}
              className="pointer-events-auto w-full max-w-lg rounded-xl border border-amber-500/40 bg-ink-900/95 px-3 py-2.5 text-sm shadow-lg backdrop-blur-sm">
              <div className="flex items-start gap-2">
                {/* nu doar culoare: icon + titlu explicit */}
                <span aria-hidden="true" className="wt-warn mt-0.5 shrink-0"><WarningIcon /></span>
                <div className="min-w-0 flex-1">
                  <div id={`wt-off-${session.id}`} className="font-semibold text-slate-100">{title}</div>
                  <div className="tabular-nums text-xs text-slate-300" title={since != null ? fmtTs(since) : undefined}>
                    {sinceLine}
                  </div>
                  {reasonKey && (
                    <div className="mt-0.5 text-xs text-slate-400">
                      {t('hostOffline.reasonLabel')} {t(reasonKey)}
                    </div>
                  )}
                  <div className="mt-0.5 text-xs text-slate-400">
                    {mode === 'agent' ? t('hostOffline.body')
                      : mode === 'via' ? t('hostOffline.viaBody', { host: host?.name ?? '' })
                      : t('hostOffline.connLostBody')}
                  </div>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                {actions.reconnect && props.onReconnect && (
                  <button type="button" onClick={props.onReconnect} disabled={props.reconnecting}
                    className={`${btn} bg-sky-600 text-white ring-sky-500 hover:bg-sky-700 disabled:opacity-50`}>
                    {props.reconnecting ? t('session.reconnectingBtn') : <><RefreshIcon size={12} /><span className="ml-1">{t('hostOffline.reconnect')}</span></>}
                  </button>
                )}
                {actions.diagnostics && (
                  <button type="button" onClick={() => setDiagOpen(true)} className={secondary}>
                    {t('hostOffline.diagnostics')}
                  </button>
                )}
                {actions.wake && (
                  <button type="button" disabled={waking} title={t('sidebar.wakeTitle')}
                    onClick={async () => { setWaking(true); try { await wakeHost(target, t) } finally { setWaking(false) } }}
                    className={`${secondary} disabled:opacity-50`}>
                    <span aria-hidden="true" className="mr-1"><PowerIcon size={12} /></span>{waking ? t('hostOffline.waking') : t('hostOffline.wake')}
                  </button>
                )}
                {actions.hostPage && (props.onOpenHost ? (
                  <button type="button" onClick={() => props.onOpenHost!(target.id)} className={secondary}>
                    {t('hostOffline.hostPage')}
                  </button>
                ) : (
                  <a href={`/#/h/${target.id}`} target="_blank" rel="noopener" className={secondary}>
                    {t('hostOffline.hostPage')}
                  </a>
                ))}
                <button type="button" onClick={() => setDismissedAt(observedAt)}
                  title={t('hostOffline.dismissTitle')}
                  className={`${btn} ml-auto text-slate-400 ring-transparent hover:bg-ink-800 hover:text-slate-200`}>
                  {t('hostOffline.dismiss')}
                </button>
              </div>
            </div>
          ) : back ? (
            <div data-testid="host-back-online"
              className={`rounded-full border border-emerald-500/40 bg-ink-900/95 px-3 py-1 text-xs font-medium text-slate-100 shadow-lg motion-safe:transition-opacity motion-safe:duration-1000 ${back.fading ? 'opacity-0' : 'opacity-100'}`}>
              <span aria-hidden="true" className="wt-good mr-1 inline-block align-[-2px]"><CheckIcon size={12} /></span>{t('hostOffline.backOnline', { host: back.name })}
            </div>
          ) : null}
        </div>
      )}
      {diagOpen && target && (
        createPortal(<DiagnosticModal key={target.id} host={target} onClose={() => setDiagOpen(false)} />, document.body)
      )}
    </div>
  )
}
