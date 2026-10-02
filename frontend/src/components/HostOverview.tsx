import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { isSessionLive, api, AppLink, Host, Session, timeAgo } from '../lib/api'
import { hostAt, hostColor, protoLabel } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { hostHistory } from '../lib/metrics'
import { DockerIcon, DownloadIcon, FilesIcon, ForwardIcon, LinkIcon, NoteIcon, PlusIcon, PopoutIcon, RefreshIcon, ServerIcon, ServicesIcon, ShieldIcon, SplitIcon, TerminalPromptIcon, ToolboxIcon, TrashIcon } from './Icons'
import SessionPreview from './SessionPreview'
import Sparkline from './Sparkline'
import TranscriptPlayer from './TranscriptPlayer'

// Panourile hub-ului se încarcă DOAR când deschizi tab-ul lor (FilePanel aduce Monaco — mare),
// nu în bundle-ul paginii de host. `embed` le randează full-width, fără drawer/scrim/close.
const FilePanel = lazy(() => import('./FilePanel'))
const ForwardsPanel = lazy(() => import('./ForwardsPanel'))
const ServicesPanel = lazy(() => import('./ServicesPanel'))
const DockerPanel = lazy(() => import('./DockerPanel'))
const ToolboxPanel = lazy(() => import('./ToolboxPanel'))

type HubTab = 'overview' | 'sessions' | 'files' | 'forwards' | 'services' | 'docker' | 'databases'

/** Pagina unui host: navigare de sesiuni (stânga) + previzualizare (dreapta).
   Click pe o sesiune = preview; „Deschide" (sau dublu-click) = terminal. */
const HOST_APP_COLOR: Record<string, string> = {
  proxmox: '#ec8b3c', portainer: '#57a8e6', grafana: '#f59e0b', custom: '#34d399',
}

export default function HostOverview(props: {
  host: Host
  sessions: Session[]
  onOpenSession: (sid: string) => void
  onNewSession: (host: Host) => void
  onSplit: (sid: string) => void
  onPopout: (sid: string) => void
  onDeleteSession: (sid: string) => void
  onMenu: () => void
  sidebarCollapsed?: boolean
  // acţiuni de host care deschid o sesiune de terminal (prin App)
  onConnectionOpen: (host: Host, connId: number) => void
  onJournal: (host: Host, unit: string) => void
  onContainerShell: (host: Host, containerId: string) => void
  onSerial: (host: Host) => void
  onDiagnostic: (host: Host) => void
}) {
  const { t } = useI18n()
  const { host } = props
  const canConnect = host.connection_type !== 'agent' || host.online
  const isAgent = (host.connection_type ?? 'agent') === 'agent'
  const agentReady = isAgent && !!host.online      // tab-urile prin agent cer agentul online
  const m = host.metrics
  const [tab, setTab] = useState<HubTab>('overview')
  useEffect(() => { setTab('overview') }, [host.id])

  // complete per-host history (not limited by the global recent-closed window),
  // fetched on host change + refreshed, merged with the fresh 5s global poll
  const [hostSessions, setHostSessions] = useState<Session[]>([])
  useEffect(() => {
    let alive = true
    const load = () => api<Session[]>(`/api/hosts/${host.id}/sessions`)
      .then((r) => { if (alive) setHostSessions(r) }).catch(() => {})
    load()
    const t = setInterval(() => { if (!document.hidden) load() }, 6000)
    return () => { alive = false; clearInterval(t) }
  }, [host.id])
  // ștergerile optimiste: fără setul ăsta, sesiunea „ștearsă imediat" din
  // hostSessions ar fi re-adăugată instant din props.sessions (poll-ul global)
  const [deletedIds, setDeletedIds] = useState<Set<string>>(new Set())
  useEffect(() => { setDeletedIds(new Set()) }, [host.id])
  const allSessions = useMemo(() => {
    const byId = new Map<string, Session>()
    for (const s of hostSessions) byId.set(s.id, s)
    for (const s of props.sessions) byId.set(s.id, s)   // global poll is fresher
    return [...byId.values()]
      .filter((s) => !deletedIds.has(s.id))
      .sort((a, b) => b.created - a.created)
  }, [hostSessions, props.sessions, deletedIds])
  const active = allSessions.filter((s) => isSessionLive(s, host ? [host] : undefined))
  const closed = allSessions.filter((s) => s.state === 'closed' || s.state === 'lost')

  const [selected, setSelected] = useState<string | null>(null)
  const [playing, setPlaying] = useState<Session | null>(null)
  // preselectează prima sesiune activă (sau prima închisă) când se schimbă hostul
  useEffect(() => {
    setSelected((cur) => {
      if (cur && allSessions.some((s) => s.id === cur)) return cur
      return active[0]?.id ?? closed[0]?.id ?? null
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host.id, allSessions.length])

  const sel = allSessions.find((s) => s.id === selected) ?? null
  const selLive = sel ? isSessionLive(sel, host ? [host] : undefined) : false

  const row = (s: Session) => {
    const live = isSessionLive(s, host ? [host] : undefined)
    return (
      <button
        key={s.id}
        onClick={() => setSelected(s.id)}
        onDoubleClick={() => props.onOpenSession(s.id)}
        className={`flex w-full items-center gap-2.5 px-3 py-2 text-left ${
          selected === s.id ? 'bg-ink-800' : 'hover:bg-ink-800/50'
        }`}
      >
        <span className={`h-2 w-2 shrink-0 rounded-full ${
          live ? 'bg-emerald-400 dot-live' : s.state === 'lost' ? 'bg-rose-500' : 'bg-slate-600'}`} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm text-slate-200">{s.title || t('host.sessionFallback')}</span>
          <span className="block truncate text-[11px] text-slate-600">
            {live ? t('host.stateActive') : s.state === 'lost' ? t('host.stateLost') : t('host.stateClosed')}
            {s.exit_status != null ? ` · exit ${s.exit_status}` : ''} · {timeAgo(s.closed_at || s.created, t)}
          </span>
        </span>
        {s.connected_clients > 0 && <span className="shrink-0 text-[11px] text-slate-500">👁 {s.connected_clients}</span>}
      </button>
    )
  }

  const tabs: { id: HubTab; label: string; show: boolean; icon: React.ReactNode }[] = [
    { id: 'overview', label: t('host.tabOverview'), show: true, icon: <ServerIcon /> },
    { id: 'sessions', label: t('host.tabSessions'), show: true, icon: <TerminalPromptIcon /> },
    { id: 'files', label: t('host.tabFiles'), show: agentReady, icon: <FilesIcon /> },
    { id: 'forwards', label: t('host.tabForwards'), show: agentReady, icon: <ForwardIcon /> },
    { id: 'services', label: t('host.tabServices'), show: agentReady, icon: <ServicesIcon /> },
    { id: 'docker', label: t('host.tabDocker'), show: agentReady, icon: <DockerIcon /> },
    { id: 'databases', label: t('host.tabDatabases'), show: agentReady, icon: <ToolboxIcon /> },
  ]
  // dacă tab-ul curent devine indisponibil (agentul a căzut), cădem înapoi pe Overview
  const visibleTabs = tabs.filter((x) => x.show)
  useEffect(() => {
    if (!visibleTabs.some((x) => x.id === tab)) setTab('overview')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentReady])

  const paneFallback = (
    <div className="flex h-full items-center justify-center text-sm text-slate-500">{t('host.loadingPanel')}</div>
  )

  return (
    <div className="flex h-full min-w-0 flex-1 flex-col">
      {/* ── header ── */}
      <div className="flex flex-wrap items-start gap-x-4 gap-y-3 border-b border-ink-800 px-4 pt-4 pb-3 sm:px-6">
        <button onClick={props.onMenu} className={`wt-touch grid place-items-center rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800 ${props.sidebarCollapsed ? '' : 'md:hidden'}`} aria-label={t('host.openHostListAria')}>
          ☰
        </button>
        <div className="relative shrink-0">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-ink-800 text-slate-400 ring-1 ring-ink-700">
            <ServerIcon />
          </div>
          <span className={`absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full ring-2 ring-[color:var(--term-bg)] ${
            host.online ? 'bg-emerald-400' : 'bg-slate-500'}`} />
        </div>
        <div className="min-w-[10rem] flex-1">
          <div className="flex items-center gap-2">
            <h1 className="truncate text-lg font-semibold text-slate-100">{host.name}</h1>
            {host.connection_type && host.connection_type !== 'agent' && (
              <span className="rounded bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-sky-400">
                {host.connection_type}
              </span>
            )}
          </div>
          <div className="mt-0.5 truncate text-sm text-slate-500">
            <span className="font-mono">{host.hostname ? `${host.ssh_username || host.agent_user || ''}@${host.hostname}` : t('host.notConfigured')}</span>
            {' · '}
            <span className={host.online ? 'wt-good' : 'text-slate-500'}>
              {host.online ? 'online' : (host.connection_type === 'agent' ? 'offline' : t('host.connectOnDemand'))}
            </span>
            {host.online && m && (
              <span className="ml-2 hidden font-mono text-slate-600 tabular-nums sm:inline">
                {m.cpu_pct != null && `CPU ${Math.round(m.cpu_pct)}%`}
                {m.mem_total ? ` · MEM ${Math.round(((m.mem_used ?? 0) / m.mem_total) * 100)}%` : ''}
                {m.load1 != null ? ` · load ${m.load1.toFixed(2)}` : ''}
              </span>
            )}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {/* Serial + Diagnostic rămân acţiuni (deschid o sesiune / un modal), nu tab-uri */}
          {agentReady && (
            <button onClick={() => props.onSerial(host)} title={t('host.serialConsole')}
              className="wt-touch flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
              🔌 <span className="hidden sm:inline">{t('host.serialConsole')}</span>
            </button>
          )}
          {isAgent && (
            <button onClick={() => props.onDiagnostic(host)} title={t('host.diagnostic')}
              className="wt-touch flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
              🩺 <span className="hidden sm:inline">{t('host.diagnostic')}</span>
            </button>
          )}
          <button disabled={!canConnect} onClick={() => props.onNewSession(host)}
            className="wt-touch flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-40">
            <PlusIcon /> {t('host.newSession')}
          </button>
        </div>

      </div>

      {/* ── corp: nav vertical (stânga pe desktop, rând derulabil pe mobil) + conţinut ── */}
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <nav aria-label={t('host.sections')}
          className="flex shrink-0 gap-1 overflow-x-auto border-b border-ink-800 p-2 md:w-52 md:flex-col md:overflow-x-visible md:overflow-y-auto md:border-b-0 md:border-r">
          {visibleTabs.map((x) => (
            <button key={x.id} onClick={() => setTab(x.id)} aria-current={tab === x.id ? 'page' : undefined}
              className={`flex shrink-0 items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition md:w-full ${
                tab === x.id ? 'bg-ink-800 text-slate-100 ring-1 ring-ink-700'
                             : 'text-slate-400 hover:bg-ink-800/50 hover:text-slate-200'}`}>
              <span className="grid h-4 w-4 shrink-0 place-items-center opacity-80">{x.icon}</span>
              {x.label}
              {x.id === 'sessions' && active.length > 0 && (
                <span className="ml-auto rounded-full bg-emerald-500/15 px-1.5 text-[10px] font-semibold wt-good">{active.length}</span>
              )}
            </button>
          ))}
        </nav>

        {/* ── conţinutul secţiunii ── */}
        <div className="flex min-h-0 flex-1 flex-col">
        {tab === 'overview' && (
          <div className="min-h-0 flex-1 overflow-y-auto p-4 sm:p-6">
            <div className="mx-auto max-w-6xl space-y-6">
              {host.backend === 'pty' && (
                <p className="wt-warn rounded-xl bg-amber-500/10 p-3 text-sm ring-1 ring-amber-500/30">
                  {t('host.noTmuxWarning')}
                </p>
              )}
              {/* rândul de metrici — inima dashboard-ului (doar agent online cu metrici) */}
              <StatTiles host={host} />

              {active.length > 0 && (
                <section>
                  <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    {t('host.active')} <span className="text-slate-600">· {active.length}</span>
                    <button onClick={() => setTab('sessions')} className="ml-auto text-[11px] normal-case text-sky-400 hover:underline">{t('host.allSessions')} →</button>
                  </div>
                  {/* thumbnail-uri LIVE: fiecare card e un preview read-only al sesiunii, auto-fit */}
                  <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))' }}>
                    {active.map((s) => (
                      <SessionThumb key={s.id} session={s}
                        onOpen={() => props.onOpenSession(s.id)}
                        onSplit={() => props.onSplit(s.id)}
                        onPopout={() => props.onPopout(s.id)} />
                    ))}
                  </div>
                </section>
              )}
              <HostDetail host={host} />
            </div>
          </div>
        )}

        {tab === 'sessions' && (
          <div className="flex min-h-0 flex-1 flex-col md:flex-row">
            <div className="max-h-[38%] w-full shrink-0 overflow-y-auto border-b border-ink-800 md:max-h-none md:w-[320px] md:border-b-0 md:border-r">
              <div className="px-3 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                {t('host.active')} {active.length > 0 && <span className="text-slate-600">· {active.length}</span>}
              </div>
              {active.length === 0
                ? <p className="px-3 pb-2 text-xs text-slate-600">{t('host.noActiveSessions')}</p>
                : active.map(row)}
              {closed.length > 0 && (
                <>
                  <div className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    {t('host.closed')} <span className="text-slate-600">· {closed.length}</span>
                  </div>
                  {closed.map(row)}
                </>
              )}
            </div>
            <div className="flex min-w-0 flex-1 flex-col">
              {sel ? (
                <>
                  <div className="flex flex-wrap items-center gap-2 border-b border-ink-800 px-4 py-2.5">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${
                      selLive ? 'bg-emerald-400 dot-live' : sel.state === 'lost' ? 'bg-rose-500' : 'bg-slate-600'}`} />
                    <div className="min-w-[8rem] flex-1">
                      <div className="truncate text-sm font-medium text-slate-200">{sel.title || t('host.sessionFallback')}</div>
                      <div className="truncate text-[11px] text-slate-600">
                        {selLive ? t('host.previewLive') : t('host.previewHistory')} · {timeAgo(sel.closed_at || sel.created, t)}
                      </div>
                    </div>
                    <button onClick={() => props.onSplit(sel.id)} title={t('host.splitTitle')}
                      className="hidden shrink-0 rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200 lg:block"><SplitIcon /></button>
                    <button onClick={() => props.onPopout(sel.id)} title={t('host.popoutTitle')}
                      className="hidden shrink-0 rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200 lg:block"><PopoutIcon /></button>
                    {!selLive && (
                      <button onClick={() => setPlaying(sel)} title={t('host.playTitle')} aria-label={t('host.playTitle')}
                        className="wt-touch grid place-items-center rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200">▶</button>
                    )}
                    <a href={`/api/sessions/${sel.id}/transcript?format=cast`} download title={t('host.downloadTitle')}
                      className="wt-touch grid place-items-center rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200"><DownloadIcon /></a>
                    {!selLive && (
                      <button onClick={() => {
                          if (!confirm(t('session.confirmDelete'))) return
                          setDeletedIds((prev) => new Set(prev).add(sel.id))
                          props.onDeleteSession(sel.id); setSelected(null)
                        }} title={t('host.deleteTitle')}
                        className="wt-touch grid place-items-center rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-rose-400"><TrashIcon /></button>
                    )}
                    <button onClick={() => props.onOpenSession(sel.id)}
                      className="wt-touch ml-1 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700">
                      {selLive ? t('host.openTerminal') : t('host.viewHistory')}
                    </button>
                  </div>
                  <div className="min-h-0 flex-1 bg-[#0b0e14] p-2">
                    <SessionPreview key={sel.id} sid={sel.id} live={selLive} />
                  </div>
                </>
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-slate-500">
                  <p>{t('host.noSessionsYet')}</p>
                  <button disabled={!canConnect} onClick={() => props.onNewSession(host)}
                    className="rounded-lg bg-sky-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-40">
                    <span className="inline-flex items-center gap-1.5"><PlusIcon /> {t('host.newSession')}</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'files' && (
          <Suspense fallback={paneFallback}>
            <FilePanel embed host={host} sessionId="" onClose={() => setTab('overview')} />
          </Suspense>
        )}
        {tab === 'forwards' && (
          <Suspense fallback={paneFallback}>
            <ForwardsPanel embed host={host} onClose={() => setTab('overview')} onOpenSession={props.onOpenSession} />
          </Suspense>
        )}
        {tab === 'services' && (
          <Suspense fallback={paneFallback}>
            <ServicesPanel embed host={host} onClose={() => setTab('overview')} onJournal={(unit) => props.onJournal(host, unit)} />
          </Suspense>
        )}
        {tab === 'docker' && (
          <Suspense fallback={paneFallback}>
            <DockerPanel embed host={host} onClose={() => setTab('overview')} onOpenContainerShell={(cid) => props.onContainerShell(host, cid)} />
          </Suspense>
        )}
        {tab === 'databases' && (
          <Suspense fallback={paneFallback}>
            <ToolboxPanel embed host={host} onClose={() => setTab('overview')} onOpen={(h, cid) => props.onConnectionOpen(h, cid)} />
          </Suspense>
        )}
        </div>
      </div>

      {playing && (
        <TranscriptPlayer sid={playing.id} title={playing.title} onClose={() => setPlaying(null)} />
      )}
    </div>
  )
}

/** Card-thumbnail pentru o sesiune activă: un preview LIVE read-only (xterm auto-fit) +
    titlu + acţiuni la hover (split/popout). Click pe card = deschide terminalul. Dă paginii
    Overview un aer de dashboard, nu o listă de butoane. */
function SessionThumb(props: {
  session: Session
  onOpen: () => void
  onSplit: () => void
  onPopout: () => void
}) {
  const { t } = useI18n()
  const s = props.session
  return (
    <div className="group relative overflow-hidden rounded-xl bg-ink-900 ring-1 ring-ink-700 transition hover:ring-sky-500/60">
      <button onClick={props.onOpen} className="block w-full text-left"
        title={t('host.openTerminal')} aria-label={`${s.title || t('host.sessionFallback')} — ${t('host.openTerminal')}`}>
        {/* fereastra de preview: raport ~16:10, fundal de terminal; SessionPreview se auto-fit-ează */}
        <div className="relative h-[150px] w-full overflow-hidden bg-[#0b0e14]">
          <SessionPreview key={s.id} sid={s.id} live />
          {/* overlay „deschide" la hover */}
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center bg-black/0 opacity-0 transition group-hover:bg-black/30 group-hover:opacity-100">
            <span className="rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-medium text-white shadow-lg">{t('host.openTerminal')}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 px-3 py-2">
          <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-400 dot-live" />
          <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{s.title || t('host.sessionFallback')}</span>
          {s.connected_clients > 0 && <span className="shrink-0 text-[11px] text-slate-500">👁 {s.connected_clients}</span>}
        </div>
      </button>
      {/* acţiuni rapide — apar la hover, pe ecrane mari (split/popout cer spaţiu) */}
      <div className="absolute right-1.5 top-1.5 hidden gap-1 opacity-0 transition group-hover:opacity-100 lg:flex">
        <button onClick={props.onSplit} title={t('host.splitTitle')} aria-label={t('host.splitTitle')}
          className="grid h-7 w-7 place-items-center rounded-md bg-ink-900/80 text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 hover:text-white"><SplitIcon /></button>
        <button onClick={props.onPopout} title={t('host.popoutTitle')} aria-label={t('host.popoutTitle')}
          className="grid h-7 w-7 place-items-center rounded-md bg-ink-900/80 text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 hover:text-white"><PopoutIcon /></button>
      </div>
    </div>
  )
}

/** Prag de culoare pentru metrici: verde <70% · chihlimbar <90% · roşu peste. */
function pctColor(p: number): string {
  return p < 70 ? '#10b981' : p < 90 ? '#f59e0b' : '#f43f5e'
}

/** Inel de progres cu procentul în centru — gauge-ul de dashboard. */
function Gauge({ pct, color, size = 60 }: { pct: number; color: string; size?: number }) {
  const v = Math.max(0, Math.min(100, Math.round(pct)))
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 40 40" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="20" cy="20" r="16" fill="none" strokeWidth="3.5" className="stroke-ink-700" />
        <circle cx="20" cy="20" r="16" fill="none" strokeWidth="3.5" strokeLinecap="round"
          pathLength={100} strokeDasharray="100" strokeDashoffset={100 - v} style={{ stroke: color }}
          className="transition-[stroke-dashoffset,stroke] duration-500 ease-out motion-reduce:transition-none" />
      </svg>
      <span className="absolute inset-0 grid place-items-center font-mono text-sm font-semibold tabular-nums" style={{ color }}>{v}%</span>
    </div>
  )
}

/** Un tile de metrică: etichetă + gauge (ori cifră mare) + sub-text + sparkline opţional. */
function StatTile(props: { label: string; pct?: number; big?: string; sub?: string; spark?: number[]; sparkLabel?: string }) {
  const color = props.pct != null ? pctColor(props.pct) : '#94a3b8'
  return (
    <div className="rounded-2xl border border-ink-700/70 bg-ink-800/40 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{props.label}</div>
          {props.big != null && <div className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-slate-100">{props.big}</div>}
          {props.sub && <div className="mt-1 truncate font-mono text-xs text-slate-500 tabular-nums">{props.sub}</div>}
        </div>
        {props.pct != null && <Gauge pct={props.pct} color={color} />}
      </div>
      {props.spark && props.spark.length > 1 && (
        <div className="mt-3 overflow-hidden">
          <Sparkline values={props.spark} width={200} height={26} label={props.sparkLabel ?? props.label} />
        </div>
      )}
    </div>
  )
}

/** Rândul de tile-uri metrice — inima dashboard-ului. Doar host de agent online cu metrici. */
function StatTiles({ host }: { host: Host }) {
  const { t } = useI18n()
  const m = host.metrics
  const hist = hostHistory(host.id)
  if (!host.online || !m || m.cpu_pct == null) return null
  const gib = (n?: number) => (n != null ? (n / 1024 ** 3).toFixed(1) : null)
  const memPct = m.mem_total && m.mem_used != null ? (m.mem_used / m.mem_total) * 100 : null
  const diskPct = m.disk_total && m.disk_used != null ? (m.disk_used / m.disk_total) * 100 : null
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatTile label="CPU" pct={m.cpu_pct} spark={hist?.cpu} sparkLabel={t('host.cpuChartLabel', { name: host.name })} />
      {memPct != null && (
        <StatTile label={t('host.memory')} pct={memPct} sub={`${gib(m.mem_used)} / ${gib(m.mem_total)} GiB`}
          spark={hist?.mem} sparkLabel={t('host.memChartLabel', { name: host.name })} />
      )}
      {diskPct != null && (
        <StatTile label={t('host.disk')} pct={diskPct} sub={`${gib(m.disk_used)} / ${gib(m.disk_total)} GiB`} />
      )}
      {m.load1 != null && (
        <StatTile label="Load" big={m.load1.toFixed(2)} sub={`5m ${(m.load5 ?? 0).toFixed(2)} · 15m ${(m.load15 ?? 0).toFixed(2)}`} />
      )}
    </div>
  )
}

/** Card de informaţii cu icon-chip colorat + eyebrow. */
function Card(props: { title: string; icon?: React.ReactNode; accent?: string; className?: string; children: React.ReactNode }) {
  const accent = props.accent ?? '#64748b'
  return (
    <div className={`rounded-2xl border border-ink-700/70 bg-ink-800/40 p-4 ${props.className ?? ''}`}>
      <div className="mb-2.5 flex items-center gap-2.5">
        {props.icon && (
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg [&>svg]:h-4 [&>svg]:w-4"
            style={{ background: `${accent}1a`, color: accent }}>{props.icon}</span>
        )}
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{props.title}</h3>
      </div>
      <dl>{props.children}</dl>
    </div>
  )
}

/** Cardurile de info ale hostului: conexiune, securitate, agent, apps, notă. */
function HostDetail({ host }: { host: Host }) {
  const { t } = useI18n()
  const isAgent = (host.connection_type ?? 'agent') === 'agent'
  const credPolicy = host.credential_policy === 'ask' ? t('host.credAsk')
    : host.credential_policy === 'ephemeral' ? t('host.credEphemeral')
    : host.has_credentials ? t('host.credStored') : t('host.credNone')
  const [hostApps, setHostApps] = useState<AppLink[]>([])
  useEffect(() => {
    let gone = false
    api<AppLink[]>('/api/apps')
      .then((all) => { if (!gone) setHostApps(all.filter((a) => a.host_id === host.id)) })
      .catch(() => { if (!gone) setHostApps([]) })
    return () => { gone = true }
  }, [host.id])

  return (
    <div className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-3">
      <Card title={t('host.secConnection')} icon={<ServerIcon />} accent={hostColor(host)}>
        <Row k={t('host.protocol')} v={protoLabel(host)} />
        <Row k={t('host.address')} v={host.hostname ? hostAt(host) : '—'} mono />
        {!isAgent && <Row k={t('host.authentication')} v={host.auth_method === 'key' ? t('host.sshKey') : host.auth_method === 'password' ? t('host.passwordLabel') : '—'} />}
        {host.backend && <Row k="Backend" v={host.backend} mono />}
        <Row k={t('host.status')} v={host.online ? 'online' : isAgent ? 'offline' : t('host.connectOnDemand')}
          tone={host.online ? 'good' : undefined} />
      </Card>

      <Card title={t('host.secSecurity')} icon={<ShieldIcon />} accent="#38bdf8">
        <Row k={t('host.twoFaOnConnect')} v={host.require_2fa ? t('host.yesPasskey') : t('host.no')} tone={host.require_2fa ? 'good' : undefined} />
        <Row k={t('host.credentials')} v={credPolicy} />
      </Card>

      {isAgent && (
        <Card title={t('host.agent')} icon={<RefreshIcon />} accent="#a78bfa">
          <Row k={t('host.version')} v={host.agent_version != null ? `v${host.agent_version}` : t('host.notInstalled')}
            badge={host.update_pending ? t('host.updateAvailable') : undefined} />
          {host.last_heartbeat != null && <Row k={t('host.lastActivity')} v={timeAgo(host.last_heartbeat, t)} />}
        </Card>
      )}

      {hostApps.length > 0 && (
        <Card title={t('dashboard.apps')} icon={<LinkIcon />} accent="#34d399" className="md:col-span-2 xl:col-span-3">
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {hostApps.map((a) => {
              const color = HOST_APP_COLOR[a.app_type] || '#34d399'
              return (
                <a key={a.id} href={a.enabled ? a.url : undefined} target="_blank" rel="noopener noreferrer"
                  title={a.enabled ? a.url : t('dashboard.appDisabled')}
                  className={`group flex items-center gap-3 rounded-xl border border-ink-700 bg-ink-900/40 px-3 py-2.5 ${
                    a.enabled ? 'hover:border-ink-500 hover:bg-ink-800' : 'cursor-not-allowed opacity-50'}`}>
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg font-mono text-sm font-bold"
                    style={{ background: `${color}22`, color }}>{a.label.slice(0, 1).toUpperCase()}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-slate-200">{a.label}</span>
                    <span className="block truncate font-mono text-[11px] text-slate-500">{a.url.replace(/^https?:\/\//, '')}</span>
                  </span>
                  {a.enabled && <span className="shrink-0 text-slate-600 group-hover:text-slate-400">↗</span>}
                </a>
              )
            })}
          </div>
        </Card>
      )}

      {host.note && (
        <Card title={t('host.secNote')} icon={<NoteIcon />} className="md:col-span-2 xl:col-span-3">
          <p className="text-sm text-slate-400">{host.note}</p>
        </Card>
      )}
    </div>
  )
}

function Row(props: { k: string; v: string; mono?: boolean; tone?: 'good'; badge?: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-ink-800/60 py-2 last:border-0">
      <dt className="shrink-0 text-sm text-slate-500">{props.k}</dt>
      <dd className={`min-w-0 truncate text-right text-sm ${props.tone === 'good' ? 'wt-good' : 'text-slate-200'} ${props.mono ? 'font-mono' : ''}`}>
        {props.v}
        {props.badge && (
          <span className="ml-2 rounded bg-amber-500/15 px-1.5 py-0.5 align-middle text-[10px] font-semibold uppercase tracking-wide text-amber-400">{props.badge}</span>
        )}
      </dd>
    </div>
  )
}
