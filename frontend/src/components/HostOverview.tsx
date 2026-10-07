import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { errText, isSessionLive, api, AppLink, Host, HostSupervision, Session, timeAgo, withStepup } from '../lib/api'
import { hostAt, hostColor, protoLabel, reachState } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { peekFilesDir } from '../lib/uploads'
import { useConfirm } from '../lib/confirm'
import { notify, notifyError } from '../lib/notify'
import { askSecret } from '../lib/secretPrompt'
import { hostHistory } from '../lib/metrics'
import { pressureColor, pressureTextColor } from '../lib/thresholds'
import { updatesSignal, useUpdatesPref } from '../lib/updatesPref'
import { ArrowRightIcon, ArrowUpIcon, ArrowUpRightIcon, DockerIcon, DownloadIcon, EyeIcon, FilesIcon, ForwardIcon, LinkIcon, MenuIcon, NoteIcon, PencilIcon, PlayIcon, PlugIcon, PlusIcon, PopoutIcon, RefreshIcon, ServerIcon, ServicesIcon, ShieldIcon, SparkleIcon, SplitIcon, StethoscopeIcon, TerminalPromptIcon, ToolboxIcon, TrashIcon } from './Icons'
import { Badge, Button, Card, EmptyState, IconButton, cardClass, iconButtonClass } from './ui'
import SessionPreview from './SessionPreview'
import Sparkline from './Sparkline'
import TranscriptPlayer from './TranscriptPlayer'
import HelpTip from './HelpTip'
import type { HelpId } from '../lib/help'

// Panourile hub-ului se încarcă DOAR când deschizi tab-ul lor (FilePanel aduce Monaco — mare),
// nu în bundle-ul paginii de host. `embed` le randează full-width, fără drawer/scrim/close.
const FilePanel = lazy(() => import('./FilePanel'))
const ForwardsPanel = lazy(() => import('./ForwardsPanel'))
const ServicesPanel = lazy(() => import('./ServicesPanel'))
const DockerPanel = lazy(() => import('./DockerPanel'))
const ToolboxPanel = lazy(() => import('./ToolboxPanel'))
const AiToolsPanel = lazy(() => import('./AiToolsPanel'))

type HubTab = 'overview' | 'sessions' | 'files' | 'forwards' | 'services' | 'docker' | 'databases' | 'ai'

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
  onEdit: (host: Host) => void
}) {
  const { t } = useI18n()
  // confirm() nativ → dialog propriu (vezi lib/confirm.tsx: de ce)
  const { confirm } = useConfirm()
  const { host } = props
  const canConnect = host.connection_type !== 'agent' || host.online
  const isAgent = (host.connection_type ?? 'agent') === 'agent'
  const agentReady = isAgent && !!host.online      // tab-urile prin agent cer agentul online
  const m = host.metrics
  const [tab, setTab] = useState<HubTab>('overview')
  // bara de transferuri poate cere „deschide Files în directorul X" (upload orfan): atunci
  // pornim direct pe tab-ul Files; FilePanel consumă directorul (lib/uploads.ts)
  useEffect(() => { setTab(peekFilesDir(host.id) ? 'files' : 'overview') }, [host.id])
  useEffect(() => {
    const onOpen = (e: Event) => {
      if ((e as CustomEvent<{ hostId: number }>).detail.hostId === host.id) setTab('files')
    }
    window.addEventListener('wt-open-files', onOpen)
    return () => window.removeEventListener('wt-open-files', onOpen)
  }, [host.id])

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
    // Rândul = două butoane surori (nu imbricate): clicul pe corp alege previzualizarea,
    // „Deschide" e vizibil mereu — dublu-clicul rămâne scurtătură, dar nu mai e singura cale.
    return (
      <div key={s.id} className={`flex w-full items-center ${
        selected === s.id ? 'bg-ink-800' : 'hover:bg-ink-800/50'
      }`}>
      <button
        type="button"
        onClick={() => setSelected(s.id)}
        onDoubleClick={() => props.onOpenSession(s.id)}
        aria-pressed={selected === s.id}
        title={t('host.rowPreview')}
        className="flex min-w-0 flex-1 items-center gap-2.5 py-2 pl-3 pr-1 text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-sky-500"
      >
        <span aria-hidden="true" className={`h-2 w-2 shrink-0 ${s.state === 'lost' ? 'rounded-md' : 'rounded-full'} ${
          live ? 'bg-emerald-400 dot-live' : s.state === 'lost' ? 'bg-rose-500' : 'bg-slate-600'}`} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm text-slate-200">{s.title || t('host.sessionFallback')}</span>
          <span className="block truncate text-2xs text-slate-600">
            {live ? t('host.stateActive') : s.state === 'lost' ? t('host.stateLost') : t('host.stateClosed')}
            {s.exit_status != null ? ` · exit ${s.exit_status}` : ''} · {timeAgo(s.closed_at || s.created, t)}
          </span>
        </span>
        {s.connected_clients > 0 && <span className="flex shrink-0 items-center gap-1 text-2xs text-slate-500"><EyeIcon /> {s.connected_clients}</span>}
      </button>
      <button
        type="button"
        onClick={() => props.onOpenSession(s.id)}
        aria-label={t('host.rowOpenAria', { name: s.title || t('host.sessionFallback') })}
        className="wt-link mr-2 shrink-0 rounded-md px-2 py-1 text-xs font-medium ring-1 ring-ink-700 hover:bg-ink-700"
      >{t('host.rowOpen')}</button>
      </div>
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
    { id: 'ai', label: t('host.tabAi'), show: agentReady, icon: <SparkleIcon /> },
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
        <IconButton size="md" onClick={props.onMenu} className={props.sidebarCollapsed ? '' : 'md:hidden'} label={t('host.openHostListAria')}>
          <MenuIcon />
        </IconButton>
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
              <Badge tone="accent" className="py-0.5 uppercase tracking-wide">
                {host.connection_type}
              </Badge>
            )}
          </div>
          <div className="mt-0.5 truncate text-sm text-slate-500">
            <span className="font-mono">{host.hostname ? `${host.ssh_username || host.agent_user || ''}@${host.hostname}` : t('host.notConfigured')}</span>
            {' · '}
            <span className={host.online ? 'wt-good' : 'text-slate-500'}>
              {host.online ? t('host.statusOnline') : (isAgent ? t('host.statusOffline') : t('host.connectOnDemand'))}
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
          {/* Edit host — pe bară, lângă New session (Serial/Diagnostic au trecut în nav → Tools) */}
          <Button variant="secondary" size="lg" onClick={() => props.onEdit(host)} title={t('host.editHost')} className="wt-touch">
            <PencilIcon /> <span className="hidden sm:inline">{t('host.editHost')}</span>
          </Button>
          <Button variant="primary" size="lg" disabled={!canConnect} onClick={() => props.onNewSession(host)} className="wt-touch">
            <PlusIcon /> {t('host.newSession')}
          </Button>
        </div>

      </div>

      {/* ── corp: nav vertical (stânga pe desktop, rând derulabil pe mobil) + conţinut ── */}
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <nav aria-label={t('host.sections')}
          className="flex shrink-0 gap-1 overflow-x-auto border-b border-ink-800 p-2 md:w-52 md:flex-col md:overflow-x-visible md:overflow-y-auto md:border-b-0 md:border-r">
          {visibleTabs.map((x) => (
            <button key={x.id} onClick={() => setTab(x.id)} aria-current={tab === x.id ? 'page' : undefined}
              className={`flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition md:w-full ${
                tab === x.id ? 'bg-ink-800 text-slate-100 ring-1 ring-ink-700'
                             : 'text-slate-400 hover:bg-ink-800/50 hover:text-slate-200'}`}>
              <span className="grid h-4 w-4 shrink-0 place-items-center opacity-80">{x.icon}</span>
              {x.label}
              {x.id === 'sessions' && active.length > 0 && (
                <Badge tone="ok" className="ml-auto">{active.length}</Badge>
              )}
            </button>
          ))}

          {/* Tools: acţiuni (deschid o sesiune/un modal), NU tab-uri — Serial + Diagnostic */}
          {(agentReady || isAgent) && (
            <>
              <div className="mx-2 my-1 hidden self-stretch border-t border-ink-800 md:block" aria-hidden="true" />
              <div className="hidden px-3 pb-0.5 pt-1 text-2xs font-semibold uppercase tracking-wider text-slate-600 md:block">{t('host.tools')}</div>
              {agentReady && (
                <button onClick={() => props.onSerial(host)}
                  className="flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium text-slate-400 transition hover:bg-ink-800/50 hover:text-slate-200 md:w-full">
                  <span className="grid h-4 w-4 shrink-0 place-items-center opacity-80"><PlugIcon /></span>
                  {t('host.serialConsole')}
                </button>
              )}
              {isAgent && (
                <button onClick={() => props.onDiagnostic(host)}
                  className="flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium text-slate-400 transition hover:bg-ink-800/50 hover:text-slate-200 md:w-full">
                  <span className="grid h-4 w-4 shrink-0 place-items-center opacity-80"><StethoscopeIcon /></span>
                  {t('host.diagnostic')}
                </button>
              )}
            </>
          )}
        </nav>

        {/* ── conţinutul secţiunii ── */}
        <div className="flex min-h-0 flex-1 flex-col">
        {tab === 'overview' && (
          <div className="min-h-0 flex-1 overflow-y-auto p-4 sm:p-6">
            <div className="mx-auto max-w-6xl space-y-6">
              {/* banda de status — identitate + fapte-cheie, accent = culoarea hostului. Umple
                  partea de sus şi pe hosturile fără metrici (nu mai rămâne spaţiu mort). */}
              <StatusBand host={host} />
              {host.backend === 'pty' && (
                <p className="wt-warn rounded-xl bg-amber-500/10 p-3 text-sm ring-1 ring-amber-500/30">
                  {t('host.noTmuxWarning')}
                </p>
              )}
              {/* rândul de metrici — inima dashboard-ului (doar agent online cu metrici) */}
              <StatTiles host={host} />

              {active.length > 0 && (
                <section>
                  <div className="mb-3 flex items-center gap-2 text-2xs font-semibold uppercase tracking-wider text-slate-500">
                    {t('host.active')} <span className="text-slate-600">· {active.length}</span>
                    <button onClick={() => setTab('sessions')} className="wt-link ml-auto inline-flex items-center gap-1 rounded-md px-1 py-1 text-2xs normal-case">{t('host.allSessions')} <ArrowRightIcon size={11} /></button>
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

              {/* stare goală: fără sesiuni active, nu lăsăm un ecran pustiu — un îndemn clar */}
              {active.length === 0 && (
                <EmptyState framed tone="neutral"
                  icon={<TerminalPromptIcon />}
                  title={t('host.noActiveSessions')}
                  action={(
                    <div className="flex items-center gap-2">
                      <Button variant="primary" size="lg" disabled={!canConnect} onClick={() => props.onNewSession(host)}>
                        <PlusIcon /> {t('host.newSession')}
                      </Button>
                      {closed.length > 0 && (
                        <Button variant="secondary" size="lg" onClick={() => setTab('sessions')}>
                          {t('host.closed')} · {closed.length}
                        </Button>
                      )}
                    </div>
                  )}
                />
              )}

              <HostDetail host={host} />
            </div>
          </div>
        )}

        {tab === 'sessions' && (
          <div className="flex min-h-0 flex-1 flex-col md:flex-row">
            <div className="max-h-[38%] w-full shrink-0 overflow-y-auto border-b border-ink-800 md:max-h-none md:w-[320px] md:border-b-0 md:border-r">
              <div className="px-3 pb-1 pt-3 text-2xs font-semibold uppercase tracking-wide text-slate-500">
                {t('host.active')} {active.length > 0 && <span className="text-slate-600">· {active.length}</span>}
              </div>
              {active.length === 0
                ? <p className="px-3 pb-2 text-xs text-slate-600">{t('host.noActiveSessions')}</p>
                : active.map(row)}
              {closed.length > 0 && (
                <>
                  <div className="px-3 pb-1 pt-4 text-2xs font-semibold uppercase tracking-wide text-slate-500">
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
                      <div className="truncate text-2xs text-slate-600">
                        {selLive ? t('host.previewLive') : t('host.previewHistory')} · {timeAgo(sel.closed_at || sel.created, t)}
                      </div>
                    </div>
                    <IconButton size="md" touch={false} onClick={() => props.onSplit(sel.id)} label={t('host.splitTitle')}
                      className="hidden lg:grid"><SplitIcon /></IconButton>
                    <IconButton size="md" touch={false} onClick={() => props.onPopout(sel.id)} label={t('host.popoutTitle')}
                      className="hidden lg:grid"><PopoutIcon /></IconButton>
                    {!selLive && (
                      <IconButton size="md" onClick={() => setPlaying(sel)} label={t('host.playTitle')}><PlayIcon /></IconButton>
                    )}
                    <a href={`/api/sessions/${sel.id}/transcript?format=cast`} download title={t('host.downloadTitle')}
                      className={iconButtonClass('ghost', 'md')}><DownloadIcon /></a>
                    {!selLive && (
                      <IconButton size="md" variant="danger" onClick={async () => {
                          if (!(await confirm({
                            title: t('host.deleteTitle'), message: t('session.confirmDelete'),
                            danger: true, confirmLabel: t('session.delete'),
                          }))) return
                          setDeletedIds((prev) => new Set(prev).add(sel.id))
                          props.onDeleteSession(sel.id); setSelected(null)
                        }} label={t('host.deleteTitle')}><TrashIcon /></IconButton>
                    )}
                    <Button variant="primary" onClick={() => props.onOpenSession(sel.id)} className="wt-touch ml-1">
                      {selLive ? t('host.openTerminal') : t('host.viewHistory')}
                    </Button>
                  </div>
                  <div className="min-h-0 flex-1 bg-[#0b0e14] p-2">
                    <SessionPreview key={sel.id} sid={sel.id} live={selLive} />
                  </div>
                </>
              ) : (
                <EmptyState className="h-full" title={t('host.noSessionsYet')}
                  action={(
                    <Button variant="primary" size="lg" disabled={!canConnect} onClick={() => props.onNewSession(host)}>
                      <PlusIcon /> {t('host.newSession')}
                    </Button>
                  )} />
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
        {tab === 'ai' && (
          <Suspense fallback={paneFallback}>
            <AiToolsPanel embed host={host} onClose={() => setTab('overview')} />
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

/** Preview-text al unei sesiuni pentru thumbnail: ia coada transcriptului, curăţă secvenţele
    ANSI/OSC + octeţii de control şi arată ultimele linii VIZIBILE ca text mono. Fiabil la orice
    dimensiune (spre deosebire de un xterm minuscul, care rămânea negru); gol → placeholder. */
function ThumbPreview({ sid, live }: { sid: string; live: boolean }) {
  const { t } = useI18n()
  const [text, setText] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await fetch(`/api/sessions/${sid}/preview`, { credentials: 'same-origin' })
        if (!r.ok || cancelled) return
        const s = new TextDecoder().decode(new Uint8Array(await r.arrayBuffer()))
        const clean = s
          .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, '')    // OSC (BEL/ST)
          .replace(/\x1b[PX^_][\s\S]*?\x1b\\/g, '')          // DCS/PM/APC/SOS
          .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')           // CSI (inclusiv privat: ? > < =)
          .replace(/\x1b[()*+][\x20-\x7e]/g, '')             // charset
          .replace(/\x1b[=>Fclmno|}~]/g, '')                 // misc escape simplu
          .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '')          // alte caractere de control
        if (cancelled) return
        // ecranul unui shell e mai ales gol (promptul într-un colţ al unui grid de 24 rânduri);
        // păstrăm DOAR liniile cu text vizibil, compact şi sus-aliniat — altfel promptul ateriza
        // după ~13 rânduri goale şi thumbnail-ul părea negru.
        const lines = clean.split('\n').map((l) => l.replace(/\s+$/, '')).filter((l) => l !== '')
        setText(lines.slice(-14).join('\n'))
      } catch { /* ignoră */ }
    }
    load()
    const timer = live ? setInterval(() => { if (!document.hidden) load() }, 3000) : undefined
    return () => { cancelled = true; if (timer) clearInterval(timer) }
  }, [sid, live])

  if (!text || !text.trim()) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-1.5 text-slate-600">
        <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
          <rect x="3" y="4" width="18" height="16" rx="2" />
          <path d="M7 9l3 3-3 3M13 15h4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="text-2xs">{t('host.previewEmpty')}</span>
      </div>
    )
  }
  return (
    // miniatură = imagine a ecranului (excepţie de la scara tipografică, vezi design.guard.test.ts)
    <pre aria-hidden="true" className="h-full w-full overflow-hidden whitespace-pre px-2.5 py-2 font-mono text-[9px] leading-[1.4] text-slate-400">{text}</pre>
  )
}

/** Card-thumbnail pentru o sesiune activă: snapshot text al transcriptului + titlu + acţiuni la
    hover (split/popout). Click pe card = deschide terminalul. Dă paginii Overview aer de dashboard. */
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
        {/* fereastra de preview: snapshot text al transcriptului (fiabil la orice dimensiune) */}
        <div className="relative h-[132px] w-full overflow-hidden bg-[#0b0e14]">
          <ThumbPreview sid={s.id} live />
          {/* overlay „deschide" la hover */}
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center bg-black/0 opacity-0 transition group-hover:bg-black/30 group-hover:opacity-100">
            <span className="rounded-xl bg-sky-600 px-3 py-1.5 text-xs font-medium text-white shadow-lg">{t('host.openTerminal')}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 px-3 py-2">
          <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-400 dot-live" />
          <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{s.title || t('host.sessionFallback')}</span>
          {s.connected_clients > 0 && <span className="flex shrink-0 items-center gap-1 text-2xs text-slate-500"><EyeIcon /> {s.connected_clients}</span>}
        </div>
      </button>
      {/* acţiuni rapide — apar la hover ŞI când focusul e înăuntru (altfel erau focusabile dar
          invizibile: focusul „dispărea" pe card), pe ecrane mari (split/popout cer spaţiu) */}
      <div className="absolute right-1.5 top-1.5 hidden gap-1 opacity-0 transition focus-within:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100 lg:flex">
        <button onClick={props.onSplit} title={t('host.splitTitle')} aria-label={t('host.splitTitle')}
          className="grid h-7 w-7 place-items-center rounded-md bg-ink-900/80 text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 hover:text-white"><SplitIcon /></button>
        <button onClick={props.onPopout} title={t('host.popoutTitle')} aria-label={t('host.popoutTitle')}
          className="grid h-7 w-7 place-items-center rounded-md bg-ink-900/80 text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 hover:text-white"><PopoutIcon /></button>
      </div>
    </div>
  )
}

/** Inel de progres cu procentul în centru — gauge-ul de dashboard. Pragurile şi culorile vin din
    lib/thresholds (aceleaşi ca Sparkline şi HostLoadRing): arcul ia culoarea de grafic, cifra pe
    cea de text (AA pe ambele teme). */
function Gauge({ pct, size = 60 }: { pct: number; size?: number }) {
  const v = Math.max(0, Math.min(100, Math.round(pct)))
  const color = pressureColor(pct)
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 40 40" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="20" cy="20" r="16" fill="none" strokeWidth="3.5" className="stroke-ink-700" />
        <circle cx="20" cy="20" r="16" fill="none" strokeWidth="3.5" strokeLinecap="round"
          pathLength={100} strokeDasharray="100" strokeDashoffset={100 - v} style={{ stroke: color }}
          className="transition-[stroke-dashoffset,stroke] duration-500 ease-out motion-reduce:transition-none" />
      </svg>
      <span className="absolute inset-0 grid place-items-center font-mono text-sm font-semibold tabular-nums" style={{ color: pressureTextColor(pct) }}>{v}%</span>
    </div>
  )
}

/** Un tile de metrică: etichetă + gauge (ori cifră mare) + sub-text + sparkline opţional. */
function StatTile(props: { label: string; pct?: number; big?: string; sub?: string; spark?: number[]; sparkLabel?: string }) {
  return (
    <Card>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-2xs font-semibold uppercase tracking-wider text-slate-500">{props.label}</div>
          {props.big != null && <div className="mt-2 font-mono text-3xl font-semibold leading-none tabular-nums text-slate-100">{props.big}</div>}
          {props.sub && <div className="mt-1.5 truncate font-mono text-xs text-slate-500 tabular-nums">{props.sub}</div>}
        </div>
        {props.pct != null && <Gauge pct={props.pct} size={64} />}
      </div>
      {props.spark && props.spark.length > 1 && (
        <div className="mt-3">
          <Sparkline fluid values={props.spark} height={28} label={props.sparkLabel ?? props.label} />
        </div>
      )}
    </Card>
  )
}

/** Banda de status — hero-ul paginii: stare mare + fapte-cheie, cu accentul culorii hostului.
    Prezentă mereu, deci pagina are identitate şi când hostul n-are metrici/sesiuni. */
function StatusBand({ host }: { host: Host }) {
  const { t } = useI18n()
  const updPref = useUpdatesPref()
  const reach = reachState(host)
  const color = hostColor(host)
  const isAgent = (host.connection_type ?? 'agent') === 'agent'
  const label = reach === 'online' ? t('host.statusOnline')
    : reach === 'ondemand' ? t('host.statusOndemand') : t('host.statusOffline')
  const dot = reach === 'online' ? 'bg-emerald-400' : reach === 'ondemand' ? 'bg-sky-500' : 'bg-slate-500'
  const tone = reach === 'online' ? 'wt-good' : reach === 'ondemand' ? 'wt-accent' : 'text-slate-400'
  // sub-linia: adresa, iar pe un agent căzut „de cât timp" (context de incident la o privire)
  const sub = reach === 'offline' && host.last_heartbeat
    ? t('host.lastSeen', { ago: timeAgo(host.last_heartbeat, t) })
    : host.hostname ? hostAt(host) : protoLabel(host)
  // chip-urile sunt rezumatul de sus; detaliul (versiune agent, 2FA, auth) stă în carduri,
  // ca să nu dublăm. Aici doar semnale „la o privire": backend, update-uri OS, etichete.
  const chips: { label: React.ReactNode; tone?: 'warn' | 'danger'; title?: string }[] = []
  if (isAgent && host.backend) chips.push({ label: host.backend })
  // update-uri OS: pe pagina hostului (unde ai venit deliberat) chip-ul apare mereu, dar NEUTRU;
  // accent doar pentru securitate şi doar dacă semnalul nu e mascat (global sau per host)
  if (host.updates && host.updates.count > 0) {
    const sig = updatesSignal(host.id, host.updates, updPref.mode, updPref.muted)
    chips.push({
      label: <><ArrowUpIcon size={11} /> {host.updates.count}</>, tone: sig === 'security' ? 'danger' : undefined,
      title: host.updates.security
        ? t('updates.chipSecTitle', { count: host.updates.count, sec: host.updates.security })
        : t('updates.chipTitle', { count: host.updates.count }),
    })
  }
  for (const tag of (host.tags || []).slice(0, 5)) chips.push({ label: tag })
  return (
    <div className={`relative overflow-hidden ${cardClass} p-5`}>
      {/* glow discret în culoarea hostului — identitate fără zgomot */}
      <div className="pointer-events-none absolute -right-20 -top-24 h-56 w-56 rounded-full opacity-[0.08] blur-3xl" style={{ background: color }} aria-hidden="true" />
      <div className="relative flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${dot} ${reach === 'online' ? 'dot-live' : ''}`} />
            <span className={`text-xl font-semibold ${tone}`}>{label}</span>
          </div>
          <div className="mt-1 truncate font-mono text-sm text-slate-500">{sub}</div>
        </div>
        {chips.length > 0 && (
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {chips.map((c, i) => (
              <span key={i} title={c.title} className={`inline-flex items-center gap-0.5 rounded-md px-2.5 py-1 text-xs font-medium ring-1 ${
                c.tone === 'danger' ? 'bg-danger/10 text-danger ring-danger/30'
                : c.tone === 'warn' ? 'bg-warn/10 text-warn ring-warn/30'
                : 'bg-ink-900/50 text-slate-400 ring-ink-700'}`}>{c.label}</span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/** Rândul de tile-uri metrice — inima dashboard-ului. Doar host de agent online cu metrici. */
function StatTiles({ host }: { host: Host }) {
  const { t } = useI18n()
  const m = host.metrics
  const hist = hostHistory(host.id)
  // NU condiţiona pe cpu_pct: primul sample de CPU vine mai târziu (nevoie de 2 citiri), iar
  // mem/disk/load sunt deja acolo — altfel tot rândul dispărea până „se încălzea" CPU-ul.
  if (!host.online || !m) return null
  const gib = (n?: number) => (n != null ? (n / 1024 ** 3).toFixed(1) : null)
  const memPct = m.mem_total && m.mem_used != null ? (m.mem_used / m.mem_total) * 100 : null
  const diskPct = m.disk_total && m.disk_used != null ? (m.disk_used / m.disk_total) * 100 : null
  if (m.cpu_pct == null && memPct == null && diskPct == null && m.load1 == null) return null
  return (
    // auto-fit: 2-4 tile-uri umplu lăţimea egal (CPU vine mai târziu → fără celulă goală)
    <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))' }}>
      {m.cpu_pct != null && (
        <StatTile label="CPU" pct={m.cpu_pct} spark={hist?.cpu} sparkLabel={t('host.cpuChartLabel', { name: host.name })} />
      )}
      {memPct != null && (
        <StatTile label={t('host.memory')} pct={memPct} sub={`${gib(m.mem_used)} / ${gib(m.mem_total)} GiB`}
          spark={hist?.mem} sparkLabel={t('host.memChartLabel', { name: host.name })} />
      )}
      {diskPct != null && (
        <StatTile label={t('host.disk')} pct={diskPct} sub={`${gib(m.disk_used)} / ${gib(m.disk_total)} GiB`} />
      )}
      {m.load1 != null && (
        <StatTile label={t('host.load')} big={m.load1.toFixed(2)} sub={`5m ${(m.load5 ?? 0).toFixed(2)} · 15m ${(m.load15 ?? 0).toFixed(2)}`} />
      )}
    </div>
  )
}

/** Card de informaţii cu icon-chip colorat + eyebrow. */
function InfoCard(props: { title: string; icon?: React.ReactNode; accent?: string; className?: string; children: React.ReactNode }) {
  const accent = props.accent ?? '#64748b'
  return (
    <Card className={props.className}>
      <div className="mb-2.5 flex items-center gap-2.5">
        {props.icon && (
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md [&>svg]:h-4 [&>svg]:w-4"
            style={{ background: `${accent}1a`, color: accent }}>{props.icon}</span>
        )}
        <h3 className="text-2xs font-semibold uppercase tracking-wider text-slate-500">{props.title}</h3>
      </div>
      <dl>{props.children}</dl>
    </Card>
  )
}

/** Cardurile de info ale hostului: conexiune, securitate, agent, apps, notă. */
function HostDetail({ host }: { host: Host }) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const [forgetting, setForgetting] = useState(false)
  const isAgent = (host.connection_type ?? 'agent') === 'agent'
  const credPolicy = host.credential_policy === 'ask' ? t('host.credAsk')
    : host.credential_policy === 'ephemeral' ? t('host.credEphemeral')
    : host.has_credentials ? t('host.credStored') : t('host.credNone')
  // Ruta exista de la F-05, dar niciun buton n-o chema. Ireversibil: pe un host fără agent,
  // credenţiala stocată era singurul drum până la el — de aici confirmarea + parola contului.
  const forgetCreds = async () => {
    const ok = await confirm({
      title: t('host.forgetCredsTitle', { host: host.name }),
      message: isAgent ? t('host.forgetCredsMsgAgent') : t('host.forgetCredsMsgSsh'),
      confirmLabel: t('host.forgetCreds'), danger: true,
    })
    if (!ok) return
    const pw = await askSecret(t('host.forgetCredsPassword'))
    if (!pw) return
    setForgetting(true)
    try {
      await withStepup(host.id, () => api(`/api/hosts/${host.id}/forget-credentials`,
        { method: 'POST', body: JSON.stringify({ current_password: pw }) }))
      notify(t('host.forgetCredsDone', { host: host.name }), '', 'info')
    } catch (e) {
      notifyError(t('host.forgetCredsFailed'), errText(e, t) || '')
    } finally {
      setForgetting(false)
    }
  }
  // Pornirea la boot (agent v57+). `supLocal` ţine răspunsul comutării până când poll-ul listei
  // de hosturi aduce o valoare nouă (gateway-ul o stochează imediat, deci vine aceeaşi).
  const [supLocal, setSupLocal] = useState<HostSupervision | null | undefined>(undefined)
  const [autostartBusy, setAutostartBusy] = useState(false)
  const hs = host.supervision
  useEffect(() => { setSupLocal(undefined) }, [host.id, hs?.mode, hs?.boot, hs?.linger])
  const sup = supLocal !== undefined ? supLocal : hs ?? null
  const canAutostart = host.online && (host.agent_version ?? 0) >= 57
  const supLabel = !sup ? t('host.autostartUnknown')
    : sup.boot ? t('host.autostartYes', { mode: sup.mode === 'cron' ? 'cron' : 'systemd' })
    : sup.mode === 'systemd' && !sup.linger ? t('host.autostartNoLinger')
    : t('host.no')
  const toggleAutostart = async (enable: boolean) => {
    if (!enable) {
      const ok = await confirm({
        title: t('host.autostartDisableTitle', { host: host.name }),
        message: t('host.autostartDisableMsg'),
        confirmLabel: t('host.autostartDisable'), danger: true,
      })
      if (!ok) return
    }
    setAutostartBusy(true)
    try {
      const r = await withStepup(host.id, () => api<{ supervision: HostSupervision | null; hint: string }>(
        `/api/hosts/${host.id}/autostart`, { method: 'POST', body: JSON.stringify({ enable }) }))
      setSupLocal(r.supervision)
      const s2 = r.supervision
      if (enable && s2 && !s2.boot && s2.mode === 'systemd' && !s2.linger) {
        notify(t('host.autostartLingerTitle'), t('host.autostartLingerBody', { user: host.agent_user || 'USER' }), 'warn')
      } else {
        notify(enable ? t('host.autostartEnabled', { host: host.name }) : t('host.autostartDisabled', { host: host.name }), '', 'info')
      }
    } catch (e) {
      notifyError(t('host.autostartFailed'), errText(e, t) || '')
    } finally {
      setAutostartBusy(false)
    }
  }
  const [hostApps, setHostApps] = useState<AppLink[]>([])
  useEffect(() => {
    let gone = false
    api<AppLink[]>('/api/apps')
      .then((all) => { if (!gone) setHostApps(all.filter((a) => a.host_id === host.id)) })
      .catch(() => { if (!gone) setHostApps([]) })
    return () => { gone = true }
  }, [host.id])

  return (
    <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
      {/* Connection: doar pe hosturi NON-agent (protocol/auth/via nu-s în bandă). Pe agent,
          protocolul/adresa/backend-ul sunt deja în banda de status → n-are rost un card redundant. */}
      {!isAgent && (
        <InfoCard title={t('host.secConnection')} icon={<ServerIcon />} accent={hostColor(host)}>
          <Row k={t('host.protocol')} v={protoLabel(host)} />
          <Row k={t('host.authentication')} v={host.auth_method === 'key' ? t('host.sshKey') : host.auth_method === 'password' ? t('host.passwordLabel') : '—'} />
        </InfoCard>
      )}

      <InfoCard title={t('host.secSecurity')} icon={<ShieldIcon />} accent="#38bdf8">
        <Row k={t('host.twoFaOnConnect')} help="require2fa" v={host.require_2fa ? t('host.yesPasskey') : t('host.no')} tone={host.require_2fa ? 'good' : undefined} />
        <Row k={t('host.credentials')} help="credentialPolicy" v={credPolicy} action={host.has_credentials && host.credential_policy !== 'ask' ? (
          <button onClick={forgetCreds} disabled={forgetting}
            className="wt-touch rounded-md border border-ink-700 px-2 py-0.5 text-xs text-slate-300 hover:border-danger/60 hover:text-danger disabled:opacity-50">
            {t('host.forgetCreds')}
          </button>
        ) : undefined} />
      </InfoCard>

      {isAgent && (
        <InfoCard title={t('host.agent')} icon={<RefreshIcon />} accent="#a78bfa">
          <Row k={t('host.version')} v={host.agent_version != null ? `v${host.agent_version}` : t('host.notInstalled')}
            badge={host.update_pending ? t('host.updateAvailable') : undefined} />
          {host.last_heartbeat != null && <Row k={t('host.lastActivity')} v={timeAgo(host.last_heartbeat, t)} />}
          <Row k={t('host.autostart')} help="autostart" v={supLabel} tone={sup?.boot ? 'good' : undefined}
            badge={sup && !sup.boot ? t('host.autostartRisk') : undefined}
            action={canAutostart && sup ? (
              <button onClick={() => toggleAutostart(!sup.boot)} disabled={autostartBusy}
                className={`wt-touch rounded-md border border-ink-700 px-2 py-0.5 text-xs text-slate-300 disabled:opacity-50 ${
                  sup.boot ? 'hover:border-danger/60 hover:text-danger' : 'hover:border-ok/60 hover:text-ok'}`}>
                {sup.boot ? t('host.autostartDisable') : t('host.autostartEnable')}
              </button>
            ) : undefined} />
        </InfoCard>
      )}

      {hostApps.length > 0 && (
        <InfoCard title={t('dashboard.apps')} icon={<LinkIcon />} accent="#34d399" className="lg:col-span-2">
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {hostApps.map((a) => {
              const color = HOST_APP_COLOR[a.app_type] || '#34d399'
              return (
                <a key={a.id} href={a.enabled ? a.url : undefined} target="_blank" rel="noopener noreferrer"
                  title={a.enabled ? a.url : t('dashboard.appDisabled')}
                  className={`group flex items-center gap-3 rounded-xl border border-ink-700 bg-ink-900/40 px-3 py-2.5 ${
                    a.enabled ? 'hover:border-ink-500 hover:bg-ink-800' : 'cursor-not-allowed opacity-50'}`}>
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md font-mono text-sm font-bold"
                    style={{ background: `${color}22`, color }}>{a.label.slice(0, 1).toUpperCase()}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-slate-200">{a.label}</span>
                    <span className="block truncate font-mono text-2xs text-slate-500">{a.url.replace(/^https?:\/\//, '')}</span>
                  </span>
                  {a.enabled && <span className="shrink-0 text-slate-600 group-hover:text-slate-400"><ArrowUpRightIcon /></span>}
                </a>
              )
            })}
          </div>
        </InfoCard>
      )}

      {host.note && (
        <InfoCard title={t('host.secNote')} icon={<NoteIcon />} className="lg:col-span-2">
          <p className="text-sm text-slate-400">{host.note}</p>
        </InfoCard>
      )}
    </div>
  )
}

function Row(props: { k: string; v: string; mono?: boolean; tone?: 'good'; badge?: string; action?: React.ReactNode; help?: HelpId }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-ink-800/60 py-2 last:border-0">
      <dt className="flex shrink-0 items-center gap-1.5 text-sm text-slate-500">{props.k}{props.help && <HelpTip id={props.help} />}</dt>
      {/* acţiunea stă ÎN <dd>: un <div> frate cu <dt>/<dd> într-un <dl> e invalid (axe:
          definition-list, serios) — cititoarele de ecran pierd perechea termen/valoare */}
      <dd className={`flex min-w-0 items-center justify-end gap-3 text-right text-sm ${props.tone === 'good' ? 'wt-good' : 'text-slate-200'} ${props.mono ? 'font-mono' : ''}`}>
        <span className="min-w-0 truncate">
          {props.v}
          {props.badge && (
            <Badge tone="warn" className="ml-2 py-0.5 align-middle uppercase tracking-wide">{props.badge}</Badge>
          )}
        </span>
        {props.action && <span className="shrink-0">{props.action}</span>}
      </dd>
    </div>
  )
}
