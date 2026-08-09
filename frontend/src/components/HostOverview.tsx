import { useEffect, useMemo, useState } from 'react'
import { isSessionLive, api, Host, Session, timeAgo } from '../lib/api'
import { hostAt, protoLabel } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { hostHistory } from '../lib/metrics'
import { DownloadIcon, FilesIcon, PlusIcon, PopoutIcon, ServerIcon, SplitIcon, TrashIcon } from './Icons'
import SessionPreview from './SessionPreview'
import Sparkline from './Sparkline'
import TranscriptPlayer from './TranscriptPlayer'

/** Pagina unui host: navigare de sesiuni (stânga) + previzualizare (dreapta).
   Click pe o sesiune = preview; „Deschide" (sau dublu-click) = terminal. */
export default function HostOverview(props: {
  host: Host
  sessions: Session[]
  onOpenSession: (sid: string) => void
  onNewSession: (host: Host) => void
  onFiles: (host: Host) => void
  onSplit: (sid: string) => void
  onPopout: (sid: string) => void
  onDeleteSession: (sid: string) => void
  onMenu: () => void
  sidebarCollapsed?: boolean
}) {
  const { t } = useI18n()
  const { host } = props
  const canConnect = host.connection_type !== 'agent' || host.online
  const m = host.metrics

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
  // panoul din dreapta arată fie preview-ul sesiunii selectate, fie detaliile
  // hostului (implicit când nu există nicio sesiune → nu mai e un ecran gol)
  const [viewDetail, setViewDetail] = useState(false)
  useEffect(() => { setViewDetail(false) }, [host.id])
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
        onClick={() => { setSelected(s.id); setViewDetail(false) }}
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

  return (
    <div className="flex h-full min-w-0 flex-1 flex-col">
      {/* ── header ── */}
      {/* flex-wrap + min-w pe blocul de titlu: pe mobil acțiunile coboară pe
         rândul doi în loc să strivească numele hostului la o literă */}
      <div className="flex flex-wrap items-start gap-x-4 gap-y-3 border-b border-ink-800 px-4 py-4 sm:px-6">
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
              /* metricele ies din ecran pe telefon (rândul e deja lung cu
                 user@host + starea) — le arătăm de la sm în sus */
              <span className="ml-2 hidden font-mono text-slate-600 tabular-nums sm:inline">
                {m.cpu_pct != null && `CPU ${Math.round(m.cpu_pct)}%`}
                {m.mem_total ? ` · MEM ${Math.round(((m.mem_used ?? 0) / m.mem_total) * 100)}%` : ''}
                {m.load1 != null ? ` · load ${m.load1.toFixed(2)}` : ''}
              </span>
            )}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {host.online && host.connection_type === 'agent' && (
            <button onClick={() => props.onFiles(host)}
              className="wt-touch flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
              <FilesIcon /> {t('host.files')}
            </button>
          )}
          <button disabled={!canConnect} onClick={() => props.onNewSession(host)}
            className="wt-touch flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-40">
            <PlusIcon /> {t('host.newSession')}
          </button>
        </div>
      </div>

      {/* ── master (listă) + detail (preview) ──
         pe mobil: stivuit pe o coloană (lista sus, mărginită, preview dedesubt) —
         două coloane pe 390px striveau preview-ul la ~90px */}
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <div className="max-h-[38%] w-full shrink-0 overflow-y-auto border-b border-ink-800 md:max-h-none md:w-[320px] md:border-b-0 md:border-r">
          <button
            onClick={() => { setViewDetail(true); setSelected(null) }}
            className={`flex w-full items-center gap-2.5 px-3 py-2 text-left ${
              viewDetail || !sel ? 'bg-ink-800' : 'hover:bg-ink-800/50'}`}
          >
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-ink-700 text-slate-400"><ServerIcon /></span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-slate-200">{t('host.details')}</span>
              <span className="block truncate text-[11px] text-slate-600">{t('host.detailsSub')}</span>
            </span>
          </button>
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

        {/* preview sesiune SAU detalii host */}
        <div className="flex min-w-0 flex-1 flex-col">
          {sel && !viewDetail ? (
            <>
              {/* flex-wrap: pe iPad Mini, butoanele cu ținte tactile de 44px +
                  „Deschide" depășeau lățimea → coboară pe rândul doi, nu ies din ecran */}
              <div className="flex flex-wrap items-center gap-2 border-b border-ink-800 px-4 py-2.5">
                <span className={`h-2 w-2 shrink-0 rounded-full ${
                  selLive ? 'bg-emerald-400 dot-live' : sel.state === 'lost' ? 'bg-rose-500' : 'bg-slate-600'}`} />
                <div className="min-w-[8rem] flex-1">
                  <div className="truncate text-sm font-medium text-slate-200">{sel.title || t('host.sessionFallback')}</div>
                  <div className="truncate text-[11px] text-slate-600">
                    {selLive ? t('host.previewLive') : t('host.previewHistory')} · {timeAgo(sel.closed_at || sel.created, t)}
                  </div>
                </div>
                {/* split/popout: doar pe ecrane mari (pe tablete nu încap) */}
                <button onClick={() => props.onSplit(sel.id)} title={t('host.splitTitle')}
                  className="hidden shrink-0 rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200 lg:block"><SplitIcon /></button>
                <button onClick={() => props.onPopout(sel.id)} title={t('host.popoutTitle')}
                  className="hidden shrink-0 rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200 lg:block"><PopoutIcon /></button>
                {/* redare: sesiunea închisă se poate REVEDEA, nu doar descărca */}
                {!selLive && (
                  <button onClick={() => setPlaying(sel)} title={t('host.playTitle')}
                    aria-label={t('host.playTitle')}
                    className="wt-touch grid place-items-center rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200">▶</button>
                )}
                <a href={`/api/sessions/${sel.id}/transcript?format=cast`} download title={t('host.downloadTitle')}
                  className="wt-touch grid place-items-center rounded p-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-200"><DownloadIcon /></a>
                {!selLive && (
                  <button onClick={() => {
                      // Ştergerea e IREVERSIBILĂ (sesiune + transcript). Aceeaşi acţiune din
                      // interiorul sesiunii cerea confirmare; aici, un click greşit între ▶ şi ⬇
                      // ştergea istoricul fără să întrebe. Prins de auditul intern.
                      if (!confirm(t('session.confirmDelete'))) return
                      setDeletedIds((prev) => new Set(prev).add(sel.id))   // remove immediately (și față de poll-ul global)
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
            <HostDetail host={host} />
          )}
        </div>
      </div>
      {playing && (
        <TranscriptPlayer
          sid={playing.id}
          title={playing.title}
          onClose={() => setPlaying(null)}
        />
      )}
    </div>
  )
}

/** Panoul de detalii host: transformă ecranul gol într-unul util —
   conexiune, securitate, agent și resurse, la o privire. */
function HostDetail({ host }: { host: Host }) {
  const { t } = useI18n()
  const m = host.metrics
  const hist = hostHistory(host.id)
  const isAgent = (host.connection_type ?? 'agent') === 'agent'
  const pct = (used?: number, total?: number) =>
    total && used != null ? `${Math.round((used / total) * 100)}%` : null
  const gib = (n?: number) => (n != null ? `${(n / 1024 ** 3).toFixed(1)} GiB` : null)
  const credPolicy = host.credential_policy === 'ask' ? t('host.credAsk')
    : host.credential_policy === 'ephemeral' ? t('host.credEphemeral')
    : host.has_credentials ? t('host.credStored') : t('host.credNone')

  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-6">
      <div className="max-w-2xl space-y-5">
        {/* Fără tmux pe host, agentul cade pe un PTY simplu — sesiunile mor odată cu el.
            Adică exact promisiunea produsului, întoarsă pe dos, fără ca omul să afle.
            Scriptul de instalare avertizează, dar o singură dată, într-un log care se
            derulează; aici scria doar `Backend: pty`, un cuvânt care nu spune nimic cuiva
            care nu ştie ce e tmux. Nu refuzăm instalarea — pe o cutie minimală un terminal
            efemer e tot util —, dar refuzăm s-o ascundem. */}
        {host.backend === 'pty' && (
          <p className="wt-warn rounded-lg bg-amber-500/10 p-3 text-sm ring-1 ring-amber-500/30">
            {t('host.noTmuxWarning')}
          </p>
        )}
        <Section title={t('host.secConnection')}>
          <Row k={t('host.protocol')} v={protoLabel(host)} />
          <Row k={t('host.address')} v={host.hostname ? hostAt(host) : '—'} mono />
          {!isAgent && <Row k={t('host.authentication')} v={host.auth_method === 'key' ? t('host.sshKey') : host.auth_method === 'password' ? t('host.passwordLabel') : '—'} />}
          {host.backend && <Row k="Backend" v={host.backend} mono />}
          <Row k={t('host.status')} v={host.online ? 'online' : isAgent ? 'offline' : t('host.connectOnDemand')}
            tone={host.online ? 'good' : undefined} />
        </Section>

        <Section title={t('host.secSecurity')}>
          <Row k={t('host.twoFaOnConnect')} v={host.require_2fa ? t('host.yesPasskey') : t('host.no')} tone={host.require_2fa ? 'good' : undefined} />
          <Row k={t('host.credentials')} v={credPolicy} />
        </Section>

        {isAgent && (
          <Section title="Agent">
            <Row k={t('host.version')} v={host.agent_version != null ? `v${host.agent_version}` : t('host.notInstalled')}
              badge={host.update_pending ? t('host.updateAvailable') : undefined} />
            {host.last_heartbeat != null && <Row k={t('host.lastActivity')} v={timeAgo(host.last_heartbeat, t)} />}
          </Section>
        )}

        {host.online && m && (
          <Section title={t('host.secResources')}>
            {/* graficele arată ultimele ~5 minute (poll-ul de 5s); se golesc la
                reload — sunt context la incident, nu monitorizare persistentă */}
            {m.cpu_pct != null && (
              <RowChart k="CPU" v={`${Math.round(m.cpu_pct)}%`} values={hist?.cpu} label={t('host.cpuChartLabel', { name: host.name })} />
            )}
            {pct(m.mem_used, m.mem_total) && (
              <RowChart k={t('host.memory')} v={t('host.ofTotal', { pct: pct(m.mem_used, m.mem_total)!, total: gib(m.mem_total)! })}
                values={hist?.mem} label={t('host.memChartLabel', { name: host.name })} />
            )}
            {pct(m.disk_used, m.disk_total) && <Row k={t('host.disk')} v={t('host.ofTotal', { pct: pct(m.disk_used, m.disk_total)!, total: gib(m.disk_total)! })} mono />}
            {m.load1 != null && <Row k="Load (1·5·15)" v={`${m.load1.toFixed(2)} · ${(m.load5 ?? 0).toFixed(2)} · ${(m.load15 ?? 0).toFixed(2)}`} mono />}
          </Section>
        )}

        {host.note && (
          <Section title={t('host.secNote')}>
            <p className="px-3 py-2 text-sm text-slate-400">{host.note}</p>
          </Section>
        )}
      </div>
    </div>
  )
}

function Section(props: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{props.title}</h3>
      <dl className="divide-y divide-ink-800 rounded-xl ring-1 ring-ink-800">{props.children}</dl>
    </div>
  )
}

/** Rând de metrică cu tendință: cifra curentă + sparkline pe ultimele 5 minute. */
function RowChart(props: { k: string; v: string; values?: number[]; label: string }) {
  return (
    <div className="flex items-center justify-between gap-3 px-3 py-2">
      <dt className="shrink-0 text-sm text-slate-500">{props.k}</dt>
      <dd className="flex min-w-0 items-center gap-2.5">
        {props.values && props.values.length > 1 && (
          <Sparkline values={props.values} width={72} height={18} label={props.label} />
        )}
        <span className="truncate text-right font-mono text-sm text-slate-200">{props.v}</span>
      </dd>
    </div>
  )
}

function Row(props: { k: string; v: string; mono?: boolean; tone?: 'good'; badge?: string }) {
  return (
    <div className="flex items-center justify-between gap-3 px-3 py-2">
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
