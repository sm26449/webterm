import { Host, Session, timeAgo } from '../lib/api'
import { hostAt, hostColor, protoLabel, reachState } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { hostHistory } from '../lib/metrics'
import { EyeIcon, PlusIcon, ServerIcon, TerminalPromptIcon } from './Icons'
import Sparkline from './Sparkline'

/** Canvasul „acasă": în loc de vid, arată ce contează pentru un operator de
   flotă — sesiunile active de reluat + starea echipamentelor. */
export default function Dashboard(props: {
  hosts: Host[]
  sessions: Session[]
  onOpenSession: (sid: string) => void
  onSelectHost: (id: number) => void
  onNewSession: (host: Host) => void
  onAddHost: () => void
  onOpenPalette: () => void
  onOpenSidebar: () => void
}) {
  const { t } = useI18n()
  const byId = new Map(props.hosts.map((h) => [h.id, h]))
  const active = props.sessions
    .filter((s) => s.state === 'live' || s.state === 'creating')
    .sort((a, b) => (b.created) - (a.created))
  const recentClosed = props.sessions
    .filter((s) => s.state === 'closed' || s.state === 'lost')
    .sort((a, b) => (b.closed_at || b.created) - (a.closed_at || a.created))
    .slice(0, 4)
  const online = props.hosts.filter((h) => h.online).length
  const folders = [...new Set(props.hosts.map((h) => h.folder || ''))].sort((a, b) =>
    a === '' ? 1 : b === '' ? -1 : a.localeCompare(b))

  if (props.hosts.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-8 text-center">
        <div className="grid h-14 w-14 place-items-center rounded-2xl bg-sky-500/15 text-sky-400"><ServerIcon /></div>
        <div>
          <h1 className="text-lg font-semibold text-slate-100">{t('dashboard.noHostsYet')}</h1>
          <p className="mt-1 max-w-sm text-sm text-slate-500">{t('dashboard.addFirstHost')}</p>
        </div>
        <button onClick={props.onAddHost} className="flex items-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700">
          <PlusIcon /> {t('dashboard.addHost')}
        </button>
      </div>
    )
  }

  return (
    <div data-testid="dashboard" className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-8 sm:py-8">
        <button
          onClick={props.onOpenSidebar}
          className="wt-touch mb-4 rounded-lg border border-ink-600 px-4 py-2 text-sm text-slate-300 hover:bg-ink-800 md:hidden"
        >
          ☰ {t('dashboard.openHostList')}
        </button>
        {/* antet + sumar flotă + comenzi */}
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">{t('dashboard.title')}</h1>
            <p className="mt-1 text-sm text-slate-500">
              {props.hosts.length} {props.hosts.length === 1 ? t('dashboard.host') : t('dashboard.hosts')} · <span className="text-emerald-400">{online} {t('dashboard.online')}</span>
              {' · '}{active.length} {active.length === 1 ? t('dashboard.sessionActiveOne') : t('dashboard.sessionActiveMany')}
            </p>
          </div>
          <button
            onClick={props.onOpenPalette}
            className="wt-touch flex items-center gap-2 rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
          >
            {t('dashboard.jumpTo')} <kbd className="hidden rounded bg-white/10 px-1.5 text-xs text-slate-200 sm:inline">⌘K</kbd>
          </button>
        </div>

        {/* sesiuni active de reluat */}
        <section className="mt-7">
          <h2 className="mb-2.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t('dashboard.resumeSession')}</h2>
          {active.length === 0 ? (
            <p className="rounded-xl border border-dashed border-ink-700 px-4 py-6 text-center text-sm text-slate-500">
              {/* pe touch nu există ⌘K — instrucțiunea ar fi o glumă proastă */}
              {t('dashboard.noActiveSession')}
              <span className="hidden sm:inline"> {t('dashboard.orWith')} <kbd className="rounded bg-white/10 px-1 text-slate-300">⌘K</kbd></span>.
            </p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {active.slice(0, 12).map((s) => {
                const h = byId.get(s.host_id)
                const color = h ? hostColor(h) : '#64748b'
                return (
                  <button
                    key={s.id}
                    onClick={() => props.onOpenSession(s.id)}
                    className="group flex items-center gap-3 overflow-hidden rounded-xl border border-ink-700 bg-ink-900/60 p-3 text-left hover:border-ink-600 hover:bg-ink-800"
                    style={{ borderLeft: `3px solid ${color}` }}
                  >
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg" style={{ background: `${color}22`, color }}>
                      <TerminalPromptIcon />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-slate-100">{s.title || t('dashboard.session')}</span>
                      <span className="block truncate text-xs" style={{ color }}>{h?.name ?? t('dashboard.host')}</span>
                    </span>
                    <span className="shrink-0 text-right text-[11px] text-slate-500">
                      {timeAgo(s.created)}
                      {s.connected_clients > 0 && (
                        <span className="mt-0.5 flex items-center justify-end gap-1" title={t('dashboard.connectedCount', { count: s.connected_clients })}>
                          <EyeIcon /> {s.connected_clients}
                        </span>
                      )}
                    </span>
                  </button>
                )
              })}
            </div>
          )}
          {active.length > 12 && <p className="mt-2 text-xs text-slate-600">{t('dashboard.moreActiveSessions', { count: active.length - 12 })}</p>}
        </section>

        {/* închise recent — istoricul persistent e feature-ul central; fără
           secțiunea asta, reluarea unei sesiuni închise cerea drumul host → listă */}
        {recentClosed.length > 0 && (
          <section className="mt-8">
            <h2 className="mb-2.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t('dashboard.closedRecently')}</h2>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {recentClosed.map((s) => {
                const h = byId.get(s.host_id)
                const color = h ? hostColor(h) : '#64748b'
                return (
                  <button
                    key={s.id}
                    onClick={() => props.onOpenSession(s.id)}
                    className="group flex items-center gap-3 overflow-hidden rounded-xl border border-ink-700/60 bg-ink-900/40 p-3 text-left hover:border-ink-600 hover:bg-ink-800"
                    style={{ borderLeft: `3px solid ${color}66` }}
                  >
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-ink-800 text-slate-500">
                      <TerminalPromptIcon />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm text-slate-300">{s.title || t('dashboard.session')}</span>
                      <span className="block truncate text-xs text-slate-500">{h?.name ?? t('dashboard.host')}</span>
                    </span>
                    <span className="shrink-0 text-right text-[11px] text-slate-500">
                      {s.state === 'lost' ? t('dashboard.lost') : t('dashboard.closed')}
                      <span className="block">{timeAgo(s.closed_at || s.created)}</span>
                    </span>
                  </button>
                )
              })}
            </div>
          </section>
        )}

        {/* flotă */}
        <section className="mt-8">
          <div className="mb-2.5 flex flex-wrap items-center gap-x-4 gap-y-1">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t('dashboard.fleet')}</h2>
            {/* legendă stări — culoarea punctului e dublată de text (WCAG 1.4.1) */}
            <div className="flex items-center gap-3 text-[11px] text-slate-500">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-400" /> {t('dashboard.online')}</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-sky-500" /> {t('dashboard.onDemand')}</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-slate-600" /> {t('dashboard.offline')}</span>
            </div>
          </div>
          <div className="space-y-4">
            {folders.map((folder) => {
              const inF = props.hosts.filter((h) => (h.folder || '') === folder)
              if (inF.length === 0) return null
              return (
                <div key={folder || '__root__'}>
                  {folder && <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-slate-600">{folder}</div>}
                  <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
                    {inF.map((h) => {
                      const color = hostColor(h)
                      const reach = reachState(h)
                      const liveCount = props.sessions.filter((s) => s.host_id === h.id && (s.state === 'live' || s.state === 'creating')).length
                      const m = h.metrics
                      // sănătate la o privire, fără click pe host: CPU/load pentru
                      // online, „văzut acum…" pentru agenți căzuți
                      const health = h.online && m && m.cpu_pct != null
                        ? `CPU ${Math.round(m.cpu_pct)}%${m.load1 != null ? ` · load ${m.load1.toFixed(2)}` : ''}`
                        : !h.online && h.connection_type === 'agent' && h.last_heartbeat != null
                          ? t('dashboard.seen', { time: timeAgo(h.last_heartbeat) })
                          : null
                      const hist = hostHistory(h.id)
                      return (
                        // Cardul era `div onClick`: invizibil pentru Tab şi surd la Enter, deci
                        // pagina hostului — cu istoricul sesiunilor închise şi redarea
                        // transcripturilor — era accesibilă DOAR cu mouse-ul.
                        // `role="button"` pe TOT cardul ar fi părut soluţia, dar cardul conţine
                        // deja un buton („sesiune nouă"), iar controale interactive imbricate
                        // sunt ele însele o violare WCAG — poarta de accesibilitate a prins-o.
                        // Deci acţiunea principală stă pe NUMELE hostului, un buton adevărat;
                        // click-ul pe card rămâne, ca scurtătură de mouse.
                        <div
                          key={h.id}
                          onClick={() => props.onSelectHost(h.id)}
                          className="group flex cursor-pointer items-center gap-2.5 overflow-hidden rounded-lg px-2.5 py-2 ring-1 ring-ink-700 hover:bg-ink-800"
                          style={{ borderLeft: `3px solid ${color}` }}
                        >
                          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md" style={{ background: `${color}22`, color }}>
                            <ServerIcon />
                          </span>
                          <span className="min-w-0 flex-1">
                            <button
                              type="button"
                              onClick={(e) => { e.stopPropagation(); props.onSelectHost(h.id) }}
                              aria-label={t('dashboard.openHost', { name: h.name })}
                              className="block w-full truncate text-left text-sm text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded-sm"
                            >
                              {h.name}
                            </button>
                            <span className="block truncate font-mono text-[11px] text-slate-500">{protoLabel(h)} · {hostAt(h)}</span>
                            {health && (
                              <span className="flex items-center gap-1.5">
                                <span className="min-w-0 flex-1 truncate font-mono text-[11px] tabular-nums text-slate-500">{health}</span>
                                {/* tendința, nu doar cifra: „CPU 43%" nu-ți spune
                                    dacă urcă spre 100 sau tocmai a coborât de acolo */}
                                {hist && hist.cpu.length > 1 && (
                                  <Sparkline values={hist.cpu} label={t('dashboard.cpuOn', { name: h.name })} />
                                )}
                              </span>
                            )}
                          </span>
                          {liveCount > 0 && <span className="shrink-0 rounded-full bg-emerald-500/15 px-1.5 text-[11px] font-semibold text-emerald-400">{liveCount}</span>}
                          <span className={`h-2 w-2 shrink-0 rounded-full ${reach === 'online' ? 'bg-emerald-400 dot-live' : reach === 'ondemand' ? 'bg-sky-500' : 'bg-slate-600'}`}
                            title={reach === 'online' ? t('dashboard.online') : reach === 'ondemand' ? t('dashboard.onDemandConnect') : t('dashboard.offline')} />
                          {/* pe touch NU există hover: butonul „+" era invizibil,
                              deci nu puteai porni o sesiune de pe card */}
                          <button
                            onClick={(e) => { e.stopPropagation(); props.onNewSession(h) }}
                            disabled={reach === 'offline'}
                            title={t('dashboard.newSession')}
                            aria-label={t('dashboard.newSessionOn', { name: h.name })}
                            className="wt-touch shrink-0 rounded-md p-1 text-slate-400 opacity-0 hover:bg-ink-700 hover:text-slate-100 focus-visible:opacity-100 group-hover:opacity-100 disabled:opacity-0 [@media(hover:none)]:opacity-100"
                          >
                            <PlusIcon />
                          </button>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        </section>
      </div>
    </div>
  )
}
