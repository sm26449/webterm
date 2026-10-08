import { useEffect, useState } from 'react'
import { isEphemeralHost, isSessionLive, api, AppLink, Host, Session, timeAgo } from '../lib/api'
import { hostAt, hostColor, protoLabel, reachState } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { hostHistory } from '../lib/metrics'
import { ArrowUpRightIcon, DiamondIcon, EyeIcon, MenuIcon, PlusIcon, ServerIcon, TerminalPromptIcon } from './Icons'
import Sparkline from './Sparkline'
import SecurityCard, { SecurityTarget } from './SecurityCard'
import type { SettingsTarget } from '../lib/settingsIndex'
import SharesModal from './SharesModal'
import { fmt } from '../lib/shortcuts'
import { Badge, Button, EmptyState, eyebrow } from './ui'
import { MenuUnreadBadge, useUnreadAlerts } from './AlertsPanel'
import { menuLabel } from '../lib/alerts'

// culoare + glif per tip de app (dalele din strip + butoanele de pe host)
const APP_COLOR: Record<string, string> = {
  proxmox: '#ec8b3c', portainer: '#57a8e6', grafana: '#f59e0b', custom: '#34d399',
  adminer: '#7dd3fc', pgadmin: '#4f83cc', phpmyadmin: '#e0a83c',
  'mongo-express': '#4bd494', kibana: '#f04e98', clickhouse: '#f0cf5a',
}
const APP_GLYPH: Record<string, string> = {
  proxmox: 'PVE', portainer: 'PTN', grafana: 'GRA',   // custom: fără monogramă → DiamondIcon
  adminer: 'ADM', pgadmin: 'PGA', phpmyadmin: 'PMA',
  'mongo-express': 'MEX', kibana: 'KIB', clickhouse: 'CH',
}

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
  /** cardul Securitate duce la locul unde se repară: Setări pe tab-ul potrivit / Status */
  onOpenSettings: (target: SettingsTarget) => void
  onOpenStatus: () => void
}) {
  const { t } = useI18n()
  const unreadAlerts = useUnreadAlerts()
  const [sharesOpen, setSharesOpen] = useState(false)
  // „Revocă tot"/„Revocă" din inventar schimbă rândul „Link-uri de share" → cardul se reîncarcă
  const [secRefresh, setSecRefresh] = useState(0)
  const navigateSecurity = (target: SecurityTarget) => {
    if (target.kind === 'shares') setSharesOpen(true)
    else if (target.kind === 'status') props.onOpenStatus()
    else props.onOpenSettings(target.target)
  }
  const byId = new Map(props.hosts.map((h) => [h.id, h]))
  // apps (forward-uri promovate) agregate din toată flota — strip-ul „one pane of glass"
  const [apps, setApps] = useState<AppLink[]>([])
  useEffect(() => { api<AppLink[]>('/api/apps').then(setApps).catch(() => {}) }, [])
  const active = props.sessions
    .filter((s) => isSessionLive(s, props.hosts))
    .sort((a, b) => (b.created) - (a.created))
  const recentClosed = props.sessions
    .filter((s) => s.state === 'closed' || s.state === 'lost')
    .sort((a, b) => (b.closed_at || b.created) - (a.closed_at || a.created))
    .slice(0, 4)
  // contoarele şi grila de echipamente: FĂRĂ ţintele efemere („conectează o dată") —
  // `byId`/sesiunile rămân pe lista completă, ca tab-ul lor live să-şi păstreze hostul
  const hosts = props.hosts.filter((h) => !isEphemeralHost(h))
  const online = hosts.filter((h) => h.online).length
  const folders = [...new Set(hosts.map((h) => h.folder || ''))].sort((a, b) =>
    a === '' ? 1 : b === '' ? -1 : a.localeCompare(b))

  if (hosts.length === 0) {
    return (
      <EmptyState size="page" titleAs="h1" className="wt-canvas h-full"
        icon={<ServerIcon />}
        title={t('dashboard.noHostsYet')}
        body={t('dashboard.addFirstHost')}
        action={(
          <Button variant="primary" size="lg" onClick={props.onAddHost} className="gap-2">
            <PlusIcon /> {t('dashboard.addHost')}
          </Button>
        )}
      />
    )
  }

  return (
    // `wt-canvas`: dashboard-ul urmează tema aleasă (index.css) — e „acasă", nu terminal
    <div data-testid="dashboard" className="wt-canvas h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-8 sm:py-8">
        <Button variant="secondary" size="lg" onClick={props.onOpenSidebar} className="wt-touch mb-4 md:hidden"
          aria-label={menuLabel(t('dashboard.openHostList'), unreadAlerts, t)}>
          <MenuIcon /> {t('dashboard.openHostList')}
          <MenuUnreadBadge n={unreadAlerts} inline />
        </Button>
        {/* antet + sumar flotă + comenzi */}
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">{t('dashboard.title')}</h1>
            <p className="mt-1 text-sm text-slate-500">
              {t('dashboard.hostCount', { count: hosts.length })} · <span className="wt-good">{online} {t('dashboard.online')}</span>
              {' · '}{t('dashboard.activeSessionCount', { count: active.length })}
            </p>
          </div>
          <Button variant="secondary" size="lg" onClick={props.onOpenPalette} className="wt-touch gap-2">
            {t('dashboard.jumpTo')} <kbd className="hidden rounded-md bg-ink-700 px-1.5 text-xs text-slate-200 sm:inline">{fmt('Mod+K')}</kbd>
          </Button>
        </div>

        {/* Securitate: „e totul în regulă acum?" la o privire (3.5.4) */}
        <SecurityCard onNavigate={navigateSecurity} refreshSignal={secRefresh} />
        {sharesOpen && (
          <SharesModal onClose={() => setSharesOpen(false)} onChanged={() => setSecRefresh((n) => n + 1)} />
        )}

        {/* Apps: forward-urile promovate, un click din „acasă" — nu mai ieşi din WebTerm */}
        {apps.length > 0 && (
          <section className="mt-7">
            <h2 className={`mb-2.5 ${eyebrow}`}>{t('dashboard.apps')}</h2>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {apps.map((a) => {
                const color = APP_COLOR[a.app_type] || '#34d399'
                const glyph = APP_GLYPH[a.app_type] || <DiamondIcon />
                return (
                  <a key={a.id} href={a.enabled ? a.url : undefined} target="_blank" rel="noopener noreferrer"
                    title={a.enabled ? a.url : t('dashboard.appDisabled')}
                    className={`group flex items-center gap-3 rounded-xl border border-ink-700 bg-ink-800/50 px-3 py-2.5 ${
                      a.enabled ? 'hover:border-ink-500 hover:bg-ink-800' : 'cursor-not-allowed opacity-50'}`}>
                    <span className="wt-hostlabel grid h-9 w-9 shrink-0 place-items-center rounded-md font-mono text-sm font-bold"
                      style={{ background: `${color}22`, color }}>{glyph}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-slate-200">{a.label}</span>
                      <span className="block truncate text-2xs text-slate-500">{a.host_name}{a.enabled ? '' : ` · ${t('dashboard.appOff')}`}</span>
                    </span>
                    <span className="shrink-0 text-slate-600 group-hover:text-slate-400"><ArrowUpRightIcon /></span>
                  </a>
                )
              })}
            </div>
          </section>
        )}

        {/* sesiuni active de reluat */}
        <section className="mt-7">
          <h2 className={`mb-2.5 ${eyebrow}`}>{t('dashboard.resumeSession')}</h2>
          {active.length === 0 ? (
            <p className="rounded-xl border border-dashed border-ink-700 px-4 py-6 text-center text-sm text-slate-500">
              {/* pe touch nu există ⌘K — instrucțiunea ar fi o glumă proastă */}
              {t('dashboard.noActiveSession')}
              <span className="hidden sm:inline"> {t('dashboard.orWith')} <kbd className="rounded-md bg-ink-700 px-1 text-slate-300">{fmt('Mod+K')}</kbd></span>.
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
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md" style={{ background: `${color}22`, color }}>
                      <TerminalPromptIcon />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-slate-100">{s.title || t('dashboard.session')}</span>
                      <span className="wt-hostlabel block truncate text-xs" style={{ color }}>{h?.name ?? t('dashboard.host')}</span>
                    </span>
                    <span className="shrink-0 text-right text-2xs text-slate-500">
                      {timeAgo(s.created, t)}
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
          {active.length > 12 && <p className="wt-muted mt-2 text-xs">{t('dashboard.moreActiveSessions', { key: fmt('Mod+K'), count: active.length - 12 })}</p>}
        </section>

        {/* închise recent — istoricul persistent e feature-ul central; fără
           secțiunea asta, reluarea unei sesiuni închise cerea drumul host → listă */}
        {recentClosed.length > 0 && (
          <section className="mt-8">
            <h2 className={`mb-2.5 ${eyebrow}`}>{t('dashboard.closedRecently')}</h2>
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
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-ink-800 text-slate-500">
                      <TerminalPromptIcon />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm text-slate-300">{s.title || t('dashboard.session')}</span>
                      <span className="block truncate text-xs text-slate-500">{h?.name ?? t('dashboard.host')}</span>
                    </span>
                    <span className="shrink-0 text-right text-2xs text-slate-500">
                      {s.state === 'lost' ? t('dashboard.lost') : t('dashboard.closed')}
                      <span className="block">{timeAgo(s.closed_at || s.created, t)}</span>
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
            <h2 className={eyebrow}>{t('dashboard.fleet')}</h2>
            {/* legendă stări — culoarea punctului e dublată de text (WCAG 1.4.1) */}
            <div className="flex items-center gap-3 text-2xs text-slate-500">
              <span className="flex items-center gap-1"><span aria-hidden="true" className="h-2 w-2 rounded-full bg-emerald-400 ring-1 ring-emerald-700/50" /> {t('dashboard.online')}</span>
              <span className="flex items-center gap-1"><span aria-hidden="true" className="h-2 w-2 rounded-full bg-sky-500" /> {t('dashboard.onDemand')}</span>
              <span className="flex items-center gap-1"><span aria-hidden="true" className="h-2 w-2 rounded-full bg-slate-600" /> {t('dashboard.offline')}</span>
            </div>
          </div>
          <div className="space-y-4">
            {folders.map((folder) => {
              const inF = hosts.filter((h) => (h.folder || '') === folder)
              if (inF.length === 0) return null
              return (
                <div key={folder || '__root__'}>
                  {folder && <div className="wt-muted mb-1.5 text-2xs font-medium uppercase tracking-wide">{folder}</div>}
                  <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
                    {inF.map((h) => {
                      const color = hostColor(h)
                      const reach = reachState(h)
                      const liveCount = props.sessions.filter((s) => s.host_id === h.id && isSessionLive(s, [h])).length
                      const m = h.metrics
                      // sănătate la o privire, fără click pe host: CPU/load pentru
                      // online, „văzut acum…" pentru agenți căzuți
                      const health = h.online && m && m.cpu_pct != null
                        ? `CPU ${Math.round(m.cpu_pct)}%${m.load1 != null ? ` · load ${m.load1.toFixed(2)}` : ''}`
                        : !h.online && h.connection_type === 'agent' && h.last_heartbeat != null
                          ? t('dashboard.seen', { time: timeAgo(h.last_heartbeat, t) })
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
                          className="group flex cursor-pointer items-center gap-2.5 overflow-hidden rounded-md px-2.5 py-2 ring-1 ring-ink-700 hover:bg-ink-800"
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
                              className="block min-h-6 w-full truncate text-left text-sm text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded-md"
                            >
                              {h.name}
                            </button>
                            <span className="block truncate font-mono text-2xs text-slate-500">{protoLabel(h)} · {hostAt(h)}</span>
                            {health && (
                              <span className="flex items-center gap-1.5">
                                <span className="min-w-0 flex-1 truncate font-mono text-2xs tabular-nums text-slate-500">
                                  {health}
                                  {/* nota apare şi aici, nu doar în sidebar: „de ce e jos" trebuie
                                      să te găsească pe orice ecran te uiţi după host */}
                                  {!h.online && h.connection_type === 'agent' && h.note
                                    ? <span className="italic" title={h.note}> · {h.note}</span> : null}
                                </span>
                                {/* tendința, nu doar cifra: „CPU 43%" nu-ți spune
                                    dacă urcă spre 100 sau tocmai a coborât de acolo */}
                                {hist && hist.cpu.length > 1 && (
                                  <Sparkline values={hist.cpu} label={t('dashboard.cpuOn', { name: h.name })} />
                                )}
                              </span>
                            )}
                          </span>
                          {liveCount > 0 && (
                            <Badge tone="ok" aria-label={t('dashboard.connectedCount', { count: liveCount })}>{liveCount}</Badge>
                          )}
                          {/* starea NU doar prin culoare (WCAG 1.4.1): `title` pe un span nu ajunge la cititorul de
                              ecran, deci textul stării e dublat `sr-only` lângă punct */}
                          <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${reach === 'online' ? 'bg-emerald-400 ring-1 ring-emerald-700/50 dot-live' : reach === 'ondemand' ? 'bg-sky-500' : 'bg-slate-600'}`}
                            title={reach === 'online' ? t('dashboard.online') : reach === 'ondemand' ? t('dashboard.onDemandConnect') : t('dashboard.offline')} />
                          <span className="sr-only">{reach === 'online' ? t('dashboard.online') : reach === 'ondemand' ? t('dashboard.onDemand') : t('dashboard.offline')}</span>
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
