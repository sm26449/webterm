import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { api, errText, type Host } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { fmtTs } from '../../lib/tz'
import {
  filterFleet, fleetDuration, fleetMtls, fleetVersions, routeKey, type FleetPayload, type RouteFilter,
} from '../../lib/agentFleet'
import { mtlsDaysLeft, mtlsExpiringSoon, mtlsState } from '../../lib/mtls'
import { Badge, Button } from '../ui'
import { ChevronIcon, RefreshIcon } from '../Icons'
import { PHONE_QUERY, useMediaQuery } from '../../lib/sheet'
import { field, fieldBase } from './ui'
import DiagnosticModal from '../DiagnosticModal'

const ROUTES: RouteFilter[] = ['all', 'mtls', 'token', 'offline']

// 3.7.0: flota de agenţi dintr-o privire — pe ce rută a venit fiecare (mTLS / token), versiune, IP,
// reconectări. Click pe un host → jurnalul lui de conexiune (DiagnosticModal; ruta /events îşi
// aplică singură host.diagnostics + step-up, iar api() deschide step-up-ul pe /api/hosts/{id}/…).
export default function ConnectedAgents() {
  const { t } = useI18n()
  const [data, setData] = useState<FleetPayload | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [q, setQ] = useState('')
  const [route, setRoute] = useState<RouteFilter>('all')
  const [version, setVersion] = useState('')
  const [hosts, setHosts] = useState<Host[] | null>(null)
  const [diag, setDiag] = useState<Host | null>(null)
  // 3.7.1 (auditul UX Setări C3/#8): pe telefon tabelul de 8 coloane derula orizontal într-un panou
  // deja derulabil (502px în 326px). Acolo randăm carduri: ce citeşti întâi (host, stare, rută,
  // versiune) e sus, restul la atingere. JS, nu CSS: un singur set de butoane în DOM (selectorii
  // e2e şi cititoarele de ecran nu găsesc dubluri ascunse).
  const phone = useMediaQuery(PHONE_QUERY)
  const [open, setOpen] = useState<Set<number>>(() => new Set())
  const toggle = (id: number) => setOpen((s) => { const n = new Set(s); if (!n.delete(id)) n.add(id); return n })

  const load = () => {
    setBusy(true); setErr('')
    api<FleetPayload>('/api/health/agents')
      .then(setData)
      .catch((e) => setErr(errText(e, t) || t('health.agents.loadFailed')))
      .finally(() => setBusy(false))
  }
  useEffect(load, [])   // eslint-disable-line react-hooks/exhaustive-deps

  // Host-ul complet (tipul Host real, nu unul parţial) vine din /api/hosts, o dată, la primul click
  const openHost = async (id: number) => {
    setErr('')
    try {
      const list = hosts ?? await api<Host[]>('/api/hosts')
      if (!hosts) setHosts(list)
      const h = list.find((x) => x.id === id)
      if (h) setDiag(h)
      else setErr(t('health.agents.hostGone'))
    } catch (e) {
      setErr(errText(e, t) || t('health.agents.loadFailed'))
    }
  }

  const rows = useMemo(() => data ? filterFleet(data.agents, { q, route, version }) : [], [data, q, route, version])
  const versions = data ? fleetVersions(data.summary) : []
  const now = data?.now ?? Date.now() / 1000
  const sm = data?.summary

  return (
    <div className="mt-4" data-testid="connected-agents">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold">{t('health.agents.title')}</h4>
        <Button variant="ghost" size="sm" type="button" loading={busy} onClick={load}>
          <RefreshIcon size={14} /> {t('health.agents.refresh')}
        </Button>
      </div>
      <p className="mt-1 text-xs text-slate-500">{t('health.agents.hint')}</p>
      <span role="alert" className={err ? 'mt-1 block text-xs wt-danger' : 'sr-only'}>{err}</span>
      {sm && (
        <div className="mt-2 flex flex-wrap gap-1.5" role="status">
          <Badge tone="ok">{t('health.agents.sum.online', { count: sm.online })}</Badge>
          <Badge tone="info">{t('health.agents.sum.mtls', { count: sm.mtls })}</Badge>
          <Badge tone={sm.token ? 'warn' : 'neutral'}>{t('health.agents.sum.token', { count: sm.token })}</Badge>
          <Badge tone={sm.offline ? 'danger' : 'neutral'}>{t('health.agents.sum.offline', { count: sm.offline })}</Badge>
          {versions.map(([v, n]) => (
            <Badge key={v} tone={data?.expected_version != null && Number(v) < data.expected_version ? 'warn' : 'neutral'}>
              {t('health.agents.sum.version', { version: v, count: n })}
            </Badge>
          ))}
        </div>
      )}
      {data && data.agents.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2">
          <input type="search" className={field + ' sm:max-w-xs'} value={q} onChange={(e) => setQ(e.target.value)}
            placeholder={t('health.agents.search')} aria-label={t('health.agents.search')} />
          <select className={fieldBase + ' w-auto'} value={route} onChange={(e) => setRoute(e.target.value as RouteFilter)}
            aria-label={t('health.agents.filterRoute')}>
            {ROUTES.map((r) => <option key={r} value={r}>{t('health.agents.filter.' + r)}</option>)}
          </select>
          <select className={fieldBase + ' w-auto'} value={version} onChange={(e) => setVersion(e.target.value)}
            aria-label={t('health.agents.filterVersion')}>
            <option value="">{t('health.agents.allVersions')}</option>
            {versions.map(([v]) => <option key={v} value={v}>{t('health.agents.versionN', { version: v })}</option>)}
          </select>
        </div>
      )}
      {data && (data.agents.length === 0 ? (
        <p className="mt-2 text-xs text-slate-500">{t('health.agents.none')}</p>
      ) : rows.length === 0 ? (
        <p className="mt-2 text-xs text-slate-500">{t('health.agents.noMatch')}</p>
      ) : phone ? (
        <ul className="mt-2 flex flex-col gap-2" data-agent-cards aria-label={t('health.agents.title')}>
          {rows.map((a) => {
            const m = fleetMtls(a)
            const days = mtlsState(m) === 'none' ? null : mtlsDaysLeft(m, now)
            const old = a.agent_version != null && data.expected_version != null && a.agent_version < data.expected_version
            const isOpen = open.has(a.id)
            const detailsId = `agent-card-${a.id}`
            return (
              <li key={a.id} data-agent-card={a.name} className="rounded-md ring-1 ring-ink-800">
                <button type="button" aria-expanded={isOpen} aria-controls={detailsId} onClick={() => toggle(a.id)}
                  className="wt-touch flex min-h-[44px] w-full items-start gap-2 rounded-md px-3 py-2 text-left hover:bg-ink-800">
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-slate-200">{a.name}</span>
                    {a.folder && <span className="block truncate text-xs text-slate-500">{a.folder}</span>}
                    <span className="mt-1 flex flex-wrap gap-1.5">
                      <Badge tone={a.online ? 'ok' : 'danger'}>{t(a.online ? 'health.agents.online' : 'health.agents.offline')}</Badge>
                      <Badge tone={a.online && a.route ? (a.route === 'mtls' ? 'info' : 'warn') : 'neutral'}>{t(routeKey(a))}</Badge>
                      {a.agent_version != null && (
                        <Badge tone={old ? 'warn' : 'neutral'}>{t('health.agents.versionN', { version: a.agent_version })}</Badge>
                      )}
                    </span>
                  </span>
                  <span aria-hidden="true" className="mt-0.5 shrink-0 text-slate-500"><ChevronIcon open={isOpen} /></span>
                </button>
                {isOpen && (
                  <div id={detailsId} className="border-t border-ink-800 px-3 py-2 text-xs">
                    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                      {!a.online && a.last_heartbeat && (<>
                        <dt className="text-slate-500">{t('health.agents.col.status')}</dt>
                        <dd>{t('health.agents.lastSeen', { when: fmtTs(a.last_heartbeat) })}</dd>
                      </>)}
                      <dt className="text-slate-500">{t('health.agents.col.ip')}</dt>
                      <dd className="break-all font-mono">{a.agent_ip || '—'}</dd>
                      <dt className="text-slate-500">{t('health.agents.col.connectedFor')}</dt>
                      <dd>{a.online && a.connected_since ? fleetDuration(now - a.connected_since, t) : '—'}</dd>
                      <dt className="text-slate-500">{t('health.agents.col.reconnects')}</dt>
                      <dd className={'tabular-nums' + (a.reconnects_24h > 5 ? ' wt-warn' : '')}>{a.reconnects_24h}</dd>
                      <dt className="text-slate-500">{t('health.agents.col.cert')}</dt>
                      <dd className={days !== null && mtlsExpiringSoon(m, now) ? 'wt-warn' : ''}>
                        {days === null ? '—' : days < 0 ? t('health.agents.certExpired') : t('host.mtls.expires', { days })}
                      </dd>
                    </dl>
                    <Button variant="secondary" size="sm" type="button" className="mt-2" onClick={() => { void openHost(a.id) }}>
                      {t('health.agents.openLogShort')}
                    </Button>
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      ) : (
        <div className="mt-2 overflow-x-auto" role="region" aria-label={t('health.agents.title')} tabIndex={0}>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500">
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.agents.col.host')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.agents.col.status')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.agents.col.route')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.agents.col.version')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.agents.col.ip')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.agents.col.connectedFor')}</th>
                <th scope="col" className="py-1 pr-3 text-right font-normal">{t('health.agents.col.reconnects')}</th>
                <th scope="col" className="py-1 font-normal">{t('health.agents.col.cert')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => {
                const m = fleetMtls(a)
                const days = mtlsState(m) === 'none' ? null : mtlsDaysLeft(m, now)
                return (
                  <tr key={a.id} className="border-t border-slate-700/40 align-top">
                    <td className="py-1.5 pr-3">
                      <button type="button" className="wt-link text-left hover:underline" onClick={() => { void openHost(a.id) }}
                        aria-label={t('health.agents.openLog', { host: a.name })}>
                        {a.name}
                      </button>
                      {a.folder && <span className="block text-slate-500">{a.folder}</span>}
                    </td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">
                      <Badge tone={a.online ? 'ok' : 'danger'}>{t(a.online ? 'health.agents.online' : 'health.agents.offline')}</Badge>
                      {!a.online && a.last_heartbeat && (
                        <span className="block text-slate-500">{t('health.agents.lastSeen', { when: fmtTs(a.last_heartbeat) })}</span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">
                      {a.online && a.route
                        ? <Badge tone={a.route === 'mtls' ? 'info' : 'warn'}>{t(routeKey(a))}</Badge>
                        : <span className="text-slate-500">{t(routeKey(a))}</span>}
                    </td>
                    <td className={'py-1.5 pr-3 whitespace-nowrap tabular-nums'
                      + (a.agent_version != null && data.expected_version != null && a.agent_version < data.expected_version ? ' wt-warn' : '')}>
                      {a.agent_version ?? '—'}
                    </td>
                    <td className="py-1.5 pr-3 font-mono whitespace-nowrap">{a.agent_ip || '—'}</td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">
                      {a.online && a.connected_since ? fleetDuration(now - a.connected_since, t) : '—'}
                    </td>
                    <td className={'py-1.5 pr-3 text-right tabular-nums' + (a.reconnects_24h > 5 ? ' wt-warn' : '')}>{a.reconnects_24h}</td>
                    <td className={'py-1.5 whitespace-nowrap' + (days !== null && mtlsExpiringSoon(m, now) ? ' wt-warn' : '')}>
                      {days === null ? '—' : days < 0 ? t('health.agents.certExpired') : t('host.mtls.expires', { days })}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ))}
      {diag && createPortal(<DiagnosticModal key={diag.id} host={diag} initialTab="logs" onClose={() => setDiag(null)} />, document.body)}
    </div>
  )
}
