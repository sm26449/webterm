import { ReactNode, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useI18n } from '../lib/i18n'
import UpdateCommand from './UpdateCommand'

interface Status {
  uptime_seconds: number
  gateway_version: string
  image: string | null
  agent_latest: number | null
  hosts: { total: number; online: number; offline: number }
  sessions: { live: number; closed: number; lost: number }
  storage: {
    transcripts_files: number
    transcripts_bytes: number
    archive_files: number
    archive_bytes: number
    retention_days: number
    disk_free_bytes: number | null
    disk_total_bytes: number | null
  }
  gateway?: {
    rss_mb: number
    event_loop_lag_ms: number
    event_loop_lag_max_ms: number
    browser_clients: number
    active_hubs: number
    agent_connections: number
    db_ping_ms: number
  }
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`
}

function humanUptime(s: number): string {
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d}z ${h}h`
  if (h) return `${h}h ${m}m`
  return `${m}m`
}

interface VersionInfo {
  current: string
  enabled: boolean
  latest?: string
  update_available?: boolean
  update_command?: string
  error?: string
}

export default function StatusModal(props: { onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [s, setS] = useState<Status | null>(null)
  const [err, setErr] = useState(false)
  const [ver, setVer] = useState<VersionInfo | null>(null)

  useEffect(() => {
    const load = () => api<Status>('/api/status').then(setS).catch(() => setErr(true))
    load()
    const t = setInterval(() => { if (!document.hidden) load() }, 5000)
    // verificarea de versiune e cache-uită server-side (1h) — o cerem o dată
    api<VersionInfo>('/api/version').then(setVer).catch(() => {})
    return () => clearInterval(t)
  }, [])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('status.title')}
        className="glass max-h-[88vh] w-full max-w-md overflow-y-auto rounded-2xl p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('status.title')}</h2>
          <button onClick={props.onClose} aria-label={t('common.close')} className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
            ✕
          </button>
        </div>

        {err && <p className="mt-4 text-sm wt-danger">{t('status.loadError')}</p>}
        {!s && !err && <p className="mt-4 text-sm text-slate-500">{t('status.loading')}</p>}

        {s && (
          <div className="mt-4 flex flex-col gap-5">
            <div className="grid grid-cols-2 gap-3">
              <Stat label={t('status.hostsOnline')} value={`${s.hosts.online}/${s.hosts.total}`}
                    good={s.hosts.offline === 0} />
              <Stat label={t('status.sessionsLive')} value={s.sessions.live} />
              <Stat label={t('status.sessionsClosed')} value={s.sessions.closed} muted />
              <Stat label={t('status.sessionsLost')} value={s.sessions.lost} bad={s.sessions.lost > 0} muted />
            </div>

            <div>
              <h3 className="text-[13px] font-semibold uppercase tracking-wide text-slate-400">{t('status.storage')}</h3>
              <dl className="mt-2 divide-y divide-ink-800 text-sm">
                <Row k={t('status.transcriptsActive')} v={`${humanBytes(s.storage.transcripts_bytes)} · ${t('status.filesCount', { count: s.storage.transcripts_files })}`} />
                <Row k={t('status.archive')} v={`${humanBytes(s.storage.archive_bytes)} · ${t('status.filesCount', { count: s.storage.archive_files })}`} />
                <Row k={t('status.archiveRetention')} v={t('status.retentionValue', { days: s.storage.retention_days })} />
                {/* Spaţiul RĂMAS, nu doar cât ocupăm. Un disc plin arăta identic cu unul gol:
                    containerul rămâne `healthy`, `db_ping` (o citire) rămâne verde, iar
                    login-ul dă 500. Sub 10% colorăm — e ultimul moment util. */}
                {s.storage.disk_total_bytes ? (() => {
                  const free = s.storage.disk_free_bytes ?? 0
                  const pct = (free * 100) / s.storage.disk_total_bytes
                  const cls = pct < 5 ? 'wt-danger' : pct < 10 ? 'wt-warn' : ''
                  return (
                    <Row k={t('status.diskFree')}
                         v={<span className={cls}>
                              {humanBytes(free)} / {humanBytes(s.storage.disk_total_bytes)} ({pct.toFixed(0)}%)
                            </span>} />
                  )
                })() : null}
              </dl>
            </div>

            <div>
              <h3 className="text-[13px] font-semibold uppercase tracking-wide text-slate-400">{t('status.system')}</h3>
              <dl className="mt-2 divide-y divide-ink-800 text-sm">
                <Row k={t('status.uptime')} v={humanUptime(s.uptime_seconds)} />
                <div className="flex items-center justify-between py-2">
                  <dt className="text-slate-500">{t('status.gatewayVersion')}</dt>
                  <dd className="flex items-center gap-2 font-medium text-slate-300 tabular-nums">
                    <span>{s.gateway_version}</span>
                    {ver?.enabled && ver.update_available && (
                      <span className="wt-warn rounded-full bg-amber-500/15 px-2 py-0.5 text-xs font-medium ring-1 ring-amber-500/25">
                        {t('status.updateAvailable', { version: ver.latest ?? '' })}
                      </span>
                    )}
                    {ver?.enabled && ver.update_available === false && (
                      <span className="text-xs wt-good">{t('status.upToDate')}</span>
                    )}
                  </dd>
                </div>
                {ver?.update_command && (
                  <div className="py-2">
                    <p className="text-xs text-slate-500">{t('settings.update.howTo')}</p>
                    <UpdateCommand command={ver.update_command} />
                  </div>
                )}
                {s.image && <Row k={t('status.image')} v={s.image} />}
                <Row k={t('status.agentRecommended')} v={s.agent_latest != null ? `v${s.agent_latest}` : '—'} />
              </dl>
            </div>

            {/* sănătatea gateway-ului însuși — degradarea vizibilă înainte de cădere */}
            {s.gateway && (
              <div>
                <h3 className="text-[13px] font-semibold uppercase tracking-wide text-slate-400">{t('status.gatewayHealth')}</h3>
                <dl className="mt-2 divide-y divide-ink-800 text-sm">
                  <Row k={t('status.processMemory')} v={`${s.gateway.rss_mb} MiB`} />
                  <div className="flex items-center justify-between gap-3 py-2">
                    <dt className="shrink-0 text-slate-500">{t('status.eventLoopLag')}</dt>
                    {/* lag mare = event-loop supraîncărcat/blocat; pragurile ca la RTT */}
                    <dd className={`text-right font-medium tabular-nums ${
                      s.gateway.event_loop_lag_max_ms < 50 ? 'wt-good' : s.gateway.event_loop_lag_max_ms < 250 ? 'wt-warn' : 'wt-danger'
                    }`}>
                      {s.gateway.event_loop_lag_ms} ms <span className="text-slate-400">(max {s.gateway.event_loop_lag_max_ms})</span>
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-3 py-2">
                    <dt className="shrink-0 text-slate-500">{t('status.dbPing')}</dt>
                    <dd className={`text-right font-medium tabular-nums ${
                      s.gateway.db_ping_ms < 20 ? 'wt-good' : s.gateway.db_ping_ms < 100 ? 'wt-warn' : 'wt-danger'
                    }`}>{s.gateway.db_ping_ms} ms</dd>
                  </div>
                  <Row k={t('status.connections')} v={`${s.gateway.browser_clients} · ${s.gateway.agent_connections}`} />
                </dl>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function Stat(props: { label: string; value: number | string; good?: boolean; bad?: boolean; muted?: boolean }) {
  const tone = props.bad ? 'wt-danger' : props.good ? 'wt-good' : props.muted ? 'text-slate-300' : 'text-sky-400'
  return (
    <div className="rounded-xl bg-ink-800/60 px-3 py-2.5 ring-1 ring-ink-700">
      <div className={`text-2xl font-semibold tabular-nums ${tone}`}>{props.value}</div>
      <div className="mt-0.5 text-xs text-slate-500">{props.label}</div>
    </div>
  )
}

function Row(props: { k: string; v: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2">
      <dt className="shrink-0 text-slate-500">{props.k}</dt>
      {/* break-all: valori fără spații (referința imaginii Docker) nu se rup
          natural și ar da overflow orizontal pe ecrane înguste */}
      <dd className="min-w-0 break-all text-right font-medium text-slate-300 tabular-nums">{props.v}</dd>
    </div>
  )
}
