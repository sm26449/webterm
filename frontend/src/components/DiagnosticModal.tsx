import { useEffect, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { fmtTs } from '../lib/tz'

type T = (key: string, vars?: Record<string, string | number>) => string

interface AgentEvent { ts: number; event: string; reason: string; detail: string }
interface Link { uptime?: number | null; reconnects?: number | null; rtt_ms?: number | null }
// snapshot complet (pushat de agent la connect + orar, on-demand la Refresh) — câmpuri best-effort
interface DiagSystem { hostname?: string; kernel?: string; os?: string; arch?: string; uptime_sec?: number }
interface DiagCpu { model?: string; cores?: number; load1?: number; load5?: number; load15?: number }
interface DiagMem { total?: number; used?: number; available?: number; swap_total?: number; swap_used?: number }
interface DiagFs { mount: string; fstype: string; total: number; used: number; avail: number }
interface DiagIface { name: string; state: string; mac?: string; mtu?: number; ipv4: string[]; ipv6: string[]; rx_bytes?: number; tx_bytes?: number }
interface DiagRoute { family: string; dest: string; gateway?: string; iface?: string; metric?: string }
interface Snapshot {
  collected_at?: number
  system?: DiagSystem; cpu?: DiagCpu; memory?: DiagMem
  storage?: DiagFs[]; network?: { interfaces?: DiagIface[]; routes?: DiagRoute[] }
}
interface Diag {
  online: boolean
  last_heartbeat: number | null
  agent_version: number | null
  connection_type: string | null
  agent_ip?: string | null
  link?: Link
  events: AgentEvent[]
  diagnostics?: Snapshot | null
  diagnostics_at?: number | null
}

function dur(sec: number, t: T): string {
  if (sec < 60) return `${sec}s`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${m}min`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}min`
  return t('diag.durDaysHours', { d: Math.floor(h / 24), h: h % 24 })
}

function ago(sec: number, t: T): string {
  if (sec < 60) return t('diag.agoFewSeconds')
  const m = Math.floor(sec / 60)
  if (m < 60) return t('diag.agoMinutes', { m })
  const h = Math.floor(m / 60)
  if (h < 24) return t('diag.agoHoursMinutes', { h, m: m % 60 })
  const d = Math.floor(h / 24)
  return t('diag.agoDay', { d, count: d })
}

function stamp(ts: number): string {
  return fmtTs(ts)
}

// octeţi → unitate lizibilă (baza 1024, ca restul aplicaţiei)
function fmtBytes(n: number): string {
  if (!n || n < 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}

// aspectul fiecărui tip de eveniment din jurnal (label = cheie i18n)
const META: Record<string, { icon: string; cls: string; label: string }> = {
  connect: { icon: '🟢', cls: 'wt-good', label: 'diag.evtConnect' },
  disconnect: { icon: '🔴', cls: 'wt-danger', label: 'diag.evtDisconnect' },
  update_pushed: { icon: '⬆️', cls: 'text-sky-300', label: 'diag.evtUpdatePushed' },
  update_deferred: { icon: '⏳', cls: 'text-sky-300', label: 'diag.evtUpdateDeferred' },
  update_applied: { icon: '✅', cls: 'wt-good', label: 'diag.evtUpdateApplied' },
  conflict: { icon: '⚠️', cls: 'text-amber-300', label: 'diag.evtConflict' },
}

const REASON: Record<string, { text: string; danger?: boolean }> = {
  heartbeat_stale: { text: 'diag.reasonHeartbeatStale', danger: true },
  ws_error: { text: 'diag.reasonWsError', danger: true },
  instance_refused: { text: 'diag.reasonInstanceRefused', danger: true },
  superseded: { text: 'diag.reasonSuperseded' },
  closed: { text: 'diag.reasonClosed' },
}

type Tab = 'overview' | 'storage' | 'network' | 'logs'

// bară de utilizare (disc / memorie): verde < 75%, chihlimbar < 90%, roşu peste
function UsageBar({ used, total }: { used: number; total: number }) {
  const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0
  const cls = pct < 75 ? 'bg-emerald-500' : pct < 90 ? 'bg-amber-500' : 'bg-rose-500'
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-700">
      <div className={`h-full ${cls}`} style={{ width: `${pct}%` }} />
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg bg-ink-800 px-3 py-2">
      <div className="text-[11px] text-slate-500">{label}</div>
      <div className="truncate text-[13px] text-slate-200" title={typeof children === 'string' ? children : undefined}>{children}</div>
    </div>
  )
}

/** Diagnostic al host-ului: conexiune + snapshot complet (sistem/CPU/memorie/storage/reţea+rute),
    pe tab-uri. Snapshot-ul e ultimul cunoscut — vizibil ŞI când hostul e down. */
export default function DiagnosticModal(props: { host: Host; onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [diag, setDiag] = useState<Diag | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('overview')
  const [refreshing, setRefreshing] = useState(false)
  const [log, setLog] = useState<string | null>(null)
  const [logBusy, setLogBusy] = useState(false)
  const [logErr, setLogErr] = useState('')

  const loadLog = () => {
    setLogBusy(true); setLogErr('')
    api<{ log: string }>(`/api/hosts/${props.host.id}/agent-log`)
      .then((r) => setLog(r.log || t('diag.emptyLog')))
      .catch((e) => setLogErr(errText(e, t) || t('diag.logLoadFailed')))
      .finally(() => setLogBusy(false))
  }

  const load = () => {
    setLoading(true); setErr('')
    api<Diag>(`/api/hosts/${props.host.id}/events`)
      .then(setDiag)
      .catch((e) => setErr(errText(e, t) || t('diag.eventsLoadFailed')))
      .finally(() => setLoading(false))
  }
  useEffect(load, [props.host.id])   // eslint-disable-line react-hooks/exhaustive-deps

  // Refresh on-demand: cere agentului un snapshot proaspăt (doar când e online).
  const refresh = () => {
    setRefreshing(true); setErr('')
    api<{ diagnostics: Snapshot }>(`/api/hosts/${props.host.id}/diagnostics/refresh`, { method: 'POST' })
      .then((r) => setDiag((d) => d ? { ...d, diagnostics: r.diagnostics, diagnostics_at: r.diagnostics?.collected_at ?? null } : d))
      .catch((e) => setErr(errText(e, t) || t('diag.refreshFailed')))
      .finally(() => setRefreshing(false))
  }

  const now = Date.now() / 1000
  const hbAge = diag?.last_heartbeat ? now - diag.last_heartbeat : null
  const snap = diag?.diagnostics || null
  const snapAge = diag?.diagnostics_at ? now - diag.diagnostics_at : null

  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: t('diag.tab.overview') },
    { id: 'storage', label: t('diag.tab.storage') },
    { id: 'network', label: t('diag.tab.network') },
    { id: 'logs', label: t('diag.tab.logs') },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('diag.aria')}
        className="glass flex h-[85vh] w-full max-w-3xl flex-col rounded-2xl">
        {/* antet */}
        <div className="flex items-center justify-between border-b border-ink-800 px-5 py-3">
          <h2 className="font-semibold">🩺 {t('diag.title')} · {props.host.name}</h2>
          <div className="flex items-center gap-3">
            <span className={`text-xs ${diag?.online ? 'wt-good' : 'wt-danger'}`}>
              {diag ? (diag.online ? `● ${t('diag.stateOnline')}` : `● ${t('diag.stateOffline')}`) : ''}
            </span>
            <button onClick={props.onClose} aria-label={t('diag.close')}
              className="wt-touch grid place-items-center rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
          </div>
        </div>

        {/* rail de tab-uri */}
        <div className="flex shrink-0 gap-1 border-b border-ink-800 px-3 py-2">
          {TABS.map((c) => (
            <button key={c.id} onClick={() => setTab(c.id)}
              aria-current={tab === c.id ? 'true' : undefined}
              className={`wt-touch rounded-lg px-3 py-1.5 text-sm ${
                tab === c.id ? 'bg-sky-600 text-white' : 'text-slate-300 hover:bg-ink-800'}`}>
              {c.label}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-3 pr-1 text-[11px] text-slate-500">
            {tab !== 'logs' && snapAge != null && (
              <span title={diag?.diagnostics_at ? stamp(diag.diagnostics_at) : ''}>
                {t('diag.collectedAt', { when: ago(snapAge, t) })}
              </span>
            )}
            {tab !== 'logs' && (
              <button onClick={refresh} disabled={refreshing || !diag?.online}
                title={!diag?.online ? t('diag.refreshOfflineHint') : ''}
                className="wt-link hover:underline disabled:opacity-40">
                {refreshing ? t('diag.loading') : t('diag.refresh')}
              </button>
            )}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {err && <div className="mb-3 rounded-lg bg-ink-800 px-3 py-2 text-xs wt-danger">{err}</div>}
          {loading && !diag ? (
            <div className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-500">{t('diag.loadingEllipsis')}</div>
          ) : !diag ? null : (<>

            {/* banner: snapshot vechi când hostul e offline */}
            {tab !== 'logs' && !diag.online && snapAge != null && (
              <div className="mb-3 rounded-lg bg-amber-500/10 px-3 py-2 text-xs wt-warn ring-1 ring-amber-500/25">
                {t('diag.staleOffline', { when: ago(snapAge, t) })}
              </div>
            )}
            {tab !== 'logs' && !snap && (
              <div className="mb-3 rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-500">{t('diag.noSnapshot')}</div>
            )}

            {/* ── OVERVIEW ── */}
            {tab === 'overview' && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <Field label={t('diag.lastHeartbeat')}>{hbAge != null ? ago(hbAge, t) : '—'}</Field>
                  <Field label={t('diag.agent')}>{diag.agent_version ? `v${diag.agent_version}` : '—'}</Field>
                  {diag.agent_ip && <Field label={t('diag.agentIp')}>{diag.agent_ip}</Field>}
                  {diag.online && diag.link?.rtt_ms != null && <Field label="RTT">{`${diag.link.rtt_ms} ms`}</Field>}
                  {diag.online && diag.link?.uptime != null && <Field label={t('diag.uptimeConnection')}>{dur(diag.link.uptime, t)}</Field>}
                  {diag.online && <Field label={t('diag.reconnects')}>{String(diag.link?.reconnects ?? 0)}</Field>}
                </div>

                {snap?.system && (
                  <div>
                    <div className="mb-1 text-xs font-medium text-slate-400">{t('diag.system')}</div>
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                      {snap.system.os && <Field label={t('diag.os')}>{snap.system.os}</Field>}
                      {snap.system.kernel && <Field label={t('diag.kernel')}>{snap.system.kernel}</Field>}
                      {snap.system.arch && <Field label={t('diag.arch')}>{snap.system.arch}</Field>}
                      {snap.system.hostname && <Field label={t('diag.hostname')}>{snap.system.hostname}</Field>}
                      {snap.system.uptime_sec != null && <Field label={t('diag.uptimeSystem')}>{dur(snap.system.uptime_sec, t)}</Field>}
                    </div>
                  </div>
                )}

                {snap?.cpu && (
                  <div>
                    <div className="mb-1 text-xs font-medium text-slate-400">{t('diag.cpu')}</div>
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                      {snap.cpu.model && <Field label={t('diag.cpuModel')}>{snap.cpu.model}</Field>}
                      {snap.cpu.cores != null && <Field label={t('diag.cores')}>{String(snap.cpu.cores)}</Field>}
                      {snap.cpu.load1 != null && <Field label={t('diag.loadAvg')}>{`${snap.cpu.load1} · ${snap.cpu.load5} · ${snap.cpu.load15}`}</Field>}
                    </div>
                  </div>
                )}

                {snap?.memory && (
                  <div>
                    <div className="mb-1 text-xs font-medium text-slate-400">{t('diag.memory')}</div>
                    <div className="space-y-2">
                      {snap.memory.total != null && (
                        <div className="rounded-lg bg-ink-800 px-3 py-2">
                          <div className="mb-1 flex justify-between text-[12px] text-slate-400">
                            <span>RAM</span>
                            <span className="text-slate-300">{fmtBytes(snap.memory.used ?? 0)} / {fmtBytes(snap.memory.total)}</span>
                          </div>
                          <UsageBar used={snap.memory.used ?? 0} total={snap.memory.total} />
                        </div>
                      )}
                      {snap.memory.swap_total ? (
                        <div className="rounded-lg bg-ink-800 px-3 py-2">
                          <div className="mb-1 flex justify-between text-[12px] text-slate-400">
                            <span>{t('diag.swap')}</span>
                            <span className="text-slate-300">{fmtBytes(snap.memory.swap_used ?? 0)} / {fmtBytes(snap.memory.swap_total)}</span>
                          </div>
                          <UsageBar used={snap.memory.swap_used ?? 0} total={snap.memory.swap_total} />
                        </div>
                      ) : null}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── STORAGE ── */}
            {tab === 'storage' && (
              snap?.storage?.length ? (
                <div className="space-y-2">
                  {snap.storage.map((fs) => (
                    <div key={fs.mount} className="rounded-lg bg-ink-800 px-3 py-2">
                      <div className="mb-1 flex items-baseline justify-between gap-2">
                        <span className="truncate font-mono text-[13px] text-slate-200" title={fs.mount}>{fs.mount}</span>
                        <span className="shrink-0 text-[11px] text-slate-500">{fs.fstype}</span>
                      </div>
                      <UsageBar used={fs.used} total={fs.total} />
                      <div className="mt-1 text-[11px] text-slate-500">
                        {t('diag.storageLine', { used: fmtBytes(fs.used), total: fmtBytes(fs.total), avail: fmtBytes(fs.avail) })}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-500">{t('diag.noSnapshot')}</div>
              )
            )}

            {/* ── NETWORK ── */}
            {tab === 'network' && (
              <div className="space-y-4">
                <div>
                  <div className="mb-1 text-xs font-medium text-slate-400">{t('diag.netInterfaces')}</div>
                  {snap?.network?.interfaces?.length ? (
                    <div className="space-y-1">
                      {snap.network.interfaces.map((it) => (
                        <div key={it.name} className="rounded-lg bg-ink-800 px-3 py-2 text-sm ring-1 ring-ink-700">
                          <div className="flex items-center gap-2">
                            <span className={`text-[10px] ${it.state === 'up' ? 'wt-good' : 'text-slate-500'}`}>●</span>
                            <span className="font-mono text-[13px] text-slate-200">{it.name}</span>
                            <span className="text-[11px] text-slate-500">{it.state}</span>
                            {it.mtu ? <span className="text-[11px] text-slate-600">MTU {it.mtu}</span> : null}
                            {it.mac && <span className="ml-auto font-mono text-[11px] text-slate-500">{it.mac}</span>}
                          </div>
                          {(it.ipv4.length > 0 || it.ipv6.length > 0) && (
                            <div className="mt-1 flex flex-wrap gap-1">
                              {[...it.ipv4, ...it.ipv6].map((ip) => (
                                <span key={ip} className="rounded bg-ink-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">{ip}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-500">{t('diag.noSnapshot')}</div>
                  )}
                </div>
                {snap?.network?.routes?.length ? (
                  <div>
                    <div className="mb-1 text-xs font-medium text-slate-400">{t('diag.netRoutes')}</div>
                    <div className="overflow-x-auto rounded-lg ring-1 ring-ink-700">
                      <table className="w-full text-left text-[12px]">
                        <thead className="bg-ink-800 text-[11px] text-slate-500">
                          <tr>
                            <th className="px-2 py-1 font-medium">{t('diag.routeDest')}</th>
                            <th className="px-2 py-1 font-medium">{t('diag.routeGateway')}</th>
                            <th className="px-2 py-1 font-medium">{t('diag.routeIface')}</th>
                          </tr>
                        </thead>
                        <tbody className="font-mono text-slate-300">
                          {snap.network.routes.map((r, i) => (
                            <tr key={i} className="border-t border-ink-800">
                              <td className="px-2 py-1">{r.dest}</td>
                              <td className="px-2 py-1 text-slate-400">{r.gateway || '—'}</td>
                              <td className="px-2 py-1 text-slate-400">{r.iface || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null}
              </div>
            )}

            {/* ── LOGS ── (jurnal de conexiune 7 zile + tail ptyd.log) */}
            {tab === 'logs' && (
              <div className="space-y-4">
                <div>
                  <div className="mb-1 flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-400">{t('diag.connectionLog')}</span>
                    <button onClick={load} disabled={loading} className="text-xs wt-link hover:underline disabled:opacity-50">
                      {loading ? t('diag.loading') : t('diag.reload')}
                    </button>
                  </div>
                  {diag.events.length ? (
                    <ul className="space-y-1">
                      {diag.events.map((e, i) => {
                        const m = META[e.event] || { icon: '•', cls: 'text-slate-300', label: e.event }
                        const r = e.event === 'disconnect' ? REASON[e.reason] : undefined
                        return (
                          <li key={i} className="flex items-start gap-2 rounded-lg bg-ink-800 px-2.5 py-1.5 text-sm ring-1 ring-ink-700">
                            <span className="mt-0.5">{m.icon}</span>
                            <span className="min-w-0 flex-1">
                              <span className="flex flex-wrap items-baseline gap-x-2">
                                <span className={`font-medium ${m.cls}`}>{t(m.label)}</span>
                                {r && <span className={`text-[12px] ${r.danger ? 'wt-danger' : 'text-slate-400'}`}>{t(r.text)}</span>}
                                {e.detail && <span className="text-[11px] text-slate-500">{e.detail}</span>}
                              </span>
                              <span className="block text-[11px] text-slate-500" title={stamp(e.ts)}>
                                {ago(now - e.ts, t)} · {stamp(e.ts)}
                              </span>
                            </span>
                          </li>
                        )
                      })}
                    </ul>
                  ) : (
                    <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-500">{t('diag.noEvents')}</div>
                  )}
                </div>

                {diag.online && (
                  <div>
                    <div className="mb-1 flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-400">{t('diag.agentLog')}</span>
                      <button onClick={loadLog} disabled={logBusy} className="text-xs wt-link hover:underline disabled:opacity-50">
                        {logBusy ? t('diag.loading') : log ? t('diag.reload') : t('diag.loadAgentLog')}
                      </button>
                    </div>
                    {logErr && <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs wt-danger">{logErr}</div>}
                    {log != null && (
                      <pre className="max-h-80 overflow-auto rounded-lg bg-ink-900 p-2 text-[11px] leading-relaxed text-slate-300 ring-1 ring-ink-700">{log}</pre>
                    )}
                  </div>
                )}
              </div>
            )}
          </>)}
        </div>
      </div>
    </div>
  )
}
