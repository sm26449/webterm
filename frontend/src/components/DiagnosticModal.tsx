import { useEffect, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

type T = (key: string, vars?: Record<string, string | number>) => string

interface AgentEvent { ts: number; event: string; reason: string; detail: string }
interface Link { uptime?: number | null; reconnects?: number | null; rtt_ms?: number | null }
interface Diag {
  online: boolean
  last_heartbeat: number | null
  agent_version: number | null
  connection_type: string | null
  agent_ip?: string | null
  link?: Link
  events: AgentEvent[]
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
  // Ternar binar: corect in engleza, gresit in romana (20 de zile). `count` intra in
  // `t()` ca sa aleaga forma prin Intl.PluralRules.
  return t('diag.agoDay', { d, count: d })
}

function stamp(ts: number): string {
  try { return new Date(ts * 1000).toLocaleString() } catch { return '' }
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
// motivul de deconectare, tradus + colorat după gravitate (text = cheie i18n)
const REASON: Record<string, { text: string; danger?: boolean }> = {
  heartbeat_stale: { text: 'diag.reasonHeartbeatStale', danger: true },
  ws_error: { text: 'diag.reasonWsError', danger: true },
  instance_refused: { text: 'diag.reasonInstanceRefused', danger: true },
  superseded: { text: 'diag.reasonSuperseded' },
  closed: { text: 'diag.reasonClosed' },
}

/** Diagnostic al conexiunii agentului: stare curentă + jurnal de evenimente pe 7 zile
    (connect/disconnect cu MOTIV, update-uri, conflicte) — ca să vezi din UI ce s-a întâmplat. */
export default function DiagnosticModal(props: { host: Host; onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [diag, setDiag] = useState<Diag | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
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

  const now = Date.now() / 1000
  const hbAge = diag?.last_heartbeat ? now - diag.last_heartbeat : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('diag.aria')}
        className="glass flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl p-6">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">🩺 {t('diag.title')} · {props.host.name}</h2>
          <button onClick={load} disabled={loading}
            className="text-xs wt-link hover:underline disabled:opacity-50">
            {loading ? t('diag.loading') : t('diag.reload')}
          </button>
        </div>

        {/* stare curentă */}
        {diag && (
          <div className="mt-3 grid grid-cols-3 gap-2 text-sm">
            <div className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="text-[11px] text-slate-500">{t('diag.state')}</div>
              <div className={diag.online ? 'wt-good' : 'wt-danger'}>
                {diag.online ? t('diag.stateOnline') : t('diag.stateOffline')}
              </div>
            </div>
            <div className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="text-[11px] text-slate-500">{t('diag.lastHeartbeat')}</div>
              <div className="text-slate-200" title={diag.last_heartbeat ? stamp(diag.last_heartbeat) : ''}>
                {hbAge != null ? ago(hbAge, t) : '—'}
              </div>
            </div>
            <div className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="text-[11px] text-slate-500">{t('diag.agent')}</div>
              <div className="text-slate-200">{diag.agent_version ? `v${diag.agent_version}` : '—'}</div>
            </div>
            {diag.agent_ip && (
              <div className="rounded-lg bg-ink-800 px-3 py-2">
                <div className="text-[11px] text-slate-500">{t('diag.agentIp')}</div>
                <div className="truncate font-mono text-[13px] text-slate-200" title={diag.agent_ip}>{diag.agent_ip}</div>
              </div>
            )}
          </div>
        )}

        {/* health de link (Faza 3): RTT real agent↔gateway, uptime, flapping */}
        {diag?.online && diag.link && (diag.link.rtt_ms != null || diag.link.uptime != null) && (
          <div className="mt-2 grid grid-cols-3 gap-2 text-sm">
            <div className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="text-[11px] text-slate-500">RTT agent↔gateway</div>
              <div className={diag.link.rtt_ms == null ? 'text-slate-500'
                : diag.link.rtt_ms < 120 ? 'wt-good' : diag.link.rtt_ms < 350 ? 'wt-warn' : 'wt-danger'}>
                {diag.link.rtt_ms != null ? `${diag.link.rtt_ms} ms` : '—'}
              </div>
            </div>
            <div className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="text-[11px] text-slate-500">{t('diag.uptimeConnection')}</div>
              <div className="text-slate-200">{diag.link.uptime != null ? dur(diag.link.uptime, t) : '—'}</div>
            </div>
            <div className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="text-[11px] text-slate-500">{t('diag.reconnects')}</div>
              <div className={diag.link.reconnects ? 'wt-warn' : 'text-slate-200'}>
                {diag.link.reconnects ?? 0}{(diag.link.reconnects ?? 0) > 0 ? ' ⚠' : ''}
              </div>
            </div>
          </div>
        )}

        {/* jurnal de evenimente (7 zile) */}
        <div className="mt-4 min-h-0 flex-1 overflow-y-auto">
          <div className="mb-1 text-xs font-medium text-slate-400">{t('diag.connectionLog')}</div>
          {err ? (
            <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs wt-danger">{err}</div>
          ) : loading && !diag ? (
            <div className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-500">{t('diag.loadingEllipsis')}</div>
          ) : diag && diag.events.length ? (
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
            <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-500">
              {t('diag.noEvents')}
            </div>
          )}
        </div>

        {/* log agent (tail ptyd.log) — debug fără SSH; doar când e online */}
        {diag?.online && (
          <div className="mt-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">{t('diag.agentLog')}</span>
              <button onClick={loadLog} disabled={logBusy}
                className="text-xs wt-link hover:underline disabled:opacity-50">
                {logBusy ? t('diag.loading') : log ? t('diag.reload') : t('diag.loadAgentLog')}
              </button>
            </div>
            {logErr && <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs wt-danger">{logErr}</div>}
            {log != null && (
              <pre className="max-h-48 overflow-auto rounded-lg bg-ink-900 p-2 text-[11px] leading-relaxed text-slate-300 ring-1 ring-ink-700">{log}</pre>
            )}
          </div>
        )}

        <div className="mt-5 flex justify-end">
          <button onClick={props.onClose} className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-ink-800">{t('diag.close')}</button>
        </div>
      </div>
    </div>
  )
}
