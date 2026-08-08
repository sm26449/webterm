import { useMemo, useRef, useState } from 'react'
import { matchCommandRule } from '../lib/commands'
import { errText, api, CommandGuard, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { copyText } from '../lib/clipboard'

type RunResult = {
  status: 'running' | 'done' | 'error'
  exit_code?: number | null
  timed_out?: boolean
  stdout?: string
  stderr?: string
  duration?: number
  error?: string
}

/** Consola de flotă: o comandă → N hosturi → grilă de rezultate.
    Trei faze în același modal: alegi hosturile, confirmi (pas deliberat),
    citești grila care se umple live pe măsură ce fiecare host răspunde. */
export default function FleetRunModal(props: { hosts: Host[]; onClose: () => void }) {
  const { t } = useI18n()
  // doar hosturi cu agent online pot rula (op-ul `run` merge doar prin agent)
  const runnable = useMemo(
    () => props.hosts.filter((h) => (!h.connection_type || h.connection_type === 'agent') && h.online),
    [props.hosts],
  )
  const [phase, setPhase] = useState<'pick' | 'confirm' | 'running'>('pick')
  const [selected, setSelected] = useState<Set<number>>(() => new Set(runnable.map((h) => h.id)))
  const [command, setCommand] = useState('')
  const [results, setResults] = useState<Record<number, RunResult>>({})
  const [expanded, setExpanded] = useState<number | null>(null)
  const [copied, setCopied] = useState(false)
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  const chosen = runnable.filter((h) => selected.has(h.id))
  const toggle = (id: number) =>
    setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })

  async function run() {
    // Guardrail: serverul aplică acum regulile şi pe `/run` — `block` refuză, `confirm` cere
    // un DA explicit. Îl întrebăm pe om AICI, o singură dată pentru toată flota, altfel ar
    // primi un 409 pe fiecare host şi n-ar şti de ce.
    const guard = await api<CommandGuard>('/api/settings/command-guard').catch(() => null)
    const rule = matchCommandRule(command.trim(), guard)
    if (rule?.action === 'block') {
      alert(t('fleet.guardBlocked', { pattern: rule.pattern }))
      return
    }
    const confirmed = rule ? window.confirm(t('fleet.guardConfirm', { pattern: rule.pattern })) : false
    if (rule && !confirmed) return
    setPhase('running')
    setResults(Object.fromEntries(chosen.map((h) => [h.id, { status: 'running' } as RunResult])))
    // o cerere PER host, în paralel; fiecare rând se completează când răspunde
    await Promise.all(chosen.map(async (h) => {
      try {
        const r = await api<RunResult>(`/api/hosts/${h.id}/run`, {
          method: 'POST', body: JSON.stringify({ command: command.trim(), timeout: 60, confirmed: true }),
        })
        setResults((prev) => ({ ...prev, [h.id]: { ...r, status: 'done' } }))
      } catch (e) {
        setResults((prev) => ({ ...prev, [h.id]: { status: 'error', error: errText(e, t) || t('fleet.error') } }))
      }
    }))
  }

  const summary = useMemo(() => {
    const vals = Object.values(results)
    return {
      total: vals.length,
      ok: vals.filter((r) => r.status === 'done' && !r.timed_out && r.exit_code === 0).length,
      fail: vals.filter((r) => r.status === 'error' || r.timed_out || (r.status === 'done' && r.exit_code !== 0)).length,
      running: vals.filter((r) => r.status === 'running').length,
    }
  }, [results])

  function reportMarkdown(): string {
    let md = `# ${t('fleet.reportTitle', { count: chosen.length })}\n\n\`\`\`console\n$ ${command.trim()}\n\`\`\`\n\n`
    for (const h of chosen) {
      const r = results[h.id]
      const badge = !r ? '—'
        : r.status === 'error' ? t('fleet.reportError', { error: r.error ?? '' })
        : r.timed_out ? 'TIMEOUT'
        : `exit ${r.exit_code}`
      md += `## ${h.name} — ${badge}\n\n`
      const body = [r?.stdout, r?.stderr].filter(Boolean).join('\n').trim()
      md += '```\n' + (body || t('fleet.noOutput')) + '\n```\n\n'
    }
    return md
  }
  async function copyReport() {
    if (!await copyText(reportMarkdown())) return   // idem
    setCopied(true); setTimeout(() => setCopied(false), 1500)
  }

  const rowState = (r?: RunResult) => {
    if (!r || r.status === 'running') return { dot: 'bg-sky-500 dot-live', badge: t('fleet.running'), cls: 'text-sky-400' }
    if (r.status === 'error') return { dot: 'bg-rose-500', badge: r.error || t('fleet.error'), cls: 'text-rose-400' }
    if (r.timed_out) return { dot: 'bg-rose-500', badge: `timeout · ${r.duration}s`, cls: 'text-rose-400' }
    const ok = r.exit_code === 0
    return { dot: ok ? 'bg-emerald-500' : 'bg-rose-500', badge: `exit ${r.exit_code} · ${r.duration}s`, cls: ok ? 'text-emerald-400' : 'text-rose-400' }
  }
  const oneLine = (r?: RunResult) => {
    if (!r || r.status === 'running') return t('fleet.connecting')
    if (r.status === 'error') return r.error || t('fleet.error')
    const body = (r.stdout || r.stderr || '').trim().split('\n').filter(Boolean)
    return body.length ? body[body.length - 1] : t('fleet.noOutput')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('nav.fleetRunAria')}
        className="flex max-h-[88vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-ink-700 bg-ink-900 shadow-2xl">
        <header className="flex items-center gap-2 border-b border-ink-800 px-4 py-3">
          <span className="font-semibold">{t('nav.fleetRunAria')}</span>
          {phase === 'running' && (
            <span className="font-mono text-xs text-slate-500">
              <b className="text-slate-300">{summary.total}</b> {t('fleet.hosts')} ·
              <span className="text-emerald-400"> ✓{summary.ok}</span>
              <span className="text-rose-400"> ✕{summary.fail}</span>
              {summary.running > 0 && <span className="text-sky-400"> ●{summary.running}</span>}
            </span>
          )}
          <button onClick={props.onClose} aria-label={t('fleet.close')}
            className="ml-auto rounded px-2 text-slate-500 hover:bg-ink-800 hover:text-slate-300">✕</button>
        </header>

        {/* ── faza „alegi" ── */}
        {phase === 'pick' && (
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
            {runnable.length === 0 ? (
              <p className="text-sm text-slate-500">{t('fleet.noAgentHosts')}</p>
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('fleet.hostsCount', { sel: chosen.length, total: runnable.length })}</span>
                  <button onClick={() => setSelected(new Set(chosen.length === runnable.length ? [] : runnable.map((h) => h.id)))}
                    className="text-xs wt-link hover:underline">
                    {chosen.length === runnable.length ? t('fleet.deselectAll') : t('fleet.allOnline')}
                  </button>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {runnable.map((h) => (
                    <button key={h.id} onClick={() => toggle(h.id)}
                      className={`rounded-lg border px-2.5 py-1 font-mono text-[13px] ${
                        selected.has(h.id) ? 'border-sky-500 bg-sky-500/10 wt-accent' : 'border-ink-700 bg-ink-800 text-slate-400 hover:border-ink-600'}`}>
                      {selected.has(h.id) ? '✓ ' : ''}{h.name}
                    </button>
                  ))}
                </div>
                <label className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-400">{t('fleet.command')}</label>
                <textarea value={command} onChange={(e) => setCommand(e.target.value)} rows={3} autoFocus spellCheck={false}
                  placeholder={t('fleet.commandPlaceholder')} aria-label={t('fleet.command')}
                  className="rounded-lg bg-ink-800 px-3 py-2 font-mono text-sm text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                <p className="text-xs text-slate-500">{t('fleet.commandHint')}</p>
              </>
            )}
          </div>
        )}

        {/* ── faza „confirmi" (pas deliberat) ── */}
        {phase === 'confirm' && (
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
            <div className="flex items-center gap-2 font-medium text-amber-300">⚠ {t('fleet.youRunOn')} {t('fleet.hostCount', { count: chosen.length })}</div>
            <div className="rounded-lg bg-ink-800/60 px-3 py-2 font-mono text-sm text-slate-200">$ {command.trim()}</div>
            <div className="flex flex-wrap gap-1.5">
              {chosen.map((h) => <span key={h.id} className="rounded bg-ink-800 px-2 py-0.5 font-mono text-xs text-slate-400 ring-1 ring-ink-700">{h.name}</span>)}
            </div>
          </div>
        )}

        {/* ── faza „grila" ── */}
        {phase === 'running' && (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <div className="border-b border-ink-800 bg-ink-800/40 px-4 py-2 font-mono text-[13px] text-slate-300">$ {command.trim()}</div>
            {chosen.map((h) => {
              const r = results[h.id]; const st = rowState(r); const isOpen = expanded === h.id
              const full = [r?.stdout, r?.stderr].filter(Boolean).join('\n').trim()
              return (
                <div key={h.id} className="border-b border-ink-800/60">
                  <button onClick={() => setExpanded(isOpen ? null : h.id)}
                    className="flex w-full items-center gap-2.5 px-4 py-2.5 text-left hover:bg-ink-800/40">
                    <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${st.dot}`} />
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[13.5px] font-semibold text-slate-200">{h.name}</span>
                      <span className={`block truncate font-mono text-[11.5px] ${r?.status === 'error' || (r?.status === 'done' && r?.exit_code !== 0) ? 'text-rose-400/80' : 'text-slate-500'}`}>{oneLine(r)}</span>
                    </span>
                    <span className={`shrink-0 rounded-full border border-ink-700 px-2 py-0.5 font-mono text-[11px] ${st.cls}`}>{st.badge}</span>
                  </button>
                  {isOpen && (
                    <div className="px-4 pb-3 pl-11">
                      <pre className="max-h-72 overflow-auto rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-[12px] text-slate-200">{full || t('fleet.noOutput')}</pre>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}

        <footer className="flex items-center gap-2 border-t border-ink-800 px-4 py-3">
          {phase === 'pick' && (
            <button disabled={chosen.length === 0 || !command.trim()} onClick={() => setPhase('confirm')}
              className="rounded-lg bg-sky-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-40">
              {t('fleet.continue')}
            </button>
          )}
          {phase === 'confirm' && (
            <>
              <button onClick={run}
                className="rounded-lg bg-amber-500 px-4 py-1.5 text-sm font-semibold text-ink-950 hover:bg-amber-400">
                {t('fleet.runOn')} {t('fleet.hostCount', { count: chosen.length })}
              </button>
              <button onClick={() => setPhase('pick')} className="rounded-lg px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800">{t('fleet.back')}</button>
            </>
          )}
          {phase === 'running' && (
            <>
              <button disabled={summary.running > 0} onClick={copyReport}
                className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
                {copied ? t('fleet.copied') : t('fleet.copyReport')}
              </button>
              <button disabled={summary.running > 0} onClick={() => { setPhase('pick'); setResults({}); setExpanded(null) }}
                className="rounded-lg px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800 disabled:opacity-40">{t('fleet.newRun')}</button>
              <span className="ml-auto text-xs text-slate-500">{summary.running > 0 ? t('fleet.running') : t('fleet.done')}</span>
            </>
          )}
        </footer>
      </div>
    </div>
  )
}
