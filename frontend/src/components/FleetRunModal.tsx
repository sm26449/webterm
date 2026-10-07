import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { matchCommandRule } from '../lib/commands'
import { errText, api, ApiError, ensureStepup, isEphemeralHost, CommandGuard, Host, Snippet } from '../lib/api'
import {
  fillSnippet, hostsMatchingTags, migrateFleetSaved, snippetParams, snippetTags, sortForFleet,
  tagsOfHosts, targetsPayload,
} from '../lib/snippets'
import SnippetTags from './SnippetTags'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useConfirm } from '../lib/confirm'
import { notifyError } from '../lib/notify'
import { copyText } from '../lib/clipboard'
import { Button } from './ui'

type RunResult = {
  // queued = încă netrimis (dispatch limitat); cancelled = nu s-a rulat (Stop sau guardrail refuzat)
  status: 'queued' | 'running' | 'done' | 'error' | 'cancelled'
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
  // confirm()/alert() native → dialoguri proprii (coadă în ConfirmProvider: se deschid PESTE
  // acest modal, iar focusul se întoarce aici la închidere)
  const { confirm } = useConfirm()
  // doar hosturi cu agent online pot rula (op-ul `run` merge doar prin agent)
  const runnable = useMemo(
    // doar agenţi online, FĂRĂ ţintele efemere (oricum nu sunt agenţi, dar predicatul e explicit)
    () => props.hosts.filter((h) => (!h.connection_type || h.connection_type === 'agent') && h.online && !isEphemeralHost(h)),
    [props.hosts],
  )
  const [phase, setPhase] = useState<'pick' | 'confirm' | 'running'>('pick')
  // NICIUN host preselectat: o comandă pe flotă e o acţiune cu rază mare — „toţi" trebuie să fie
  // o alegere explicită (butonul „Selectează tot (N)"), nu starea implicită peste care dai Enter
  const [selected, setSelected] = useState<Set<number>>(() => new Set())
  const [timeoutSec, setTimeoutSec] = useState(60)          // 1–300, plafonat şi de server
  const stopRef = useRef(false)                             // Stop: nu mai trimitem hosturi noi
  const [stopping, setStopping] = useState(false)
  const [command, setCommand] = useState('')
  // Comenzi fleet SALVATE = snippet-uri (3.5.4), pe server: aceleaşi pe orice dispozitiv şi
  // aceleaşi cu cele din terminal (Alt+S, Toolbox). Un snippet poate purta ţinte pe etichete —
  // alegerea lui preselectează hosturile online care poartă ORICARE dintre ele. Înainte trăiau în
  // localStorage (`wt-fleet-saved`); la prima deschidere le migrăm (lib/snippets).
  const [snips, setSnips] = useState<Snippet[] | null>(null)
  const [snipErr, setSnipErr] = useState('')
  const [savedFilter, setSavedFilter] = useState('')
  const [renaming, setRenaming] = useState<{ id: number; title: string } | null>(null)
  const [migrated, setMigrated] = useState(0)
  // ţintele snippet-ului ales (pentru linia „se potriveşte cu N hosturi")
  const [picked, setPicked] = useState<string[] | null>(null)
  // snippet cu {{parametri}} ales: câmpurile înlocuiesc textarea până când sunt completate
  const [paramTpl, setParamTpl] = useState<{ body: string; values: Record<string, string> } | null>(null)
  const [remember, setRemember] = useState(false)
  const loadSnips = useCallback(async () => {
    try { setSnips(await api<Snippet[]>('/api/snippets')); setSnipErr('') }
    catch (e) { setSnipErr(errText(e, t) || t('fleet.savedLoadFailed')); setSnips((p) => p ?? []) }
  }, [t])
  useEffect(() => {
    let alive = true
    ;(async () => {
      let storage: Storage | null = null
      try { storage = window.localStorage } catch { /* privat / blocat → nimic de migrat */ }
      if (storage) {
        const r = await migrateFleetSaved({
          storage,
          list: () => api<Snippet[]>('/api/snippets'),
          create: (x) => api('/api/snippets', { method: 'POST', body: JSON.stringify(x) }),
        }).catch(() => null)
        if (alive && r?.status === 'done' && r.uploaded) setMigrated(r.uploaded)
      }
      if (alive) await loadSnips()
    })()
    return () => { alive = false }
  }, [loadSnips])

  const [saveName, setSaveName] = useState('')
  const pickSaved = (s: Snippet) => {
    if (snippetParams(s.body).length) setParamTpl({ body: s.body, values: {} })
    else { setParamTpl(null); setCommand(s.body) }
    const tags = snippetTags(s)
    // DOAR ţintele explicite ale snippet-ului preselectează (3.5.3: nimic selectat implicit);
    // un snippet fără ţinte nu atinge selecţia pe care ai făcut-o deja
    if (tags.length) {
      setSelected(new Set(hostsMatchingTags(runnable, tags).map((h) => h.id)))
      setPicked(tags)
    } else setPicked(null)
  }
  const saveCurrent = async () => {
    // cu parametri în curs, salvăm ŞABLONUL ({{x}}), nu o completare parţială
    const cmd = paramTpl ? paramTpl.body : command.trim()
    const name = saveName.trim().slice(0, 60)
    if (!cmd || !name || snips === null) return
    const existing = snips.find((s) => s.title === name)
    // suprascriere NU tăcută: acelaşi nume cu altă comandă cere confirmare
    if (existing && existing.body !== cmd
        && !(await confirm({
          title: t('fleet.overwriteTitle'), message: t('fleet.overwriteConfirm', { name }),
          danger: true, confirmLabel: t('fleet.replace'),
        }))) return
    // bifa e activă doar când hosturile alese AU etichete; altfel nu trimitem `targets` deloc
    // (un `null` ar şterge ţintele existente ale unui snippet suprascris)
    const tags = tagsOfHosts(chosen)
    const targets = remember && tags.length ? { targets: targetsPayload(tags) } : {}
    setSnipErr('')
    try {
      if (existing) {
        await api(`/api/snippets/${existing.id}`, { method: 'PATCH', body: JSON.stringify({ title: name, body: cmd, ...targets }) })
      } else {
        await api('/api/snippets', { method: 'POST', body: JSON.stringify({ title: name, body: cmd, ...targets }) })
      }
      setSaveName('')
      await loadSnips()
    } catch (e) { setSnipErr(errText(e, t) || t('fleet.saveFailed')) }
  }
  const renameSaved = async () => {
    if (!renaming) return
    const s = snips?.find((x) => x.id === renaming.id)
    const title = renaming.title.trim().slice(0, 60)
    if (!s || !title || title === s.title) { setRenaming(null); return }
    try {
      // fără `targets` în corp → serverul păstrează ţintele
      await api(`/api/snippets/${s.id}`, { method: 'PATCH', body: JSON.stringify({ title, body: s.body }) })
      setRenaming(null)
      await loadSnips()
    } catch (e) { setSnipErr(errText(e, t) || t('fleet.saveFailed')) }
  }
  const deleteSaved = async (s: Snippet) => {
    if (!(await confirm({ title: t('snippets.deleteTitle', { title: s.title }),
      message: t('snippets.confirmDelete', { title: s.title }), danger: true }))) return
    try { await api(`/api/snippets/${s.id}`, { method: 'DELETE' }); await loadSnips() }
    catch (e) { setSnipErr(errText(e, t) || t('snippets.deleteFailed')) }
  }
  const [results, setResults] = useState<Record<number, RunResult>>({})
  const [expanded, setExpanded] = useState<number | null>(null)
  const [copied, setCopied] = useState(false)
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  const chosen = runnable.filter((h) => selected.has(h.id))
  const toggle = (id: number) =>
    setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })

  const timeoutOk = Number.isInteger(timeoutSec) && timeoutSec >= 1 && timeoutSec <= 300
  const tplParams = paramTpl ? snippetParams(paramTpl.body) : []
  const paramsMissing = !!paramTpl && tplParams.some((p) => !(paramTpl.values[p] ?? '').trim())
  // comanda efectivă: cu parametri în curs, completarea live a şablonului
  const effective = paramTpl ? fillSnippet(paramTpl.body, paramTpl.values) : command
  const chosenTags = tagsOfHosts(chosen)
  const pickedMatches = picked ? hostsMatchingTags(runnable, picked).length : 0
  const sortedSnips = useMemo(() => sortForFleet(snips ?? []), [snips])
  const fq = savedFilter.trim().toLowerCase()
  const visibleSnips = fq
    ? sortedSnips.filter((s) => s.title.toLowerCase().includes(fq) || s.body.toLowerCase().includes(fq)
      || snippetTags(s).some((x) => x.includes(fq)))
    : sortedSnips

  async function run() {
    // Guardrail: serverul aplică regulile şi pe `/run` — `block` refuză, `confirm` cere un DA
    // explicit. Îl întrebăm pe om AICI, o singură dată pentru toată flota. `confirmed: true` pleacă
    // DOAR dacă omul chiar a confirmat o regulă potrivită — înainte, un fetch eşuat al regulilor
    // cădea pe „nicio regulă" şi trimitea totuşi `confirmed: true`, adică ocolea confirmarea serverului.
    const guard = await api<CommandGuard>('/api/settings/command-guard').catch(() => null)
    const rule = matchCommandRule(command.trim(), guard)
    if (rule?.action === 'block') {
      notifyError(t('fleet.guardBlockedTitle'), t('fleet.guardBlocked', { pattern: rule.pattern }))
      return
    }
    const humanConfirmed = rule ? await confirm({
      title: t('fleet.guardConfirmTitle'), message: t('fleet.guardConfirm', { pattern: rule.pattern }),
      danger: true, confirmLabel: t('fleet.runOnAll'),
    }) : false
    if (rule && !humanConfirmed) return
    // Dacă totuşi serverul răspunde 409 run.guardConfirm (reguli necunoscute aici), întrebăm O
    // SINGURĂ dată pentru toată rularea (ca withGuardConfirm din lib/api.ts) — promisiunea e
    // partajată, deci N hosturi care primesc 409 în paralel nu deschid N dialoguri.
    let lateAnswer: Promise<boolean> | null = humanConfirmed ? Promise.resolve(true) : null
    const askLate = (msg: string) => {
      if (!lateAnswer) {
        const pattern = /\/(.*)\/\s*$/.exec(msg)?.[1] ?? ''
        lateAnswer = confirm({
          title: t('fleet.guardConfirmTitle'), message: t('fleet.guardConfirm', { pattern }),
          danger: true, confirmLabel: t('fleet.runOnAll'),
        })
      }
      return lateAnswer
    }
    // Pre-flight step-up: fiecare host cu require_2fa are nevoie de propria fereastră. Le deblocăm
    // SERIAL aici (un prompt pe rând) ca dispatch-ul de mai jos să nu declanşeze N ceremonii
    // passkey simultan — sau, pe SSO, un redirect de pagină întreagă care ar omorî toată rularea.
    // Un host pentru care userul anulează step-up-ul e marcat „skipped", nu bombardat cu 403-uri.
    const skipped: Record<number, boolean> = {}
    for (const h of chosen.filter((x) => x.require_2fa)) {
      if (!(await ensureStepup(h.id))) skipped[h.id] = true
    }
    const queue = chosen.filter((h) => !skipped[h.id])
    stopRef.current = false
    setStopping(false)
    setPhase('running')
    setResults(Object.fromEntries(chosen.map((h) => [h.id,
      skipped[h.id] ? { status: 'error', error: t('fleet.stepupSkipped') } as RunResult
        : { status: 'queued' } as RunResult])))
    const body = (confirmed: boolean) =>
      JSON.stringify({ command: command.trim(), timeout: timeoutSec, confirmed })
    const runOne = async (h: Host) => {
      setResults((prev) => ({ ...prev, [h.id]: { status: 'running' } }))
      try {
        let r: RunResult
        try {
          r = await api<RunResult>(`/api/hosts/${h.id}/run`, { method: 'POST', body: body(humanConfirmed) })
        } catch (e) {
          if (!(e instanceof ApiError) || e.code !== 'run.guardConfirm') throw e
          if (!(await askLate(e.message))) {
            setResults((prev) => ({ ...prev, [h.id]: { status: 'cancelled', error: t('guard.cancelled') } }))
            return
          }
          r = await api<RunResult>(`/api/hosts/${h.id}/run`, { method: 'POST', body: body(true) })
        }
        setResults((prev) => ({ ...prev, [h.id]: { ...r, status: 'done' } }))
      } catch (e) {
        setResults((prev) => ({ ...prev, [h.id]: { status: 'error', error: errText(e, t) || t('fleet.error') } }))
      }
    }
    // Dispatch cu concurenţă limitată (nu toate deodată): altfel „Stop" n-ar avea ce opri —
    // toate cererile ar fi deja plecate. O cerere trimisă NU poate fi anulată pe server; Stop
    // doar nu mai trimite hosturi noi, iar cele rămase devin „nerulate".
    const LIMIT = 6
    let next = 0
    const worker = async () => {
      while (next < queue.length) {
        const h = queue[next++]
        if (stopRef.current) {
          setResults((prev) => ({ ...prev, [h.id]: { status: 'cancelled', error: t('fleet.notRunStopped') } }))
          continue
        }
        await runOne(h)
      }
    }
    await Promise.all(Array.from({ length: Math.min(LIMIT, queue.length) }, worker))
    setStopping(false)
  }

  const summary = useMemo(() => {
    const vals = Object.values(results)
    return {
      total: vals.length,
      ok: vals.filter((r) => r.status === 'done' && !r.timed_out && r.exit_code === 0).length,
      fail: vals.filter((r) => r.status === 'error' || r.timed_out || (r.status === 'done' && r.exit_code !== 0)).length,
      running: vals.filter((r) => r.status === 'running' || r.status === 'queued').length,
      cancelled: vals.filter((r) => r.status === 'cancelled').length,
    }
  }, [results])

  function reportMarkdown(): string {
    let md = `# ${t('fleet.reportTitle', { count: chosen.length })}\n\n\`\`\`console\n$ ${command.trim()}\n\`\`\`\n\n`
    for (const h of chosen) {
      const r = results[h.id]
      const badge = !r ? '—'
        : r.status === 'error' ? t('fleet.reportError', { error: r.error ?? '' })
        : r.status === 'cancelled' ? (r.error ?? t('fleet.cancelledBadge'))
        : r.status === 'queued' || r.status === 'running' ? t('fleet.running')
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
    // culorile prin clasele semantice theme-aware (tokenii sky/rose/emerald-400 cădeau sub AA pe Aurora)
    if (!r || r.status === 'running') return { dot: 'bg-sky-500 dot-live', badge: t('fleet.running'), cls: 'wt-accent' }
    if (r.status === 'queued') return { dot: 'bg-slate-600', badge: t('fleet.queued'), cls: 'text-slate-400' }
    if (r.status === 'cancelled') return { dot: 'bg-slate-600', badge: t('fleet.cancelledBadge'), cls: 'text-slate-400' }
    if (r.status === 'error') return { dot: 'bg-rose-500', badge: r.error || t('fleet.error'), cls: 'wt-danger' }
    if (r.timed_out) return { dot: 'bg-rose-500', badge: `timeout · ${r.duration}s`, cls: 'wt-danger' }
    const ok = r.exit_code === 0
    return { dot: ok ? 'bg-emerald-500' : 'bg-rose-500', badge: `exit ${r.exit_code} · ${r.duration}s`, cls: ok ? 'wt-good' : 'wt-danger' }
  }
  const oneLine = (r?: RunResult) => {
    if (!r || r.status === 'running') return t('fleet.connecting')
    if (r.status === 'queued') return t('fleet.queuedLine')
    if (r.status === 'error' || r.status === 'cancelled') return r.error || t('fleet.error')
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
              <span className="wt-good"> ✓{summary.ok}</span>
              <span className="wt-danger"> ✕{summary.fail}</span>
              {summary.running > 0 && <span className="wt-accent"> ●{summary.running}</span>}
              {summary.cancelled > 0 && <span className="text-slate-400"> ⊘{summary.cancelled}</span>}
            </span>
          )}
          <button onClick={props.onClose} aria-label={t('fleet.close')}
            className="ml-auto rounded px-2 py-1 text-slate-500 hover:bg-ink-800 hover:text-slate-300">✕</button>
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
                    {chosen.length === runnable.length ? t('fleet.deselectAll') : t('fleet.selectAllN', { n: runnable.length })}
                  </button>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {runnable.map((h) => (
                    <button key={h.id} onClick={() => toggle(h.id)} aria-pressed={selected.has(h.id)}
                      className={`rounded-lg border px-2.5 py-1 font-mono text-[13px] ${
                        selected.has(h.id) ? 'border-sky-500 bg-sky-500/10 wt-accent' : 'border-ink-700 bg-ink-800 text-slate-400 hover:border-ink-600'}`}>
                      {selected.has(h.id) ? '✓ ' : ''}{h.name}
                    </button>
                  ))}
                </div>
                {picked && (
                  <p data-testid="fleet-matches" role="status" className="text-[11px] text-slate-400">
                    {pickedMatches
                      ? t('fleet.matchesHosts', { count: pickedMatches, tags: picked.join(', ') })
                      : t('fleet.matchesNone', { tags: picked.join(', ') })}
                  </p>
                )}
                {/* ── comenzi salvate (= snippet-uri, pe server) ── */}
                <div data-testid="fleet-saved" className="rounded-lg border border-ink-800 p-2">
                  <div className="mb-1 flex flex-wrap items-baseline gap-x-2">
                    <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('fleet.savedTitle')}</span>
                    <span className="text-[10px] text-slate-500">{t('fleet.savedShared')}</span>
                  </div>
                  {migrated > 0 && <p role="status" className="mb-1 text-[11px] wt-good">{t('fleet.migrated', { count: migrated })}</p>}
                  {snips !== null && snips.length > 6 && (
                    <input value={savedFilter} onChange={(e) => setSavedFilter(e.target.value)}
                      placeholder={t('fleet.savedFilter')} aria-label={t('fleet.savedFilter')}
                      className="mb-1 w-full rounded bg-ink-800 px-2 py-0.5 text-[11px] text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                  )}
                  {snips === null ? (
                    <p className="text-[11px] text-slate-500">{t('toolbox.loading')}</p>
                  ) : snips.length === 0 ? (
                    <p className="text-[11px] text-slate-500">{t('fleet.savedEmpty')}</p>
                  ) : (
                    <div className="flex max-h-28 flex-wrap items-center gap-1 overflow-y-auto">
                      {visibleSnips.map((s) => renaming?.id === s.id ? (
                        <span key={s.id} className="inline-flex items-center gap-1">
                          <input autoFocus value={renaming.title} aria-label={t('fleet.renameSaved', { name: s.title })}
                            onChange={(e) => setRenaming({ id: s.id, title: e.target.value })}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') { e.preventDefault(); renameSaved() }
                              // Escape anulează DOAR redenumirea, nu închide consola
                              if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); e.nativeEvent.stopImmediatePropagation(); setRenaming(null) }
                            }}
                            className="w-36 rounded bg-ink-800 px-1.5 py-0.5 text-[11px] text-slate-200 ring-1 ring-sky-500" />
                          <button type="button" onClick={renameSaved} className="min-h-6 px-1 text-[11px] wt-link hover:underline">{t('fleet.renameSave')}</button>
                        </span>
                      ) : (
                        <span key={s.id} className="inline-flex items-center gap-0.5 rounded bg-ink-800 pl-1.5 text-[11px] text-slate-300 ring-1 ring-ink-700">
                          <button type="button" onClick={() => pickSaved(s)} title={s.body}
                            aria-label={t('fleet.pickSaved', { name: s.title })}
                            className="inline-flex min-h-6 items-center gap-1 hover:text-white">
                            <span>{s.title}</span>
                            {snippetParams(s.body).length > 0 && (
                              <span aria-hidden="true" className="font-mono text-[10px] text-slate-500">{'{…}'}</span>
                            )}
                          </button>
                          <SnippetTags tags={snippetTags(s)} />
                          <button type="button" onClick={() => setRenaming({ id: s.id, title: s.title })}
                            aria-label={t('fleet.renameSaved', { name: s.title })} title={t('fleet.renameSaved', { name: s.title })}
                            className="grid h-6 w-6 place-items-center rounded text-slate-500 hover:bg-ink-700 hover:text-slate-200">✎</button>
                          <button type="button" onClick={() => deleteSaved(s)}
                            aria-label={t('fleet.removeSaved', { name: s.title })} title={t('fleet.removeSaved', { name: s.title })}
                            className="grid h-6 w-6 place-items-center rounded text-slate-500 hover:bg-ink-700 hover:wt-danger">×</button>
                        </span>
                      ))}
                      {visibleSnips.length === 0 && (
                        <span className="text-[11px] text-slate-500">{t('snippets.noMatch', { q: savedFilter })}</span>
                      )}
                    </div>
                  )}
                  {snipErr && <p role="alert" className="mt-1 text-[11px] wt-danger">{snipErr}</p>}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('fleet.command')}</label>
                  <input value={saveName} onChange={(e) => setSaveName(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); saveCurrent() } }}
                    placeholder={t('fleet.saveNamePlaceholder')} aria-label={t('fleet.saveName')}
                    className="ml-auto w-40 rounded bg-ink-800 px-2 py-0.5 text-[11px] text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                  <button type="button" onClick={saveCurrent}
                    disabled={!(paramTpl ? paramTpl.body : command.trim()) || !saveName.trim() || snips === null}
                    className="text-[11px] wt-link hover:underline disabled:opacity-40">
                    {t('fleet.saveCurrent')}
                  </button>
                </div>
                <label className={`flex items-center gap-1.5 text-[11px] ${chosenTags.length ? 'text-slate-400' : 'text-slate-600'}`}>
                  <input type="checkbox" checked={remember && chosenTags.length > 0} disabled={!chosenTags.length}
                    onChange={(e) => setRemember(e.target.checked)} />
                  {chosenTags.length ? t('fleet.rememberTags', { tags: chosenTags.join(', ') }) : t('fleet.rememberNoTags')}
                </label>
                {paramTpl ? (
                  <div data-testid="fleet-params" className="space-y-2 rounded-lg bg-ink-800/50 p-2 ring-1 ring-ink-700">
                    <div className="flex items-center">
                      <span className="text-xs font-medium text-slate-400">{t('fleet.paramsTitle')}</span>
                      <button type="button" onClick={() => { setCommand(effective); setParamTpl(null) }}
                        aria-label={t('fleet.paramsDismiss')} title={t('fleet.paramsDismiss')}
                        className="ml-auto rounded px-1.5 text-slate-500 hover:bg-ink-700 hover:text-slate-300">✕</button>
                    </div>
                    {tplParams.map((p, i) => (
                      <label key={p} className="block">
                        <span className="mb-0.5 block font-mono text-[11px] text-slate-400">{p}</span>
                        <input autoFocus={i === 0} value={paramTpl.values[p] ?? ''}
                          onChange={(e) => setParamTpl({ ...paramTpl, values: { ...paramTpl.values, [p]: e.target.value } })}
                          className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                      </label>
                    ))}
                    <div>
                      <span className="mb-0.5 block text-[11px] text-slate-400">{t('snippetparams.finalCommand')}</span>
                      <code className="block max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[#0b0e14] p-2 font-mono text-xs text-emerald-300">{effective}</code>
                    </div>
                    {paramsMissing && <p className="text-[11px] text-slate-500">{t('fleet.paramsMissing')}</p>}
                  </div>
                ) : (
                  <textarea value={command} onChange={(e) => setCommand(e.target.value)} rows={3} autoFocus spellCheck={false}
                    placeholder={t('fleet.commandPlaceholder')} aria-label={t('fleet.command')}
                    className="rounded-lg bg-ink-800 px-3 py-2 font-mono text-sm text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                )}
                <div className="flex flex-wrap items-center gap-2">
                  <label htmlFor="fleet-timeout" className="text-xs text-slate-400">{t('fleet.timeoutLabel')}</label>
                  <input id="fleet-timeout" type="number" min={1} max={300} step={1} inputMode="numeric"
                    value={Number.isNaN(timeoutSec) ? '' : timeoutSec}
                    onChange={(e) => setTimeoutSec(e.target.value === '' ? NaN : Math.trunc(Number(e.target.value)))}
                    aria-invalid={!timeoutOk}
                    className="w-20 rounded bg-ink-800 px-2 py-0.5 font-mono text-xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                  <span className={`text-[11px] ${timeoutOk ? 'text-slate-500' : 'wt-danger'}`}>{t('fleet.timeoutRange')}</span>
                </div>
                <p className="text-xs text-slate-500">{t('fleet.commandHint')}</p>
              </>
            )}
          </div>
        )}

        {/* ── faza „confirmi" (pas deliberat) ── */}
        {phase === 'confirm' && (
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
            <div className="wt-warn flex items-center gap-2 font-medium">⚠ {t('fleet.youRunOn')} {t('fleet.hostCount', { count: chosen.length })}</div>
            <div className="rounded-lg bg-ink-800/60 px-3 py-2 font-mono text-sm text-slate-200">$ {command.trim()}</div>
            <div className="text-xs text-slate-500">{t('fleet.timeoutSummary', { n: timeoutSec })}</div>
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
                    <span aria-hidden="true" className={`h-2.5 w-2.5 shrink-0 rounded-full ${st.dot}`} />
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[13.5px] font-semibold text-slate-200">{h.name}</span>
                      <span className={`block truncate font-mono text-[11.5px] ${r?.status === 'error' || (r?.status === 'done' && r?.exit_code !== 0) ? 'wt-danger opacity-80' : 'text-slate-500'}`}>{oneLine(r)}</span>
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
            <Button variant="primary" disabled={chosen.length === 0 || !effective.trim() || !timeoutOk || paramsMissing}
              onClick={() => {
                // parametrii completaţi devin comanda propriu-zisă (confirmarea + rularea o citesc pe ea)
                if (paramTpl) { setCommand(effective); setParamTpl(null) }
                setPhase('confirm')
              }}>
              {t('fleet.continue')}
            </Button>
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
              {summary.running > 0 && (
                <button disabled={stopping}
                  onClick={() => { stopRef.current = true; setStopping(true) }}
                  className="rounded-lg px-3 py-1.5 text-sm wt-danger ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-60">
                  {stopping ? t('fleet.stopping') : t('fleet.stop')}
                </button>
              )}
              <span role="status" className="ml-auto text-xs text-slate-500">
                {summary.running > 0 ? (stopping ? t('fleet.stoppingHint') : t('fleet.running')) : t('fleet.done')}
              </span>
            </>
          )}
        </footer>
      </div>
    </div>
  )
}
