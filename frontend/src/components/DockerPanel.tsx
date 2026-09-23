import { useCallback, useEffect, useState } from 'react'
import { errText, api, ApiError, Host, withStepup } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { RefreshIcon, TerminalPromptIcon } from './Icons'

// Panou Docker: containere / imagini / volume / reţele ale host-ului, plus start/stop/restart
// şi „shell în container". TOTUL prin op-ul `run` al agentului (docker CLI rulat pe host) —
// niciun op nou în agent, deci fără re-semnare de flotă. Doar host-uri de agent (docker e local).
type Row = Record<string, string>
type Kind = 'containers' | 'images' | 'volumes' | 'networks'
const KINDS: Kind[] = ['containers', 'images', 'volumes', 'networks']

export default function DockerPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean
  /** deschide un tab de terminal cu un shell în containerul dat (docker exec) */
  onOpenContainerShell?: (containerId: string) => void
}) {
  const { t } = useI18n()
  const [kind, setKind] = useState<Kind>('containers')
  const [rows, setRows] = useState<Row[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')          // id-ul containerului pe care rulează o acţiune
  const [logsFor, setLogsFor] = useState<string | null>(null)
  const [logs, setLogs] = useState('')

  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const load = useCallback(async (k: Kind) => {
    setError(''); setRows(null)
    try {
      const r = await api<{ rows: Row[] }>(`/api/hosts/${props.host.id}/docker?kind=${k}`)
      setRows(r.rows)
    } catch (e) {
      // docker.absent / docker.denied vin cu mesaj tradus prin errText; altele generice
      setError(errText(e, t) || (e instanceof ApiError ? e.message : t('docker.error')))
      setRows([])
    }
  }, [props.host.id, t])

  useEffect(() => { load(kind) }, [kind, load])

  async function action(id: string, act: 'start' | 'stop' | 'restart') {
    setBusy(id); setError('')
    try {
      await withStepup(props.host.id, () => api(`/api/hosts/${props.host.id}/docker/action`,
        { method: 'POST', body: JSON.stringify({ container: id, action: act }) }))
      await load(kind)
    } catch (e) {
      setError(errText(e, t) || t('docker.error'))
    } finally { setBusy('') }
  }

  async function showLogs(id: string) {
    setLogsFor(id); setLogs(t('docker.loadingLogs'))
    try {
      const r = await api<{ logs: string }>(`/api/hosts/${props.host.id}/docker/logs?container=${encodeURIComponent(id)}`)
      setLogs(r.logs || t('docker.noLogs'))
    } catch (e) {
      setLogs(errText(e, t) || t('docker.error'))
    }
  }

  // câmpuri utile după kind (docker `{{json .}}` are chei cu majusculă). `State` e sursa de
  // adevăr când există (paused/restarting NU sunt „running"); cădem pe `Status` doar dacă lipseşte
  const isRunning = (r: Row) => r.State ? r.State.toLowerCase() === 'running' : /^up/i.test(r.Status || '')

  const header = (
    <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('docker.title')}</span>
      <button onClick={() => load(kind)} title={t('docker.refresh')} aria-label={t('docker.refresh')}
        className="ml-auto rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"><RefreshIcon /></button>
      <button onClick={props.onClose} aria-label={t('docker.closeAria')}
        className="wt-touch rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300">✕</button>
    </header>
  )

  const tabs = (
    <div className="flex gap-1 border-b border-ink-800 px-2 py-1.5">
      {KINDS.map((k) => (
        <button key={k} onClick={() => setKind(k)}
          className={`rounded px-2 py-1 text-xs font-medium ${kind === k ? 'bg-ink-700 text-slate-100' : 'text-slate-400 hover:bg-ink-800'}`}>
          {t(`docker.tab.${k}`)}
        </button>
      ))}
    </div>
  )

  const body = (
    <>
      {header}
      {tabs}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <div className="px-3 py-2 text-xs wt-warn">{error}</div>}
        {rows === null && <div className="px-3 py-6 text-center text-xs text-slate-500">{t('docker.loading')}</div>}
        {rows && rows.length === 0 && !error && (
          <div className="px-3 py-6 text-center text-xs text-slate-500">{t(`docker.empty.${kind}`)}</div>
        )}

        {/* CONTAINERE: nume, imagine, stare + acţiuni (shell/start/stop/restart/logs) */}
        {kind === 'containers' && rows?.map((r) => {
          const id = r.ID || r.Names || ''
          const running = isRunning(r)
          return (
            <div key={id} className="border-b border-ink-800/60 px-3 py-2">
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 shrink-0 rounded-full ${running ? 'bg-emerald-500' : 'bg-slate-600'}`}
                  title={r.Status || r.State} />
                <span className="min-w-0 flex-1 truncate text-sm text-slate-200" title={r.Names}>{r.Names || id.slice(0, 12)}</span>
                {busy === id && <span className="shrink-0 text-[10px] text-slate-500">…</span>}
              </div>
              <div className="mt-0.5 truncate pl-4 font-mono text-[11px] text-slate-500" title={r.Image}>{r.Image}</div>
              <div className="mt-1 flex flex-wrap gap-1 pl-4">
                {running && props.onOpenContainerShell && (
                  <button onClick={() => props.onOpenContainerShell!(id)}
                    className="inline-flex items-center gap-1 rounded bg-sky-600/15 px-1.5 py-0.5 text-[11px] wt-accent hover:bg-sky-600/25">
                    <TerminalPromptIcon /> {t('docker.shell')}
                  </button>
                )}
                {running
                  ? <button disabled={!!busy} onClick={() => action(id, 'stop')}
                      className="rounded px-1.5 py-0.5 text-[11px] text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40">{t('docker.stop')}</button>
                  : <button disabled={!!busy} onClick={() => action(id, 'start')}
                      className="rounded px-1.5 py-0.5 text-[11px] wt-good ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40">{t('docker.start')}</button>}
                {running && <button disabled={!!busy} onClick={() => action(id, 'restart')}
                  className="rounded px-1.5 py-0.5 text-[11px] text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40">{t('docker.restart')}</button>}
                <button onClick={() => showLogs(id)}
                  className="rounded px-1.5 py-0.5 text-[11px] text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800">{t('docker.logs')}</button>
              </div>
            </div>
          )
        })}

        {/* IMAGINI / VOLUME / REŢELE: doar citire, două linii per rând */}
        {kind !== 'containers' && rows?.map((r, i) => (
          <div key={i} className="border-b border-ink-800/60 px-3 py-2">
            <div className="truncate text-sm text-slate-200">
              {kind === 'images' ? `${r.Repository}:${r.Tag}` : (r.Name || r.Driver)}
            </div>
            <div className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
              {kind === 'images' ? `${r.ID?.slice(0, 12)} · ${r.Size}`
                : kind === 'volumes' ? `${r.Driver} · ${r.Mountpoint || ''}`
                : `${r.Driver} · ${r.Scope}`}
            </div>
          </div>
        ))}
      </div>
    </>
  )

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} />
      <aside className={asideCls} aria-label={t('docker.title')}>
        {body}
      </aside>

      {/* logs: overlay simplu peste panou */}
      {logsFor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setLogsFor(null)}>
          <div className="glass flex max-h-[80vh] w-full max-w-3xl flex-col rounded-2xl" onClick={(e) => e.stopPropagation()}>
            <header className="flex items-center gap-2 border-b border-ink-800 px-4 py-2">
              <span className="min-w-0 flex-1 truncate text-sm font-semibold">{t('docker.logsFor', { name: logsFor })}</span>
              <button onClick={() => setLogsFor(null)} aria-label={t('docker.closeAria')}
                className="rounded px-1.5 text-slate-400 hover:bg-ink-800">✕</button>
            </header>
            <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-4 py-3 font-mono text-[11px] leading-relaxed text-slate-300">{logs}</pre>
          </div>
        </div>
      )}
    </>
  )
}
