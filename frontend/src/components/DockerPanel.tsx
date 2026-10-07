import { ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, Host, withGuardConfirm, withStepup } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { copyText } from '../lib/clipboard'
import { SHEET_CLS } from '../lib/sheet'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { useFocusTrap } from '../lib/useFocusTrap'
import { CloseIcon, RefreshIcon, TerminalPromptIcon } from './Icons'

// Panou Docker: containere / imagini / volume / reţele ale host-ului, plus start/stop/restart
// şi „shell în container". TOTUL prin op-ul `run` al agentului (docker CLI rulat pe host) —
// niciun op nou în agent, deci fără re-semnare de flotă. Doar host-uri de agent (docker e local).
type Row = Record<string, string>
type Kind = 'containers' | 'images' | 'volumes' | 'networks'
const KINDS: Kind[] = ['containers', 'images', 'volumes', 'networks']

// Overlay-ul de log-uri ca dialog REAL: focus-trap + Escape + rol/etichetă. Înainte era un div
// peste panou fără niciuna — Tab ieşea în pagina de sub el, Escape nu-l închidea (audit a11y).
function LogsDialog(props: { onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={props.onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="wt-docker-logs-title"
        className="glass flex max-h-[80vh] w-full max-w-3xl flex-col rounded-2xl" onClick={(e) => e.stopPropagation()}>
        {props.children}
      </div>
    </div>
  )
}

export default function DockerPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean; embed?: boolean
  /** deschide un tab de terminal cu un shell în containerul dat (docker exec) */
  onOpenContainerShell?: (containerId: string) => void
}) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const asideRef = useRef<HTMLElement>(null)
  const drawer = useDrawer(asideRef, props.onClose, !props.embed)
  const [kind, setKind] = useState<Kind>('containers')
  const [rows, setRows] = useState<Row[] | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')   // notă neutră (guardrail anulat) — nu eroare
  const [denied, setDenied] = useState(false)   // userul agentului nu e în grupul docker → card de remediere
  const [copied, setCopied] = useState('')      // care din comenzile de remediere tocmai s-a copiat
  const [busy, setBusy] = useState('')          // id-ul containerului pe care rulează o acţiune
  const [logsFor, setLogsFor] = useState<string | null>(null)
  const [logs, setLogs] = useState('')

  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const load = useCallback(async (k: Kind) => {
    setError(''); setDenied(false); setRows(null)
    try {
      const r = await api<{ rows: Row[] }>(`/api/hosts/${props.host.id}/docker?kind=${k}`)
      setRows(r.rows)
    } catch (e) {
      // docker.denied → card de remediere dedicat (comanda de fix); restul → mesaj simplu
      if (e instanceof ApiError && e.code === 'docker.denied') setDenied(true)
      else setError(errText(e, t) || (e instanceof ApiError ? e.message : t('docker.error')))
      setRows([])
    }
  }, [props.host.id, t])

  // Ambele remedii fac userul agentului root-echivalent pe host (socketul docker = root) — cardul
  // o spune explicit, nu o ascunde după „Copy" (audit 2026-10-04, LOW #8; vezi THREAT-MODEL).
  // Regula sudoers îngustă e prima: explicită, jurnalizată de sudo şi merge imediat prin
  // fallback-ul `sudo -n` al gateway-ului (fără restart de agent / re-login pentru noul grup).
  const agentUser = props.host.agent_user || '$(whoami)'
  const sudoersCmd = `echo "${agentUser} ALL=(root) NOPASSWD: /usr/bin/docker" | sudo tee /etc/sudoers.d/${agentUser}-docker >/dev/null && sudo chmod 440 /etc/sudoers.d/${agentUser}-docker`
  const groupCmd = `sudo usermod -aG docker ${agentUser}`
  const cmdRow = (id: string, cmd: string) => (
    <div className="flex items-center gap-2 rounded-md bg-ink-900/70 px-3 py-2 ring-1 ring-ink-700">
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs text-slate-200">{cmd}</code>
      <button onClick={() => copyText(cmd).then((ok) => { if (ok) { setCopied(id); setTimeout(() => setCopied(''), 1500) } })}
        className="shrink-0 rounded-md px-2 py-0.5 text-2xs wt-link hover:bg-ink-800">
        {copied === id ? t('docker.denied.copied') : t('docker.denied.copy')}
      </button>
    </div>
  )

  useEffect(() => { load(kind) }, [kind, load])

  async function action(id: string, act: 'start' | 'stop' | 'restart', name?: string) {
    // stop/restart opresc un container VIU (şi ce rulează în el) — confirmare care numeşte
    // containerul, buton roşu, focus pe Anulează (audit 2026-10-04 §10). Start rămâne direct.
    if (act !== 'start' && !(await confirm({
      title: `${t('docker.' + act)} ${name || id.slice(0, 12)}`,
      message: t(act === 'stop' ? 'docker.confirmStop' : 'docker.confirmRestart', { name: name || id.slice(0, 12) }),
      confirmLabel: t('docker.' + act), danger: true,
    }))) return
    setBusy(id); setError(''); setNote('')
    try {
      // null = omul a refuzat confirmarea guardrail-ului: nimic nu s-a rulat — notă neutră,
      // nu tăcere (înainte panoul nu spunea nimic, ca şi cum acţiunea ar fi mers)
      const r = await withStepup(props.host.id, () => withGuardConfirm((pattern) => confirm({ title: t('guard.confirmTitle'), message: t('guard.confirmMsg', { pattern }), danger: true, confirmLabel: t('guard.confirmRun') }),
        (confirmed) => api(`/api/hosts/${props.host.id}/docker/action`,
          { method: 'POST', body: JSON.stringify({ container: id, action: act, confirmed }) })))
      if (r === null) { setNote(t('guard.cancelled')); return }
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
        className="wt-touch ml-auto rounded-md px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"><RefreshIcon /></button>
      {!props.embed && (
        <button onClick={props.onClose} aria-label={t('docker.closeAria')}
          className="wt-touch rounded-md px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"><CloseIcon size={14} /></button>
      )}
    </header>
  )

  const tabs = (
    <div className="flex gap-1 border-b border-ink-800 px-2 py-1.5">
      {KINDS.map((k) => (
        <button key={k} onClick={() => setKind(k)}
          className={`rounded-md px-2 py-1 text-xs font-medium ${kind === k ? 'bg-ink-700 text-slate-100' : 'text-slate-400 hover:bg-ink-800'}`}>
          {t(`docker.tab.${k}`)}
        </button>
      ))}
    </div>
  )

  const body = (
    <>
      {header}
      {tabs}
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {error && <div className="mb-2 rounded-md bg-ink-800 px-3 py-2 text-xs wt-warn">{error}</div>}
        {note && !error && <div role="status" className="mb-2 rounded-md bg-ink-800/60 px-3 py-2 text-xs text-slate-400">{note}</div>}

        {/* userul agentului nu e în grupul docker → remediere clară, nu un mesaj mort.
            (gateway-ul a încercat deja `sudo -n` transparent; dacă vezi asta, nu e nici în grup
            nici cu sudo passwordless, deci o reparăm pe host.) Avertismentul vine ÎNAINTEA
            comenzilor: orice variantă dă userului root pe host. */}
        {denied && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
            <div className="mb-1 text-sm font-semibold wt-warn">{t('docker.denied.title')}</div>
            <p className="mb-2 text-xs leading-relaxed text-slate-400">{t('docker.denied.body')}</p>
            <p className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs leading-relaxed wt-warn">{t('docker.denied.warn')}</p>
            <p className="mb-1 text-2xs text-slate-400">{t('docker.denied.optSudo')}</p>
            {cmdRow('sudo', sudoersCmd)}
            <p className="mb-1 mt-3 text-2xs text-slate-400">{t('docker.denied.optGroup')}</p>
            {cmdRow('group', groupCmd)}
            <p className="mt-2 text-2xs text-slate-500">{t('docker.denied.after')}</p>
            <button onClick={() => load(kind)} className="mt-3 rounded-md px-3 py-1.5 text-xs text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
              {t('docker.denied.retry')}
            </button>
          </div>
        )}
        {rows === null && !denied && <div className="px-3 py-6 text-center text-xs text-slate-500">{t('docker.loading')}</div>}
        {rows && rows.length === 0 && !error && !denied && (
          <div className="px-3 py-6 text-center text-xs text-slate-500">{t(`docker.empty.${kind}`)}</div>
        )}

        {rows && rows.length > 0 && (
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))' }}>
            {/* CONTAINERE: card cu stare, imagine + acţiuni (shell/start/stop/restart/logs) */}
            {kind === 'containers' && rows.map((r) => {
              const id = r.ID || r.Names || ''
              const running = isRunning(r)
              const name = r.Names || id.slice(0, 12)
              // starea e şi TEXT (State-ul docker: running/exited/paused…), nu doar o bulină verde/gri
              // — culoarea singură nu trece WCAG 1.4.1 şi nu ajunge la cititorul de ecran
              const state = (r.State || (running ? 'running' : 'stopped')).toLowerCase()
              return (
                <div key={id} className="flex flex-col gap-2 rounded-xl border border-ink-700/70 bg-ink-800/40 p-3">
                  <div className="flex items-start gap-2">
                    <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${running ? 'bg-emerald-500' : 'bg-slate-600'}`} aria-hidden="true" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium text-slate-200" title={r.Names}>{name}</div>
                      <div className="truncate font-mono text-2xs text-slate-500" title={r.Image}>{r.Image}</div>
                      <div className={`font-mono text-2xs ${running ? 'wt-good' : 'text-slate-500'}`} title={r.Status}>{state}</div>
                    </div>
                    {busy === id && <span className="shrink-0 text-2xs text-slate-500">…</span>}
                  </div>
                  <div className="mt-auto flex flex-wrap items-center gap-1 border-t border-ink-800/60 pt-2">
                    {running && props.onOpenContainerShell && (
                      <button onClick={() => props.onOpenContainerShell!(id)}
                        className="inline-flex items-center gap-1 rounded-md bg-sky-600/15 px-1.5 py-0.5 text-2xs wt-accent hover:bg-sky-600/25">
                        <TerminalPromptIcon /> {t('docker.shell')}
                      </button>
                    )}
                    {running
                      ? <button disabled={!!busy} onClick={() => action(id, 'stop', name)}
                          className="rounded-md px-1.5 py-0.5 text-2xs text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40">{t('docker.stop')}</button>
                      : <button disabled={!!busy} onClick={() => action(id, 'start', name)}
                          className="rounded-md px-1.5 py-0.5 text-2xs wt-good ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40">{t('docker.start')}</button>}
                    {running && <button disabled={!!busy} onClick={() => action(id, 'restart', name)}
                      className="rounded-md px-1.5 py-0.5 text-2xs text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40">{t('docker.restart')}</button>}
                    <button onClick={() => showLogs(id)}
                      className="ml-auto rounded-md px-1.5 py-0.5 text-2xs text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800">{t('docker.logs')}</button>
                  </div>
                </div>
              )
            })}

            {/* IMAGINI / VOLUME / REŢELE: carduri read-only, două linii */}
            {kind !== 'containers' && rows.map((r, i) => (
              <div key={i} className="rounded-xl border border-ink-700/70 bg-ink-800/40 p-3">
                <div className="truncate text-sm text-slate-200">
                  {kind === 'images' ? `${r.Repository}:${r.Tag}` : (r.Name || r.Driver)}
                </div>
                <div className="mt-0.5 truncate font-mono text-2xs text-slate-500">
                  {kind === 'images' ? `${r.ID?.slice(0, 12)} · ${r.Size}`
                    : kind === 'volumes' ? `${r.Driver} · ${r.Mountpoint || ''}`
                    : `${r.Driver} · ${r.Scope}`}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  )

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} />
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
      <aside ref={asideRef} className={asideCls} aria-label={t('docker.title')} onKeyDown={drawer.onKeyDown}>
        {drawer.sheet && <SheetBar title={t('docker.title')} onBack={props.onClose} />}
        {body}
      </aside>

      {/* logs: dialog modal peste panou (focus-trap, Escape, etichetat de titlu) */}
      {logsFor && (
        <LogsDialog onClose={() => setLogsFor(null)}>
          <header className="flex items-center gap-2 border-b border-ink-800 px-4 py-2">
            <h2 id="wt-docker-logs-title" className="min-w-0 flex-1 truncate text-sm font-semibold">{t('docker.logsFor', { name: logsFor })}</h2>
            <button onClick={() => setLogsFor(null)} aria-label={t('common.close')}
              className="wt-touch rounded-md px-1.5 text-slate-400 hover:bg-ink-800"><CloseIcon size={14} /></button>
          </header>
          {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- regiune derulabilă: fără tabindex nu se poate derula din tastatură */}
          <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-4 py-3 font-mono text-2xs leading-relaxed text-slate-300" tabIndex={0}>{logs}</pre>
        </LogsDialog>
      )}
    </>
  )
}
