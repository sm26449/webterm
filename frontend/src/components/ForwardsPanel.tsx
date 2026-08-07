import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, Host, PortForward, withStepup } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { LinkIcon, PencilIcon, PlusIcon, RefreshIcon, TrashIcon } from './Icons'

type ProbeState = 'checking' | 'up' | 'down'

export default function ForwardsPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean
  /** deschide într-un tab de terminal o sesiune telnet-bastion (după sid) */
  onOpenSession?: (sid: string) => void
}) {
  const { t } = useI18n()
  const isAgent = !props.host.connection_type || props.host.connection_type === 'agent'
  const [forwards, setForwards] = useState<PortForward[] | null>(null)
  const [error, setError] = useState('')
  const [probes, setProbes] = useState<Record<number, ProbeState>>({})
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<PortForward | null>(null)
  const [confirmDel, setConfirmDel] = useState<PortForward | null>(null)
  const [copied, setCopied] = useState<number | null>(null)
  // formular de adăugare
  const [fLabel, setFLabel] = useState('')
  const [fHost, setFHost] = useState('127.0.0.1')
  const [fPort, setFPort] = useState('')
  const [fScheme, setFScheme] = useState<'http' | 'https' | 'telnet'>('http')
  const [fDesc, setFDesc] = useState('')
  const [busy, setBusy] = useState(false)
  const [opening, setOpening] = useState<number | null>(null)
  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const probe = useCallback(async (f: PortForward) => {
    setProbes((p) => ({ ...p, [f.id]: 'checking' }))
    try {
      const r = await api<{ reachable: boolean }>(`/api/forwards/${f.id}/probe`)
      setProbes((p) => ({ ...p, [f.id]: r.reachable ? 'up' : 'down' }))
    } catch {
      setProbes((p) => ({ ...p, [f.id]: 'down' }))
    }
  }, [])

  const load = useCallback(async () => {
    setError('')
    try {
      const list = await api<PortForward[]>(`/api/hosts/${props.host.id}/forwards`)
      setForwards(list)
      list.filter((f) => f.enabled).forEach(probe)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('forwards.error.generic'))
    }
  }, [props.host.id, probe])

  useEffect(() => { load() }, [load])

  function resetForm() {
    setFLabel(''); setFPort(''); setFDesc(''); setFHost('127.0.0.1'); setFScheme('http')
  }
  function openAdd() {
    setEditing(null); resetForm(); setAdding(true); setError('')
  }
  function openEdit(f: PortForward) {
    setAdding(false); setEditing(f); setError('')
    setFLabel(f.label); setFHost(f.target_host); setFPort(String(f.target_port))
    setFScheme(f.scheme === 'https' || f.scheme === 'telnet' ? f.scheme : 'http'); setFDesc(f.description || '')
  }
  function closeForm() {
    setAdding(false); setEditing(null); resetForm(); setError('')
  }

  async function submitForward() {
    const port = parseInt(fPort, 10)
    if (!fLabel.trim() || !(port >= 1 && port <= 65535)) {
      setError(t('forwards.error.invalidInput'))
      return
    }
    setBusy(true)
    try {
      const payload = {
        label: fLabel.trim(), target_host: fHost.trim() || '127.0.0.1',
        target_port: port, scheme: fScheme, description: fDesc.trim(),
      }
      if (editing) {
        // rutele /api/forwards/{id} n-au host_id în URL, deci reîncercarea automată de la
        // un 403 de step-up nu ştie pe ce host să deschidă fereastra — de-aia `withStepup`
        await withStepup(props.host.id, () =>
          api(`/api/forwards/${editing.id}`, { method: 'PATCH', body: JSON.stringify(payload) }))
      } else {
        await api(`/api/hosts/${props.host.id}/forwards`, {
          method: 'POST', body: JSON.stringify({ ...payload, enabled: true }),
        })
      }
      closeForm()
      load()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('forwards.error.generic'))
    } finally {
      setBusy(false)
    }
  }

  async function openTelnet(f: PortForward) {
    setOpening(f.id); setError('')
    try {
      // host cu 2FA fără fereastră deschisă → 403 → ceremonia de step-up + reîncercare (H1)
      const r = await withStepup(f.host_id, () =>
        api<{ id: string }>(`/api/forwards/${f.id}/telnet`, { method: 'POST', body: JSON.stringify({}) }))
      props.onOpenSession?.(r.id)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('forwards.error.telnetOpen'))
    } finally {
      setOpening(null)
    }
  }

  async function toggle(f: PortForward) {
    try {
      await withStepup(props.host.id, () =>
        api(`/api/forwards/${f.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !f.enabled }) }))
      load()
    } catch (e) { setError(e instanceof ApiError ? e.message : t('forwards.error.generic')) }
  }

  async function remove(f: PortForward) {
    setConfirmDel(null)
    try {
      await withStepup(props.host.id, () => api(`/api/forwards/${f.id}`, { method: 'DELETE' }))
      load()
    } catch (e) { setError(e instanceof ApiError ? e.message : t('forwards.error.generic')) }
  }

  function copyLink(f: PortForward) {
    navigator.clipboard.writeText(f.url).then(() => {
      setCopied(f.id); setTimeout(() => setCopied((c) => (c === f.id ? null : c)), 1500)
    }).catch(() => {})
  }

  const header = (
    <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('forwards.title')}</span>
      <button onClick={props.onClose} aria-label={t('forwards.closeAria')}
        className="wt-touch ml-auto rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300">✕</button>
    </header>
  )

  const dotColor = (f: PortForward): string => {
    if (!f.enabled) return 'bg-slate-600'
    const s = probes[f.id]
    return s === 'up' ? 'bg-emerald-500' : s === 'down' ? 'bg-rose-500' : 'bg-amber-500'
  }
  const dotTitle = (f: PortForward): string => {
    if (!f.enabled) return t('forwards.probe.off')
    const s = probes[f.id]
    return s === 'up' ? t('forwards.probe.up') : s === 'down' ? t('forwards.probe.down') : t('forwards.probe.checking')
  }

  // adresa publică e <slug>.<domeniu>; slug-ul se derivă din nume ca pe server
  // (minuscule, non-alfanumerice → „-”). Domeniul de forward = gazda aplicației.
  const slugify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40)
  const previewSlug = editing ? editing.slug : (slugify(fLabel) || 'fwd')
  const previewHost = `${previewSlug}.${window.location.hostname}`
  const urlHost = (f: PortForward) => f.url.replace(/^https?:\/\//, '')

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      <aside aria-label={t('forwards.panelAria')} className={asideCls}>
        {header}

        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1.5">
          <button onClick={() => (adding ? closeForm() : openAdd())}
            className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[12px] font-medium text-sky-400 hover:bg-ink-800">
            <PlusIcon /> {t('forwards.add')}
          </button>
          <button onClick={load} title={t('forwards.refresh')} className="wt-touch ml-auto rounded px-1.5 text-slate-400 hover:bg-ink-800"><RefreshIcon /></button>
        </div>

        {(adding || editing) && (
          <div className="flex flex-col gap-2 border-b border-ink-800 bg-ink-800/40 px-3 py-3 text-[12px]">
            <input autoFocus value={fLabel} onChange={(e) => setFLabel(e.target.value)} placeholder={t('forwards.namePlaceholder')}
              className="rounded bg-ink-800 px-2 py-1 text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
            {fScheme === 'telnet' ? (
              <div className="text-[11px] leading-snug text-slate-500">
                {t('forwards.telnetInfo.pre')} <span className="text-slate-300">{t('forwards.telnetInfo.emphasis')}</span>{t('forwards.telnetInfo.post')}
              </div>
            ) : (
              <div className="text-[11px] leading-snug text-slate-500">
                {t('forwards.addressLabel')} <span className="font-mono wt-link break-all">{previewHost}</span>
                {editing
                  ? <span className="text-slate-600"> · {t('forwards.addressFixed')}</span>
                  : <span className="text-slate-600"> · {t('forwards.addressGenerated')}</span>}
              </div>
            )}
            <div className="flex gap-2">
              <input value={fHost} onChange={(e) => setFHost(e.target.value)} placeholder="127.0.0.1"
                className="min-w-0 flex-1 rounded bg-ink-800 px-2 py-1 font-mono text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
              <input value={fPort} onChange={(e) => setFPort(e.target.value.replace(/\D/g, ''))} placeholder={t('forwards.portPlaceholder')} inputMode="numeric"
                className="w-16 rounded bg-ink-800 px-2 py-1 font-mono text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
              <select value={fScheme} aria-label={t('forwards.scheme')} onChange={(e) => {
                const v = e.target.value as 'http' | 'https' | 'telnet'
                setFScheme(v)
                if (v === 'telnet' && !fPort) setFPort('23')
              }}
                className="rounded bg-ink-800 px-1 py-1 text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500">
                <option value="http">http</option><option value="https">https</option>
                {isAgent && <option value="telnet">telnet</option>}
              </select>
            </div>
            <input value={fDesc} onChange={(e) => setFDesc(e.target.value)} placeholder={t('forwards.descPlaceholder')}
              className="rounded bg-ink-800 px-2 py-1 text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
            <div className="flex gap-2">
              <button onClick={submitForward} disabled={busy} className="rounded-lg bg-sky-600 px-3 py-1 font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                {busy ? t('forwards.saving') : editing ? t('forwards.save') : t('forwards.addShort')}
              </button>
              <button onClick={closeForm} className="rounded-lg px-3 py-1 text-slate-400 hover:bg-ink-800">{t('forwards.cancel')}</button>
            </div>
          </div>
        )}

        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}

        {!isAgent && (
          <div className="border-b border-ink-800 bg-ink-800/40 px-3 py-2 text-[11px] leading-relaxed text-slate-400">
            {t('forwards.sshInfo')}{' '}
            {props.host.require_2fa
              ? t('forwards.sshInfo2fa')
              : t('forwards.sshInfoStored')}
          </div>
        )}

        <div className="min-h-0 flex-1 overflow-y-auto">
          {forwards && forwards.length === 0 && !adding && !editing && (
            <div className="flex flex-col items-center gap-2 px-4 py-8 text-center text-[12px] text-slate-500">
              <p>{t('forwards.empty')}</p>
              <button onClick={openAdd} className="rounded-lg bg-sky-600 px-3 py-1.5 text-white hover:bg-sky-700">{t('forwards.addFirst')}</button>
            </div>
          )}
          {forwards?.map((f) => {
            const isTelnet = f.scheme === 'telnet'
            return (
            <div key={f.id} className="group flex items-start gap-2.5 border-b border-ink-800/60 px-3 py-2.5">
              <button onClick={() => (isTelnet || f.enabled) && probe(f)} title={isTelnet ? t('forwards.checkAccess') : dotTitle(f)}
                className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${isTelnet ? (probes[f.id] === 'up' ? 'bg-emerald-500' : probes[f.id] === 'down' ? 'bg-rose-500' : 'bg-slate-600') : dotColor(f)}`}
                aria-label={dotTitle(f)} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13.5px] font-semibold text-slate-200">{f.label}</div>
                {isTelnet
                  ? <div className="truncate text-[11.5px] text-slate-500">{t('forwards.telnetSubtitle')}</div>
                  : <div className="truncate font-mono text-[11.5px] wt-link" title={f.url}>{urlHost(f)}</div>}
                <div className="truncate font-mono text-[11px] text-slate-500">→ {f.target_host}:{f.target_port} · {f.scheme}</div>
                {f.description && <div className="mt-0.5 truncate text-[11.5px] text-slate-500">{f.description}</div>}
              </div>
              <div className="flex shrink-0 items-center gap-0.5">
                {isTelnet ? (
                  <button onClick={() => openTelnet(f)} disabled={opening === f.id} title={t('forwards.openInTerminal')}
                    className="rounded px-1.5 py-0.5 text-[11px] font-medium wt-link hover:bg-ink-800 disabled:opacity-50">
                    {opening === f.id ? t('forwards.opening') : t('forwards.open')}
                  </button>
                ) : (<>
                  {f.enabled ? (
                    <a href={f.url} target="_blank" rel="noopener noreferrer" title={t('forwards.openNewTab')}
                      className="rounded px-1.5 py-0.5 text-[11px] font-medium wt-link hover:bg-ink-800">{t('forwards.open')}</a>
                  ) : (
                    <button onClick={() => toggle(f)} title={t('forwards.startTitle')} className="rounded px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-ink-800">{t('forwards.start')}</button>
                  )}
                  <button onClick={() => copyLink(f)} title={t('forwards.copyLink')} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200">
                    {copied === f.id ? <span className="text-[11px] wt-good">✓</span> : <LinkIcon />}
                  </button>
                  {f.enabled && <button onClick={() => toggle(f)} title={t('forwards.stop')} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-amber-300 text-[11px]">⏸</button>}
                </>)}
                <button onClick={() => openEdit(f)} title={t('forwards.edit')} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200"><PencilIcon /></button>
                <button onClick={() => setConfirmDel(f)} title={t('forwards.delete')} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-rose-300"><TrashIcon /></button>
              </div>
            </div>
            )
          })}
        </div>

        {confirmDel && (
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-[11px]">
            <p className="mb-1.5 text-slate-300">{t('forwards.confirmDelPre')} <span className="font-mono wt-danger">{confirmDel.label}</span>?</p>
            <div className="flex gap-2">
              <button onClick={() => remove(confirmDel)} className="rounded bg-rose-600 px-2 py-0.5 font-medium text-white hover:bg-rose-700">{t('forwards.delete')}</button>
              <button onClick={() => setConfirmDel(null)} className="rounded px-2 py-0.5 text-slate-400 hover:bg-ink-700">{t('forwards.cancel')}</button>
            </div>
          </div>
        )}
      </aside>
    </>
  )
}
