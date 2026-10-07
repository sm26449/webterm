import { useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, Host, PortForward, withStepup } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS } from '../lib/sheet'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { CheckIcon, CloseIcon, LinkIcon, PauseIcon, PencilIcon, PlusIcon, RefreshIcon, StarIcon, TrashIcon } from './Icons'
import { copyText } from '../lib/clipboard'
import HelpTip from './HelpTip'
import { Button } from './ui'

type ProbeState = 'checking' | 'up' | 'down'

export default function ForwardsPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean; embed?: boolean
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
  const [fApp, setFApp] = useState('')     // tip aplicaţie (wizard): '' = forward simplu
  const [busy, setBusy] = useState(false)
  const [opening, setOpening] = useState<number | null>(null)
  const asideRef = useRef<HTMLElement>(null)
  const drawer = useDrawer(asideRef, props.onClose, !props.embed)
  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

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
      // listarea e gardată de step-up pe host 2FA (F-06): fără `withStepup` panoul rămânea
      // pe un 403 sec în loc să ceară passkey-ul
      const list = await withStepup(props.host.id, () =>
        api<PortForward[]>(`/api/hosts/${props.host.id}/forwards`))
      setForwards(list)
      list.filter((f) => f.enabled).forEach(probe)
    } catch (e) {
      setError(errText(e, t) || t('forwards.error.generic'))
    }
  }, [props.host.id, probe, t])

  useEffect(() => { load() }, [load])

  function resetForm() {
    setFLabel(''); setFPort(''); setFDesc(''); setFHost('127.0.0.1'); setFScheme('http'); setFApp('')
  }
  function openAdd() {
    setEditing(null); resetForm(); setAdding(true); setError('')
  }
  // wizard: presetează formularul pentru o aplicaţie cunoscută (port + scheme + nume + tip)
  const APP_PRESETS: Record<string, { port: string; scheme: 'https' | 'http'; label: string }> = {
    proxmox:   { port: '8006', scheme: 'https', label: 'Proxmox' },
    portainer: { port: '9443', scheme: 'https', label: 'Portainer' },
    grafana:   { port: '3000', scheme: 'http',  label: 'Grafana' },
    // console web de baze de date (porturi implicite tipice — editabile în formular)
    adminer:        { port: '8080', scheme: 'http', label: 'Adminer' },
    pgadmin:        { port: '5050', scheme: 'http', label: 'pgAdmin' },
    phpmyadmin:     { port: '8080', scheme: 'http', label: 'phpMyAdmin' },
    'mongo-express':{ port: '8081', scheme: 'http', label: 'Mongo Express' },
    kibana:         { port: '5601', scheme: 'http', label: 'Kibana' },
    clickhouse:     { port: '8123', scheme: 'http', label: 'ClickHouse' },
  }
  // preseturile de DB, într-o listă (butoane generate) ca să nu aglomerăm markup-ul
  const DB_APPS: { type: string; color: string }[] = [
    { type: 'adminer', color: '#7dd3fc' }, { type: 'pgadmin', color: '#4f83cc' },
    { type: 'phpmyadmin', color: '#e0a83c' }, { type: 'mongo-express', color: '#4bd494' },
    { type: 'kibana', color: '#f04e98' }, { type: 'clickhouse', color: '#f0cf5a' },
  ]
  function presetApp(type: string) {
    setEditing(null); resetForm(); setError('')
    const p = APP_PRESETS[type]
    if (p) { setFPort(p.port); setFScheme(p.scheme); setFLabel(`${p.label} — ${props.host.name}`) }
    setFApp(type)
    setFHost('127.0.0.1')
    setAdding(true)
  }
  function openEdit(f: PortForward) {
    setAdding(false); setEditing(f); setError('')
    setFLabel(f.label); setFHost(f.target_host); setFPort(String(f.target_port))
    setFScheme(f.scheme === 'https' || f.scheme === 'telnet' ? f.scheme : 'http'); setFDesc(f.description || '')
    setFApp(f.app_type || '')
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
        target_port: port, scheme: fScheme, description: fDesc.trim(), app_type: fApp,
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
      setError(errText(e, t) || t('forwards.error.generic'))
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
      setError(errText(e, t) || t('forwards.error.telnetOpen'))
    } finally {
      setOpening(null)
    }
  }

  async function toggle(f: PortForward) {
    try {
      await withStepup(props.host.id, () =>
        api(`/api/forwards/${f.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !f.enabled }) }))
      load()
    } catch (e) { setError(errText(e, t) || t('forwards.error.generic')) }
  }

  async function remove(f: PortForward) {
    setConfirmDel(null)
    try {
      await withStepup(props.host.id, () => api(`/api/forwards/${f.id}`, { method: 'DELETE' }))
      load()
    } catch (e) { setError(errText(e, t) || t('forwards.error.generic')) }
  }

  // promovează / retrage statutul de „app" (bookmark) al unui forward existent — un forward
  // simplu devine dală pe dashboard, sau invers. Doar metadată (app_type), nimic de re-ţintit.
  // la demote ţinem minte tipul (proxmox/portainer/…): un ★ scos din greşeală şi repus
  // nu retrogradează tile-ul la „custom" (culoare/glif pierdute). Doar în sesiunea curentă.
  const demotedType = useRef<Record<number, string>>({})
  async function togglePromote(f: PortForward) {
    try {
      if (f.app_type) demotedType.current[f.id] = f.app_type
      const next = f.app_type ? '' : demotedType.current[f.id] || 'custom'
      await withStepup(f.host_id, () => api(`/api/forwards/${f.id}`,
        { method: 'PATCH', body: JSON.stringify({ app_type: next }) }))
      load()
    } catch (e) { setError(errText(e, t) || t('forwards.error.generic')) }
  }
  const APP_COLOR: Record<string, string> = {
    proxmox: '#ec8b3c', portainer: '#57a8e6', grafana: '#f59e0b', custom: '#34d399',
    adminer: '#7dd3fc', pgadmin: '#4f83cc', phpmyadmin: '#e0a83c',
    'mongo-express': '#4bd494', kibana: '#f04e98', clickhouse: '#f0cf5a',
  }

  function copyLink(f: PortForward) {
    copyText(f.url).then((ok) => {
      if (!ok) return
      setCopied(f.id); setTimeout(() => setCopied((c) => (c === f.id ? null : c)), 1500)
    })
  }

  const header = props.embed ? null : (
    <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('forwards.title')}</span>
      <button onClick={props.onClose} aria-label={t('forwards.closeAria')}
        className="wt-touch ml-auto rounded-md px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"><CloseIcon size={14} /></button>
    </header>
  )

  // starea sondei: bulină + TEXT cu aceeaşi semantică (wt-good/-danger/-warn) lângă ţintă —
  // culoarea singură nu ajunge la daltonişti şi nici la cititorul de ecran (WCAG 1.4.1)
  const probeOf = (f: PortForward): ProbeState | 'off' => {
    if (f.scheme === 'telnet') return probes[f.id] ?? 'off'
    if (!f.enabled) return 'off'
    return probes[f.id] ?? 'checking'
  }
  const dotColor = (f: PortForward): string => {
    const s = probeOf(f)
    return s === 'up' ? 'bg-emerald-500' : s === 'down' ? 'bg-rose-500' : s === 'checking' ? 'bg-amber-500' : 'bg-slate-600'
  }
  const probeTone = (f: PortForward): string => {
    const s = probeOf(f)
    return s === 'up' ? 'wt-good' : s === 'down' ? 'wt-danger' : s === 'checking' ? 'wt-warn' : 'text-slate-500'
  }
  const dotTitle = (f: PortForward): string => {
    const s = probeOf(f)
    return s === 'up' ? t('forwards.probe.up') : s === 'down' ? t('forwards.probe.down')
      : s === 'checking' ? t('forwards.probe.checking') : t('forwards.probe.off')
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
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
      <aside ref={asideRef} aria-label={t('forwards.panelAria')} className={asideCls} onKeyDown={drawer.onKeyDown}>
        {drawer.sheet && <SheetBar title={t('forwards.title')} onBack={props.onClose} />}
        {!drawer.sheet && header}

        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1.5">
          <button onClick={() => (adding ? closeForm() : openAdd())} aria-expanded={adding}
            className="flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium wt-link hover:bg-ink-800">
            <PlusIcon /> {t('forwards.add')}
          </button>
          <button onClick={load} title={t('forwards.refresh')} aria-label={t('forwards.refresh')} className="wt-touch ml-auto rounded-md px-1.5 text-slate-400 hover:bg-ink-800"><RefreshIcon /></button>
        </div>

        {/* wizard: apps cunoscute cu un click — presetează portul/scheme şi le marchează ca „app"
            (dală pe dashboard). Intern e tot un forward. */}
        {isAgent && (
          <div className="flex flex-wrap items-center gap-1.5 border-b border-ink-800 px-3 py-2">
            <span className="mr-1 text-2xs uppercase tracking-wide text-slate-500">{t('forwards.addApp')}</span>
            <button onClick={() => presetApp('proxmox')}
              className="rounded-md px-2 py-0.5 text-2xs font-medium ring-1 ring-ink-700 hover:bg-ink-800"
              style={{ color: '#ec8b3c' }}>Proxmox</button>
            <button onClick={() => presetApp('portainer')}
              className="rounded-md px-2 py-0.5 text-2xs font-medium ring-1 ring-ink-700 hover:bg-ink-800"
              style={{ color: '#57a8e6' }}>Portainer</button>
            <button onClick={() => presetApp('grafana')}
              className="rounded-md px-2 py-0.5 text-2xs font-medium ring-1 ring-ink-700 hover:bg-ink-800"
              style={{ color: '#f59e0b' }}>Grafana</button>
            {DB_APPS.map((a) => (
              <button key={a.type} onClick={() => presetApp(a.type)}
                className="rounded-md px-2 py-0.5 text-2xs font-medium ring-1 ring-ink-700 hover:bg-ink-800"
                style={{ color: a.color }}>{APP_PRESETS[a.type].label}</button>
            ))}
            <button onClick={() => presetApp('custom')}
              className="rounded-md px-2 py-0.5 text-2xs font-medium text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">{t('forwards.appCustom')}</button>
          </div>
        )}

        {(adding || editing) && (
          // Escape în formular închide FORMULARUL, nu tot panoul (nu urcă la drawer)
          // eslint-disable-next-line jsx-a11y/no-static-element-interactions -- doar Escape, pe containerul câmpurilor
          <div className="flex flex-col gap-2 border-b border-ink-800 bg-ink-800/40 px-3 py-3 text-xs"
            onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); closeForm() } }}>
            <input autoFocus value={fLabel} onChange={(e) => setFLabel(e.target.value)} placeholder={t('forwards.namePlaceholder')}
              className="rounded-md bg-ink-800 px-2 py-1 text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
            {fScheme === 'telnet' ? (
              <div className="text-2xs leading-snug text-slate-500">
                {t('forwards.telnetInfo.pre')} <span className="text-slate-300">{t('forwards.telnetInfo.emphasis')}</span>{t('forwards.telnetInfo.post')}
              </div>
            ) : (
              <div className="text-2xs leading-snug text-slate-500">
                {t('forwards.addressLabel')} <span className="font-mono wt-link break-all">{previewHost}</span>
                {editing
                  ? <span className="text-slate-600"> · {t('forwards.addressFixed')}</span>
                  : <span className="text-slate-600"> · {t('forwards.addressGenerated')}</span>}
              </div>
            )}
            <div className="flex gap-2">
              <input value={fHost} onChange={(e) => setFHost(e.target.value)} placeholder="127.0.0.1"
                className="min-w-0 flex-1 rounded-md bg-ink-800 px-2 py-1 font-mono text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
              <input value={fPort} onChange={(e) => setFPort(e.target.value.replace(/\D/g, ''))} placeholder={t('forwards.portPlaceholder')} inputMode="numeric"
                className="w-16 rounded-md bg-ink-800 px-2 py-1 font-mono text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
              <select value={fScheme} aria-label={t('forwards.scheme')} onChange={(e) => {
                const v = e.target.value as 'http' | 'https' | 'telnet'
                setFScheme(v)
                if (v === 'telnet' && !fPort) setFPort('23')
              }}
                className="rounded-md bg-ink-800 px-1 py-1 text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500">
                <option value="http">http</option><option value="https">https</option>
                {isAgent && <option value="telnet">telnet</option>}
              </select>
            </div>
            <input value={fDesc} onChange={(e) => setFDesc(e.target.value)} placeholder={t('forwards.descPlaceholder')}
              className="rounded-md bg-ink-800 px-2 py-1 text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
            {/* indiciu SSO onest: outcome-ul „un singur login" vine din config-ul APP-ului,
                nu din WebTerm. Doar arătăm ce/unde, fără să pretindem că provisionăm noi ceva. */}
            {(fApp === 'proxmox' || fApp === 'portainer' || fApp === 'grafana') && (
              <div className="rounded-md border border-ink-700 bg-ink-900/60 px-2.5 py-2 text-2xs leading-snug text-slate-400">
                <span className="font-semibold text-slate-300">{t('forwards.ssoTitle')}</span> {t('forwards.ssoHint')} <HelpTip id="forwardsSso" />
                {fApp === 'proxmox' && <span className="mt-1 block wt-good">{t('forwards.ssoProxmox')}</span>}
                {fApp === 'portainer' && <span className="mt-1 block wt-warn">{t('forwards.ssoPortainer')}</span>}
                {fApp === 'grafana' && <span className="mt-1 block wt-good">{t('forwards.ssoGrafana')}</span>}
              </div>
            )}
            <div className="flex gap-2">
              <Button variant="primary" size="sm" onClick={submitForward} disabled={busy}>
                {busy ? t('forwards.saving') : editing ? t('forwards.save') : t('forwards.addShort')}
              </Button>
              <button onClick={closeForm} className="rounded-md px-3 py-1 text-slate-400 hover:bg-ink-800">{t('forwards.cancel')}</button>
            </div>
          </div>
        )}

        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger">{error}</div>}

        {!isAgent && (
          <div className="border-b border-ink-800 bg-ink-800/40 px-3 py-2 text-2xs leading-relaxed text-slate-400">
            {t('forwards.sshInfo')}{' '}
            {props.host.require_2fa
              ? t('forwards.sshInfo2fa')
              : t('forwards.sshInfoStored')}
          </div>
        )}

        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          {forwards && forwards.length === 0 && !adding && !editing && (
            <div className="flex flex-col items-center gap-2 px-4 py-8 text-center text-xs text-slate-500">
              <p>{t('forwards.empty')}</p>
              <Button variant="primary" onClick={openAdd}>{t('forwards.addFirst')}</Button>
            </div>
          )}
          {forwards && forwards.length > 0 && (
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))' }}>
          {forwards.map((f) => {
            const isTelnet = f.scheme === 'telnet'
            return (
            <div key={f.id} className="flex flex-col gap-2 rounded-xl border border-ink-700/70 bg-ink-800/40 p-3">
              <div className="flex items-start gap-2.5">
                {/* butonul de re-sondare: ţintă de 24px în jurul bulinei de 10px (era 10×10) */}
                <button onClick={() => (isTelnet || f.enabled) && probe(f)} title={isTelnet ? t('forwards.checkAccess') : dotTitle(f)}
                  className="-m-1.5 grid h-6 w-6 shrink-0 place-items-center rounded-full hover:bg-ink-700"
                  aria-label={`${t('forwards.checkAccess')} — ${dotTitle(f)}`}>
                  <span className={`h-2.5 w-2.5 rounded-full ${dotColor(f)}`} aria-hidden="true" />
                </button>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate text-sm font-semibold text-slate-200">{f.label}</span>
                    {f.app_type && (
                      <span className="shrink-0 rounded-md px-1.5 text-2xs font-bold uppercase tracking-wide"
                        style={{ color: APP_COLOR[f.app_type] || '#34d399', background: `${APP_COLOR[f.app_type] || '#34d399'}1f` }}
                        title={t('forwards.isApp')}>{t('forwards.appBadge')}</span>
                    )}
                  </div>
                  {isTelnet
                    ? <div className="truncate text-xs text-slate-500">{t('forwards.telnetSubtitle')}</div>
                    : <div className="truncate font-mono text-xs wt-link" title={f.url}>{urlHost(f)}</div>}
                  <div className="truncate font-mono text-2xs text-slate-500">
                    → {f.target_host}:{f.target_port} · {f.scheme} · <span className={probeTone(f)}>{dotTitle(f)}</span>
                  </div>
                  {f.description && <div className="mt-0.5 line-clamp-2 text-xs text-slate-500">{f.description}</div>}
                </div>
                {!isTelnet && (
                  <button onClick={() => togglePromote(f)} aria-pressed={!!f.app_type}
                    title={f.app_type ? t('forwards.demoteApp') : t('forwards.promoteApp')}
                    aria-label={f.app_type ? t('forwards.demoteApp') : t('forwards.promoteApp')}
                    className={`grid h-6 w-6 shrink-0 place-items-center rounded-md hover:bg-ink-700 ${f.app_type ? 'wt-warn' : 'text-slate-500 hover:text-amber-300'}`}>
                    <StarIcon filled={!!f.app_type} />
                  </button>
                )}
              </div>
              <div className="mt-auto flex flex-wrap items-center gap-1 border-t border-ink-800/60 pt-2">
                {isTelnet ? (
                  <button onClick={() => openTelnet(f)} disabled={opening === f.id} title={t('forwards.openInTerminal')}
                    className="rounded-md px-1.5 py-0.5 text-2xs font-medium wt-link hover:bg-ink-800 disabled:opacity-50">
                    {opening === f.id ? t('forwards.opening') : t('forwards.open')}
                  </button>
                ) : (<>
                  {f.enabled ? (
                    <a href={f.url} target="_blank" rel="noopener noreferrer" title={t('forwards.openNewTab')}
                      className="rounded-md px-1.5 py-0.5 text-2xs font-medium wt-link hover:bg-ink-800">{t('forwards.open')}</a>
                  ) : (
                    <button onClick={() => toggle(f)} title={t('forwards.startTitle')} className="rounded-md px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-ink-800">{t('forwards.start')}</button>
                  )}
                  <button onClick={() => copyLink(f)} title={t('forwards.copyLink')} aria-label={`${t('forwards.copyLink')} ${f.label}`} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-slate-200">
                    {copied === f.id ? <span className="wt-good"><CheckIcon size={12} /></span> : <LinkIcon />}
                  </button>
                  {f.enabled && <button onClick={() => toggle(f)} title={t('forwards.stop')} aria-label={`${t('forwards.stop')} ${f.label}`} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-amber-300"><PauseIcon size={12} /></button>}
                </>)}
                <span className="ml-auto flex items-center gap-0.5">
                  <button onClick={() => openEdit(f)} title={t('forwards.edit')} aria-label={`${t('forwards.edit')} ${f.label}`} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-slate-200"><PencilIcon /></button>
                  <button onClick={() => setConfirmDel(f)} title={t('forwards.delete')} aria-label={`${t('forwards.delete')} ${f.label}`} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-rose-300"><TrashIcon /></button>
                </span>
              </div>
            </div>
            )
          })}
          </div>
          )}
        </div>

        {confirmDel && (
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-2xs">
            <p className="mb-1.5 text-slate-300">{t('forwards.confirmDelPre')} <span className="font-mono wt-danger">{confirmDel.label}</span>?</p>
            <div className="flex gap-2">
              <Button variant="danger" size="sm" onClick={() => remove(confirmDel)}>{t('forwards.delete')}</Button>
              <button onClick={() => setConfirmDel(null)} className="rounded-md px-2 py-0.5 text-slate-400 hover:bg-ink-700">{t('forwards.cancel')}</button>
            </div>
          </div>
        )}
      </aside>
    </>
  )
}
