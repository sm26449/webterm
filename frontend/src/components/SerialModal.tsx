import { useEffect, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { btn } from './settings/ui'

interface SerialPort {
  device: string
  by_id: string | null
  by_path?: string | null
  vid?: string
  pid?: string
  vendor?: string
  product?: string
  serial?: string
  driver?: string
  uart?: string | null
  busy?: string
  desc: string
}
export interface SerialParams { baud: number; bits: number; parity: string; stop: number; flow: string }

const BAUDS = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400]

type Found = { device: string; phase: 'removed' | 'back' } | null

/** Consolă serială pe un host cu agent: descoperă porturile (RS232/RS485/USB) cu metadate
    bogate, ajută la identificarea fizică (scoate/bagă adaptorul) și deschide o sesiune. */
export default function SerialModal(props: {
  host: Host
  onClose: () => void
  onOpen: (device: string, params: SerialParams) => Promise<boolean>
}) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  const [ports, setPorts] = useState<SerialPort[] | null>(null)
  const [discovering, setDiscovering] = useState(true)
  const [err, setErr] = useState('')
  const [device, setDevice] = useState('')
  const [baud, setBaud] = useState(115200)
  const [bits, setBits] = useState(8)
  const [parity, setParity] = useState('none')
  const [stop, setStop] = useState(1)
  const [flow, setFlow] = useState('none')
  const [advanced, setAdvanced] = useState(false)
  const [busy, setBusy] = useState(false)

  // identificare fizică prin scoatere/băgare + evidențierea schimbărilor la rescan
  const [appeared, setAppeared] = useState<Set<string>>(new Set())
  const [identifying, setIdentifying] = useState(false)
  const [baseline, setBaseline] = useState<string[]>([])
  const [found, setFound] = useState<Found>(null)
  const prevDevices = useRef<Set<string> | null>(null)

  const fetchPorts = () =>
    api<{ ports: SerialPort[] }>(`/api/hosts/${props.host.id}/serial/discover`, { method: 'POST' })
      .then((r) => r.ports)

  const applyList = (list: SerialPort[]) => {
    const prev = prevDevices.current
    setAppeared(new Set(list.map((p) => p.device).filter((d) => prev && !prev.has(d))))
    prevDevices.current = new Set(list.map((p) => p.device))
    setPorts(list)
  }

  const discover = () => {
    setDiscovering(true); setErr('')
    fetchPorts()
      .then((list) => {
        applyList(list)
        if (list.length && !device) setDevice(list[0].device)
      })
      .catch((e) => setErr(errText(e, t) || t('serial.discoveryFailed')))
      .finally(() => setDiscovering(false))
  }
  useEffect(discover, [props.host.id])   // eslint-disable-line react-hooks/exhaustive-deps

  const startIdentify = () => {
    setFound(null)
    setBaseline((ports ?? []).map((p) => p.device))
    setIdentifying(true)
  }
  const stopIdentify = () => { setIdentifying(false); setFound(null) }

  // buclă de identificare: rescanează la ~1.2s, detectează portul SCOS (dispărut din baseline)
  // apoi REVENIT (reapărut) → îl selectează automat. Fără schimbare de agent (refolosește discovery).
  useEffect(() => {
    if (!identifying) return
    let alive = true
    const iv = setInterval(async () => {
      let list: SerialPort[]
      try { list = await fetchPorts() } catch { return }
      if (!alive) return
      applyList(list)
      const now = new Set(list.map((p) => p.device))
      if (!found) {
        const removed = baseline.find((d) => !now.has(d))
        if (removed) setFound({ device: removed, phase: 'removed' })
      } else if (found.phase === 'removed' && now.has(found.device)) {
        setDevice(found.device)
        setFound({ device: found.device, phase: 'back' })
        setIdentifying(false)          // gata — l-am legat de nodul corect
      }
    }, 1200)
    return () => { alive = false; clearInterval(iv) }
  }, [identifying, found, baseline])   // eslint-disable-line react-hooks/exhaustive-deps

  const open = async () => {
    if (!device.trim()) return
    setBusy(true)
    const ok = await props.onOpen(device.trim(), { baud, bits, parity, stop, flow })
    setBusy(false)
    if (ok) props.onClose()
  }

  const sel = 'rounded-lg border border-ink-700 bg-ink-900 px-2 py-1.5 text-sm text-slate-200'
  const chip = 'rounded px-1.5 py-0.5 text-[11px] font-medium'   // minim 11 px (audit tipografie)

  const foundLabel = (d: string) => {
    const p = (ports ?? []).find((x) => x.device === d)
    return p?.desc && p.desc !== d ? `${d} · ${p.desc}` : d
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('serial.aria')}
        className="glass w-full max-w-lg rounded-2xl p-6">
        <h2 className="font-semibold">{t('serial.titleHost', { name: props.host.name })}</h2>
        <p className="mt-1 text-xs text-slate-500">
          {t('serial.subtitle')}
        </p>

        <div className="mt-4 space-y-3">
          {/* porturi descoperite */}
          <div>
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">{t('serial.port')}</span>
              <div className="flex items-center gap-3">
                <button onClick={identifying ? stopIdentify : startIdentify}
                  disabled={discovering && !identifying}
                  className="text-xs wt-link hover:underline disabled:opacity-50"
                  title={t('serial.identifyHint')}>
                  {identifying ? t('serial.stopIdentify') : t('serial.identify')}
                </button>
                <button onClick={discover} disabled={discovering || identifying}
                  className="text-xs wt-link hover:underline disabled:opacity-50">
                  {discovering ? t('serial.searching') : t('serial.rediscover')}
                </button>
              </div>
            </div>

            {/* banner mod identificare */}
            {identifying && !found && (
              <div role="status" className="wt-warn mb-2 rounded-lg bg-amber-500/10 px-3 py-2 text-xs ring-1 ring-amber-500/30">
                <span aria-hidden="true">🔍</span> <b>{t('serial.identifyModeTitle')}</b> {t('serial.identifyModeBody')}
              </div>
            )}
            {found?.phase === 'removed' && (
              <div role="status" className="wt-warn mb-2 rounded-lg bg-amber-500/10 px-3 py-2 text-xs ring-1 ring-amber-500/30">
                <span aria-hidden="true">➖</span> <b className="font-mono">{found.device}</b> {t('serial.wasRemovedPre')} <b>{t('serial.removed')}</b> {t('serial.wasRemovedPost')}
              </div>
            )}
            {found?.phase === 'back' && (
              <div role="status" className="wt-good mb-2 flex items-center justify-between rounded-lg bg-emerald-500/10 px-3 py-2 text-xs ring-1 ring-emerald-500/30">
                <span><span aria-hidden="true">✓</span> <b className="font-mono">{foundLabel(found.device)}</b> {t('serial.cameBack')} <b>{t('serial.selected')}</b>.</span>
                <button type="button" onClick={() => setFound(null)} aria-label={t('serial.dismissFound')}
                  className="grid h-6 w-6 place-items-center rounded hover:bg-ink-700"><span aria-hidden="true">×</span></button>
              </div>
            )}

            {discovering && !ports ? (
              <div className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-500">{t('serial.searchingPorts')}</div>
            ) : ports && ports.length ? (
              <div className="max-h-56 space-y-1 overflow-y-auto">
                {ports.map((p) => {
                  const isFound = found?.device === p.device
                  return (
                    <label key={p.device}
                      className={`flex cursor-pointer items-start gap-2 rounded-lg px-2.5 py-1.5 text-sm ring-1 ${
                        device === p.device ? 'bg-sky-600/15 ring-sky-600'
                        : isFound ? 'bg-orange-600/10 ring-orange-600/60'
                        : 'bg-ink-800 ring-ink-700 hover:bg-ink-700'}`}>
                      <input type="radio" checked={device === p.device} onChange={() => setDevice(p.device)}
                        className="mt-1 accent-sky-600" />
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-1.5">
                          <span className="truncate font-mono text-slate-200">{p.device}</span>
                          {appeared.has(p.device) && <span className={`${chip} wt-good bg-emerald-500/15`}>{t('serial.new')}</span>}
                          {p.busy && <span className={`${chip} wt-danger bg-rose-500/15`} title={t('serial.heldOpenBy', { who: p.busy })}>{t('serial.inUse', { who: p.busy })}</span>}
                        </span>
                        {p.desc && p.desc !== p.device &&
                          <span className="block truncate text-[11px] text-slate-400">{p.desc}</span>}
                        {/* metadate */}
                        <span className="mt-0.5 flex flex-wrap items-center gap-1">
                          {p.driver && <span className={`${chip} bg-ink-700 text-slate-300`}>{p.driver}</span>}
                          {p.vid && p.pid && <span className={`${chip} bg-ink-700 font-mono text-slate-400`}>{p.vid}:{p.pid}</span>}
                          {p.uart && <span className={`${chip} bg-ink-700 text-slate-300`}>UART {p.uart}</span>}
                          {p.serial && <span className={`${chip} wt-accent bg-sky-500/15 font-mono`} title={t('serial.usbUniqueSerial')}>SN {p.serial}</span>}
                          {p.by_path && <span className={`${chip} bg-ink-700 text-slate-400`} title={p.by_path}>🔌 {t('serial.physicalPort')}</span>}
                        </span>
                      </span>
                    </label>
                  )
                })}
              </div>
            ) : (
              <div className="rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-500">
                {t('serial.noPortsPre')} <span className="font-mono">/dev/ttyUSB0</span>{t('serial.noPortsMid')} <span className="font-mono">dialout</span>{t('serial.noPortsPost')}
              </div>
            )}
          </div>

          {/* device manual + baud */}
          <div className="flex gap-2">
            <label className="min-w-0 flex-1">
              <span className="mb-1 block text-xs font-medium text-slate-400">{t('serial.deviceManual')}</span>
              <input value={device} spellCheck={false} onChange={(e) => setDevice(e.target.value)}
                placeholder="/dev/ttyUSB0" aria-required="true"
                aria-invalid={err ? true : undefined} aria-describedby={err ? 'serial-error' : undefined}
                className="w-full rounded-lg border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-sm text-slate-200 focus:border-sky-500 focus:outline-none" />
            </label>
            <label className="shrink-0">
              <span className="mb-1 block text-xs font-medium text-slate-400">Baud</span>
              <select value={baud} aria-label={t('serial.baud')} onChange={(e) => setBaud(Number(e.target.value))} className={sel}>
                {BAUDS.map((b) => <option key={b} value={b}>{b}</option>)}
              </select>
            </label>
          </div>

          {/* avansat: biți/paritate/stop/flow */}
          <button type="button" onClick={() => setAdvanced((v) => !v)} aria-expanded={advanced} className="text-xs text-slate-400 hover:text-slate-200">
            {advanced ? '▾' : '▸'} {t('serial.advanced')}
          </button>
          {advanced && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <label className="text-xs text-slate-400">{t('serial.bits')}
                <select value={bits} aria-label={t('serial.bits')} onChange={(e) => setBits(Number(e.target.value))} className={`${sel} mt-1 w-full`}>
                  {[8, 7, 6, 5].map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
              <label className="text-xs text-slate-400">{t('serial.parity')}
                <select value={parity} aria-label={t('serial.parity')} onChange={(e) => setParity(e.target.value)} className={`${sel} mt-1 w-full`}>
                  <option value="none">none</option><option value="even">even</option><option value="odd">odd</option>
                </select>
              </label>
              <label className="text-xs text-slate-400">Stop
                <select value={stop} aria-label={t('serial.stop')} onChange={(e) => setStop(Number(e.target.value))} className={`${sel} mt-1 w-full`}>
                  <option value={1}>1</option><option value={2}>2</option>
                </select>
              </label>
              <label className="text-xs text-slate-400">Flow
                <select value={flow} aria-label={t('serial.flow')} onChange={(e) => setFlow(e.target.value)} className={`${sel} mt-1 w-full`}>
                  <option value="none">none</option><option value="rtscts">RTS/CTS</option><option value="xonxoff">XON/XOFF</option>
                </select>
              </label>
            </div>
          )}

          <div id="serial-error" role="alert" className={err ? 'text-xs wt-danger' : 'sr-only'}>{err}</div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={props.onClose} className={`${btn.ghost} px-4 py-2`}>{t('serial.cancel')}</button>
          <button type="button" onClick={open} disabled={busy || !device.trim()} className={`${btn.primary} px-4 py-2`}>
            {busy ? t('serial.opening') : t('serial.open')}
          </button>
        </div>
      </div>
    </div>
  )
}
