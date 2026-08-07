import { useEffect, useRef, useState } from 'react'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { Terminal } from '@xterm/xterm'
import { api, WatermarkConfig } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { termTheme } from '../lib/termtheme'
import Watermark from './Watermark'

// tema se citește la montare (nu la load-ul modulului): altfel schimbarea
// schemei de culori din alt tab nu s-ar reflecta la următoarea deschidere
const readTheme = () => ({ ...termTheme(), cursor: termTheme().background })   // read-only: hide cursor

// mesaje jucăușe pentru pagina de revoke (unul random la deschidere) — textele sunt în catalog (share.revokeN.*)
const REVOKE_COUNT = 5

/** Public read-only viewer opened from a share link. No account, no input. */
export default function SharedView(props: { token: string }) {
  const { t } = useI18n()
  const container = useRef<HTMLDivElement>(null)
  const [title, setTitle] = useState('')
  const [error, setError] = useState('')
  const [conn, setConn] = useState<'connecting' | 'open' | 'closed' | 'locked' | 'revoked'>('connecting')
  const [termBg] = useState(() => readTheme().background || '#0b0e14')
  const [watermark, setWatermark] = useState<WatermarkConfig | null>(null)
  const [writable, setWritable] = useState(false)
  const writableRef = useRef(false)   // citit de onData (fără stale closure)
  const [zoom, setZoom] = useState(1)                 // reglajul invitatului peste fit (A−/A+)
  const [revokeIdx] = useState(() => Math.floor(Math.random() * REVOKE_COUNT))
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const ptyRef = useRef<{ rows: number; cols: number } | null>(null)   // grila reală a PTY-ului
  const zoomRef = useRef(1)

  // Oglindă corectă: setează terminalul la grila PTY-ului (owner) și alege FONTUL care încape,
  // ca output-ul să nu se împacheteze/desincronizeze. `zoom` e reglajul invitatului peste fit.
  const applyFit = () => {
    const term = termRef.current, fit = fitRef.current, pty = ptyRef.current
    if (!term || !fit || !pty || !container.current) return
    const base = 14
    term.options.fontSize = base
    const prop = fit.proposeDimensions()   // câte cols/rows încap în container la fontul `base`
    if (!prop || !prop.cols || !prop.rows) return
    const scale = Math.min(prop.cols / pty.cols, prop.rows / pty.rows) * zoomRef.current
    term.options.fontSize = Math.max(5, Math.min(40, +(base * scale).toFixed(2)))
    term.resize(pty.cols, pty.rows)        // oglindim EXACT grila PTY-ului (fără fit la containerul nostru)
  }
  const bumpZoom = (d: number) => {
    const z = Math.max(0.4, Math.min(3, +(zoomRef.current + d).toFixed(2)))
    zoomRef.current = z; setZoom(z); applyFit()
  }

  useEffect(() => {
    api<{ title: string; watermark?: WatermarkConfig | null; writable?: boolean }>(`/api/shared/${props.token}`)
      .then((m) => {
        setTitle(m.title)
        setWatermark(m.watermark ?? null)   // ${email}/${host} deja rezolvate server-side
        document.title = t('share.docTitle', { title: m.title || 'Terminal' })
      })
      .catch(() => setError(t('share.errInvalid')))
  }, [props.token, t])

  useEffect(() => {
    if (error) return
    const term = new Terminal({
      fontSize: 14,
      fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, monospace',
      theme: readTheme(),
      scrollback: 10000,
      disableStdin: true,
      cursorBlink: false,
      allowProposedApi: true,
      minimumContrastRatio: 4.5,   // vezi comentariul din SessionView
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())
    term.open(container.current!)
    termRef.current = term
    fitRef.current = fit
    ptyRef.current = ptyRef.current || { rows: 24, cols: 80 }   // default până vine `init`
    applyFit()
    // handle pt. E2E/debug (ca în SessionView): citirea conținutului din buffer
    ;((window as unknown as { __wtTerms?: Map<string, Terminal> }).__wtTerms ??= new Map()).set('shared:' + props.token, term)
    const ro = new ResizeObserver(() => applyFit())
    ro.observe(container.current!)

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/shared/${props.token}`)
    ws.binaryType = 'arraybuffer'
    ws.onopen = () => setConn('open')
    // writable: input-ul vizitatorului merge la sesiune. Gate-uit prin writableRef
    // (autoritatea e mesajul `init` de la server); dimensiunea rămâne a owner-ului.
    term.onData((d) => {
      if (writableRef.current && ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(d))
    })
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'ping') ws.send(JSON.stringify({ type: 'pong', n: msg.n }))
        else if (msg.type === 'resync') term.reset()
        else if (msg.type === 'exit' || msg.type === 'lost') setConn('closed')
        // idle-lock 2FA: proprietarul trebuie să se re-autentifice; invitatul nu poate
        // debloca (n-are passkey) — doar așteaptă. Serverul nu trimite output cât e blocat.
        else if (msg.type === 'locked') setConn('locked')
        else if (msg.type === 'unlocked') setConn('open')   // urmează resync + tail din transcript
        // owner-ul a revocat linkul (sau a expirat) → ştergem ce a apucat să vadă + oprim tot
        else if (msg.type === 'revoked') {
          try { termRef.current?.reset() } catch { /* dispose în curs */ }
          setConn('revoked')
          try { ws.close() } catch { /* deja */ }
        }
        // grila PTY-ului (init) + schimbările ei (owner-ul redimensionează) → re-oglindim
        else if (msg.type === 'resize' && msg.rows && msg.cols) {
          ptyRef.current = { rows: msg.rows, cols: msg.cols }; applyFit()
        }
        else if (msg.type === 'init') {
          if (msg.rows && msg.cols) { ptyRef.current = { rows: msg.rows, cols: msg.cols }; applyFit() }
          if (msg.writable) {
            term.options.disableStdin = false   // fără asta xterm nu emite onData
            writableRef.current = true
            setWritable(true)
            term.focus()   // ALTFEL terminalul nu e focusat la deschidere → tastarea nu merge deloc
          }
        }
      } else {
        term.write(new Uint8Array(ev.data))
      }
    }
    // NU suprascrie 'revoked' (mesajul revoked ajunge ÎNAINTEA close-ului; altfel „deconectat" ar învinge)
    ws.onclose = () => setConn((c) => (c === 'revoked' ? c : 'closed'))

    return () => {
      ro.disconnect()
      ws.close()
      ;(window as unknown as { __wtTerms?: Map<string, Terminal> }).__wtTerms?.delete('shared:' + props.token)
      termRef.current = null
      fitRef.current = null
      term.dispose()
    }
  }, [props.token, error])

  if (error) {
    return <div className="flex h-full items-center justify-center text-slate-500">{error}</div>
  }

  // Revocat/expirat: înlocuim COMPLET terminalul cu o pagină dedicată (nu overlay peste conţinutul
  // înghețat) — mai curat şi mai sigur: invitatul nu mai vede ce apucase pe ecran.
  if (conn === 'revoked') {
    // culori dark FIXE (nu tokeni ink-*, care în tema light devin aproape albe → pagină „goală")
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center"
        style={{ background: 'radial-gradient(40rem 26rem at 50% 12%, rgba(124,58,237,.10), transparent 60%), #0a0d13' }}>
        <style>{`
          @keyframes wtRevokeIn { 0%{opacity:0;transform:translateY(10px) scale(.96)} 100%{opacity:1;transform:none} }
          @keyframes wtSlashIn { to { stroke-dashoffset: 0 } }
          @keyframes wtBadgeTip { 0%,100%{transform:rotate(0)} 30%{transform:rotate(-7deg)} 60%{transform:rotate(4deg)} }
          .wt-revoke-in { animation: wtRevokeIn .45s cubic-bezier(.2,.7,.3,1) both }
          .wt-badge-tip { animation: wtBadgeTip .6s .15s ease-in-out both }
          .wt-slash-in { stroke-dasharray: 26; stroke-dashoffset: 26; animation: wtSlashIn .45s .35s ease-out forwards }
          @media (prefers-reduced-motion: reduce){ .wt-revoke-in,.wt-badge-tip{animation:none} .wt-slash-in{animation:none;stroke-dashoffset:0} }
        `}</style>
        <div className="wt-revoke-in flex flex-col items-center gap-4">
          <div className="brand-badge wt-badge-tip grid h-16 w-16 place-items-center rounded-2xl">
            <svg width="34" height="34" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M4.5 6.4 9.4 12 4.5 17.6" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="14.6" cy="7.1" r="2.1" fill="#fff" /><circle cx="18.4" cy="12" r="2.1" fill="#fff" /><circle cx="14.6" cy="16.9" r="2.1" fill="#fff" />
              <path className="wt-slash-in" d="M4 20 20 4" stroke="#fca5a5" strokeWidth="2.4" strokeLinecap="round" />
            </svg>
          </div>
          <div className="font-mono text-6xl font-black tracking-tighter" style={{ color: '#f1f5f9' }}>403</div>
          <h1 className="text-lg font-semibold" style={{ color: '#e2e8f0' }}>{t(`share.revoke${revokeIdx}.title`)}</h1>
          <p className="max-w-xs text-sm leading-relaxed" style={{ color: '#94a3b8' }}>{t(`share.revoke${revokeIdx}.body`)}</p>
        </div>
      </div>
    )
  }

  return (
    /* wt-workspace: header/status rămân întunecate și pe tema Aurora */
    <div className="wt-workspace wt-main flex h-full flex-col">
      <div className="wt-window flex h-full flex-col">
        <header className="flex items-center gap-2 border-b border-ink-800 bg-ink-900 px-4 py-2">
          <span className="text-sm font-medium">{title || t('share.titleFallback')}</span>
          <span className={`rounded px-2 py-0.5 text-[11px] ${writable ? 'bg-emerald-500/15 text-emerald-300' : 'bg-ink-800 text-slate-400'}`}>
            {writable ? t('share.canWrite') : t('share.readOnly')}
          </span>
          {/* zoom invitat: reglaj peste fit (fontul se adaptează, grila rămâne a owner-ului) */}
          {conn === 'open' && (
            <div className="ml-auto flex items-center gap-1">
              <button onClick={() => bumpZoom(-0.1)} title={t('share.zoomOut')}
                className="grid h-6 w-6 place-items-center rounded text-slate-400 hover:bg-ink-800 hover:text-slate-200">A−</button>
              <button onClick={() => { zoomRef.current = 1; setZoom(1); applyFit() }} title={t('share.zoomFit')}
                className="rounded px-1.5 text-[11px] tabular-nums text-slate-500 hover:bg-ink-800 hover:text-slate-300">{Math.round(zoom * 100)}%</button>
              <button onClick={() => bumpZoom(0.1)} title={t('share.zoomIn')}
                className="grid h-6 w-6 place-items-center rounded text-slate-400 hover:bg-ink-800 hover:text-slate-200">A+</button>
            </div>
          )}
          {conn !== 'open' && (
            <span className="ml-auto text-xs text-slate-500">
              {conn === 'connecting' ? t('share.connecting') : conn === 'locked' ? t('share.lockedShort') : t('share.disconnected')}
            </span>
          )}
        </header>
        <div className="relative min-h-0 flex-1 overflow-auto p-1.5" style={{ background: termBg }}>
          <div ref={container} className="h-full w-full" />
          {conn === 'locked' && (
            <div className="absolute inset-0 grid place-items-center bg-black/70 p-4 text-center">
              <div className="max-w-sm space-y-1">
                <div className="text-base font-semibold text-slate-100">{t('share.lockedTitle')}</div>
                <div className="text-[13px] text-slate-400">
                  {t('share.lockedBody')}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      <Watermark config={watermark} />
    </div>
  )
}
