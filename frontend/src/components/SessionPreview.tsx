import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { useEffect, useRef, useState } from 'react'

import { termTheme } from '../lib/termtheme'
import { useI18n } from '../lib/i18n'

// paleta partajată, dar cu cursorul ascuns (preview read-only)
const previewTheme = () => ({ ...termTheme(), cursor: termTheme().background })

/** Previzualizare read-only a unei sesiuni: randează coada transcriptului.
   Pentru sesiuni active se reîmprospătează periodic. Fără WebSocket, fără input. */
export default function SessionPreview(props: { sid: string; live: boolean }) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  // gol = transcriptul n-are încă octeţi (sesiune proaspătă): arătăm un placeholder discret
  // în loc de o cutie neagră care pare ruptă.
  const [empty, setEmpty] = useState(true)

  useEffect(() => {
    const term = new Terminal({
      fontSize: 12,
      fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, monospace',
      theme: previewTheme(),
      scrollback: 2000,
      disableStdin: true,
      cursorBlink: false,
      convertEol: false,
      minimumContrastRatio: 4.5,   // vezi comentariul din SessionView
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(ref.current!)
    fit.fit()

    let cancelled = false
    const load = async () => {
      try {
        const r = await fetch(`/api/sessions/${props.sid}/preview`)
        if (!r.ok || cancelled) return
        const buf = new Uint8Array(await r.arrayBuffer())
        if (cancelled) return
        term.reset()
        term.write(buf)
        setEmpty(buf.length === 0)
      } catch {
        /* ignoră */
      }
    }
    load()
    const timer = props.live ? setInterval(() => { if (!document.hidden) load() }, 3000) : undefined
    const ro = new ResizeObserver(() => fit.fit())
    ro.observe(ref.current!)

    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
      ro.disconnect()
      term.dispose()
    }
  }, [props.sid, props.live])

  return (
    <div className="relative h-full w-full">
      <div ref={ref} className="h-full w-full" />
      {empty && (
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-1.5 text-slate-600">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <path d="M7 9l3 3-3 3M13 15h4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="text-[11px]">{t('host.previewEmpty')}</span>
        </div>
      )}
    </div>
  )
}
