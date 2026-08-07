import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { useEffect, useRef } from 'react'

import { termTheme } from '../lib/termtheme'

// paleta partajată, dar cu cursorul ascuns (preview read-only)
const previewTheme = () => ({ ...termTheme(), cursor: termTheme().background })

/** Previzualizare read-only a unei sesiuni: randează coada transcriptului.
   Pentru sesiuni active se reîmprospătează periodic. Fără WebSocket, fără input. */
export default function SessionPreview(props: { sid: string; live: boolean }) {
  const ref = useRef<HTMLDivElement>(null)

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

  return <div ref={ref} className="h-full w-full" />
}
