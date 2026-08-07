import { useEffect, useRef, useState } from 'react'
import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { CommandTracker } from '../lib/commands'
import { useI18n } from '../lib/i18n'
import { termTheme } from '../lib/termtheme'
import { useFocusTrap } from '../lib/useFocusTrap'

type Cmd = { text: string; exitCode?: number; time: number }

/** Reconstruiește lista de comenzi (text + exit + timp în .cast) rulând fluxul
    printr-un terminal ascuns cu CommandTracker (OSC 133). Un singur pas async per
    segment (≈ per comandă), deci rapid; timpul se ia din segmentul care conține C. */
async function buildCommands(evs: Ev[]): Promise<Cmd[]> {
  const hidden = document.createElement('div')
  hidden.style.cssText = 'position:fixed;left:-99999px;top:0;width:900px;height:480px;pointer-events:none'
  document.body.appendChild(hidden)
  // Sub tmux output-ul e poziționat cu escape-uri ABSOLUTE pentru dimensiunea reală
  // a sesiunii — dar header-ul .cast păstrează un default stale (80×24), deci nu ne
  // putem baza pe el. Folosim un terminal GENEROS: tmux nu adresează niciodată dincolo
  // de dimensiunea lui, deci pozițiile aterizează corect pe un terminal mai mare, iar
  // readCommand (promptRow→cursor) citește exact linia de comandă.
  const W = 300, H = 100
  const scan = new Terminal({ cols: W, rows: H, scrollback: 5000, allowProposedApi: true, disableStdin: true })
  scan.open(hidden)
  scan.resize(W, H)   // open() re-măsoară din element; forțăm înapoi la dimensiunea generoasă
  const tracker = new CommandTracker(scan)
  let curTime = 0
  tracker.onStart = (cmd) => { (cmd as unknown as { t: number }).t = curTime }
  const osc = scan.parser.registerOscHandler(133, (d) => { tracker.handle(d); return true })

  // Stepping PER-EVENIMENT: scriem fiecare eveniment 'o' și abia în callback-ul lui
  // trecem la următorul, ca `curTime` să fie corect când handler-ul OSC rulează
  // (write-ul e async). Marcajele OSC 133 pot fi SPARTE peste evenimente (chunk-uri
  // de rețea) — parser-ul xterm le reasamblează între write-uri consecutive, deci
  // detectarea prin substring nu e sigură; asta e. Timpul comenzii = evenimentul în
  // care C se completează (la ms de cel real). Sesiuni tipice: sute de evenimente.
  await new Promise<void>((resolve) => {
    let i = 0
    const step = () => {
      while (i < evs.length && evs[i][1] !== 'o') i++
      if (i >= evs.length) return resolve()
      const [t, , data] = evs[i++]
      curTime = t
      // .cast e BRUT: conține wrapper-ul de ecran alternativ al tmux (\x1b[?1049h…),
      // pe care gateway-ul îl STRIPUiește pentru stream-ul live. Fără curățare, scan-ul
      // intră în alt-screen și CommandTracker iese devreme (guard-ul de la linia „alternate”).
      // Îl curățăm identic ca să vedem exact ce vede sesiunea live (unde tracking-ul merge).
      scan.write(data.replace(/\x1b\[\?(?:1049|1047|1048|47)[hl]/g, ''), step)
    }
    step()
  })

  const list = tracker.commands.map((c) => ({
    // La replay sub tmux, readCommand prinde și promptul (cursorul e la col 0 la B).
    // Tăiem DOAR un prefix clar de prompt `user@host:path[#$%] ` — ancorat, ca să nu
    // atingem conținutul comenzii; alte stiluri de prompt rămân neatinse.
    text: c.text.replace(/^\S+@\S+:\S*?[#$%]\s+/, ''),
    exitCode: c.exitCode,
    time: (c as unknown as { t?: number }).t ?? 0,
  }))
  osc.dispose()
  scan.dispose()
  hidden.remove()
  return list
}

/** Player pentru transcripturile .cast (asciicast v2) — redare, pauză, seek,
    viteză. Nu aducem asciinema-player ca dependință: avem deja xterm.js, iar
    formatul e trivial (JSON pe linii), deci redăm cu terminalul nostru, în
    schema de culori aleasă de utilizator.

    Seek = reset + rescriere de la zero până la momentul t. Transcripturile sunt
    plafonate (16-64 MB), iar xterm scrie foarte repede când nu așteptăm timpii,
    deci e simplu și corect — fără snapshot-uri de stare. */
type Ev = [number, string, string]   // [timp, tip ('o'|'i'), date]

export default function TranscriptPlayer(props: {
  sid: string
  title: string
  onClose: () => void
}) {
  const { t } = useI18n()
  const box = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal>()
  const fitRef = useRef<FitAddon>()
  const evRef = useRef<Ev[]>([])
  const rafRef = useRef(0)
  const startedRef = useRef(0)      // performance.now() la (re)pornire
  const baseRef = useRef(0)         // poziția în transcript la (re)pornire
  const cursorRef = useRef(0)       // indexul următorului eveniment de scris
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  const [dur, setDur] = useState(0)
  const [pos, setPos] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [cmds, setCmds] = useState<Cmd[]>([])

  // ── fila TEXT ─────────────────────────────────────────────────────────────
  // Redarea e fidelă, dar inutilă când în sesiune a rulat o aplicație pe tot ecranul:
  // aceea repictează același ecran, deci „istoricul" nu se poate citi și nici căuta.
  // Textul curățat de secvențe de control e singurul mod în care devine util.
  const [mode, setMode] = useState<'play' | 'text'>('play')
  const [text, setText] = useState<string | null>(null)
  const [textErr, setTextErr] = useState('')
  const [q, setQ] = useState('')

  const showText = async () => {
    setMode('text')
    setPlaying(false)
    if (text !== null) return
    try {
      // `tail`: aducem coada (2 MB), nu zeci de MB — pentru „ce s-a întâmplat aici"
      // e destul, iar descărcarea completă e la un click distanță
      const r = await fetch(`/api/sessions/${props.sid}/transcript?format=txt&tail=true`,
        { credentials: 'same-origin' })
      if (!r.ok) throw new Error(t('transcript.errDownload'))
      setText(await r.text())
    } catch (e) {
      setTextErr(e instanceof Error ? e.message : String(e))
      setText('')
    }
  }

  const lines = text ? text.split('\n') : []
  const hits = q.trim()
    ? lines.map((l, i) => [i + 1, l] as [number, string])
      .filter(([, l]) => l.toLowerCase().includes(q.trim().toLowerCase()))
    : []

  // -- încărcare + terminal --------------------------------------------------
  useEffect(() => {
    const term = new Terminal({
      fontSize: 13,
      fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, monospace',
      theme: termTheme(),
      scrollback: 5000,
      disableStdin: true,
      cursorBlink: false,
      allowProposedApi: true,
      minimumContrastRatio: 4.5,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(box.current!)
    fit.fit()
    termRef.current = term
    fitRef.current = fit
    const ro = new ResizeObserver(() => fit.fit())
    ro.observe(box.current!)

    let alive = true
    ;(async () => {
      try {
        const res = await fetch(`/api/sessions/${props.sid}/transcript?format=cast`, {
          credentials: 'same-origin',
        })
        if (!res.ok) throw new Error(t('transcript.errDownload'))
        const text = await res.text()
        if (!alive) return
        const evs: Ev[] = []
        for (const line of text.split('\n')) {
          if (!line.trim() || line.startsWith('{"version"')) continue   // header
          try {
            const e = JSON.parse(line)
            if (Array.isArray(e) && typeof e[0] === 'number') evs.push(e as Ev)
          } catch {
            /* linie coruptă: o sărim, nu stricăm redarea */
          }
        }
        evRef.current = evs
        setDur(evs.length ? evs[evs.length - 1][0] : 0)
        setLoading(false)
        if (!evs.length) setErr(t('transcript.errEmpty'))

        // Lista de comenzi cu timp din .cast: pre-scan pe un terminal ASCUNS
        // (nu clipește player-ul vizibil) cu CommandTracker pe OSC 133. Timpul
        // din .cast se atașează la momentul CREĂRII comenzii (C) — comenzile goale
        // (doar Enter) n-au C, deci nu împerechem pe index. Segmentăm fluxul la
        // fiecare C ca timpul curent să fie corect când rulează handler-ul async.
        if (evs.length) buildCommands(evs).then((list) => { if (alive) setCmds(list) }).catch(() => { /* fără listă: player-ul rămâne funcțional */ })
      } catch (e) {
        if (alive) { setErr(e instanceof Error ? e.message : t('transcript.errGeneric')); setLoading(false) }
      }
    })()

    return () => {
      alive = false
      cancelAnimationFrame(rafRef.current)
      ro.disconnect()
      term.dispose()
      termRef.current = undefined
    }
  }, [props.sid])

  // -- redare ----------------------------------------------------------------
  const writeUntil = (t: number) => {
    const term = termRef.current
    if (!term) return
    const evs = evRef.current
    while (cursorRef.current < evs.length && evs[cursorRef.current][0] <= t) {
      const [, kind, data] = evs[cursorRef.current++]
      if (kind === 'o') term.write(data)
    }
  }

  const seek = (t: number) => {
    const term = termRef.current
    if (!term) return
    cancelAnimationFrame(rafRef.current)
    term.reset()
    cursorRef.current = 0
    writeUntil(t)
    baseRef.current = t
    startedRef.current = performance.now()
    setPos(t)
    if (playing) tick()
  }

  const tick = () => {
    rafRef.current = requestAnimationFrame(() => {
      const t = baseRef.current + ((performance.now() - startedRef.current) / 1000) * speed
      writeUntil(t)
      setPos(Math.min(t, dur))
      if (t >= dur) {
        setPlaying(false)
        return
      }
      tick()
    })
  }

  useEffect(() => {
    if (!playing) {
      cancelAnimationFrame(rafRef.current)
      return
    }
    baseRef.current = pos >= dur ? 0 : pos
    if (pos >= dur) { termRef.current?.reset(); cursorRef.current = 0 }
    startedRef.current = performance.now()
    tick()
    return () => cancelAnimationFrame(rafRef.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing, speed])

  const fmt = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = Math.floor(s % 60)
    return `${m}:${String(sec).padStart(2, '0')}`
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('transcript.dialogAria', { title: props.title })}
        className="wt-workspace flex h-[85vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl bg-ink-900 shadow-2xl ring-1 ring-ink-700"
      >
        <header className="flex items-center gap-3 border-b border-ink-800 px-4 py-2.5">
          <span className="truncate text-sm font-medium text-slate-200">
            ▶ {props.title || t('transcript.sessionFallback')}
          </span>
          <span className="shrink-0 rounded bg-ink-800 px-2 py-0.5 text-[11px] text-slate-400">{t('transcript.badge')}</span>
          {/* redare = fidel; text = citibil și căutabil (esențial după aplicații pe tot ecranul) */}
          <div className="ml-auto flex shrink-0 gap-1 rounded-lg bg-ink-800 p-0.5">
            {([['play', t('transcript.tabPlay')], ['text', t('transcript.tabText')]] as const).map(([m, label]) => (
              <button key={m} onClick={() => (m === 'text' ? showText() : setMode('play'))}
                aria-current={mode === m ? 'true' : undefined}
                className={`wt-touch rounded-md px-2.5 py-1 text-xs ${
                  mode === m ? 'bg-sky-600 text-white' : 'text-slate-300 hover:bg-ink-700'}`}
              >{label}</button>
            ))}
          </div>
          <a
            href={`/api/sessions/${props.sid}/transcript?format=${mode === 'text' ? 'txt' : 'cast'}`}
            download
            className="shrink-0 text-xs wt-link hover:underline"
          >
            {mode === 'text' ? t('transcript.downloadTxt') : t('transcript.download')}
          </a>
          <button onClick={props.onClose} aria-label={t('transcript.close')} className="shrink-0 rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
            ✕
          </button>
        </header>

        {mode === 'text' && (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-2">
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder={t('transcript.searchPlaceholder')}
                aria-label={t('transcript.searchPlaceholder')}
                spellCheck={false}
                className="min-w-0 flex-1 rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-500"
              />
              <span className="shrink-0 text-xs tabular-nums text-slate-500">
                {q.trim()
                  ? t('transcript.matches', { n: hits.length })
                  : t('transcript.lines', { n: lines.length })}
              </span>
            </div>
            <div className="min-h-0 flex-1 overflow-auto px-4 py-3">
              {text === null ? (
                <p className="text-sm text-slate-500">{t('transcript.loading')}</p>
              ) : textErr ? (
                <p className="text-sm wt-danger">{textErr}</p>
              ) : !text ? (
                <p className="text-sm text-slate-500">{t('transcript.errEmpty')}</p>
              ) : q.trim() ? (
                // la căutare afișăm doar liniile potrivite, cu numărul lor — restul ar fi zgomot
                <ul className="flex flex-col gap-0.5">
                  {hits.slice(0, 1000).map(([n, l]) => (
                    <li key={n} className="flex gap-3 font-mono text-xs">
                      <span className="shrink-0 tabular-nums text-slate-600">{n}</span>
                      <span className="whitespace-pre-wrap break-all text-slate-200">{l}</span>
                    </li>
                  ))}
                  {hits.length > 1000 && (
                    <li className="mt-2 text-xs text-slate-500">{t('transcript.tooManyMatches')}</li>
                  )}
                </ul>
              ) : (
                <pre className="whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-slate-200">{text}</pre>
              )}
            </div>
            <div className="border-t border-ink-800 px-4 py-2 text-[11px] text-slate-500">
              {t('transcript.textHint')}
            </div>
          </div>
        )}

        <div className={`flex min-h-0 flex-1 ${mode === 'text' ? 'hidden' : ''}`}>
          <div className="min-h-0 flex-1 p-2" style={{ background: termTheme().background }}>
            <div ref={box} className="h-full w-full" />
          </div>
          {cmds.length > 0 && (
            <aside className="hidden w-60 shrink-0 flex-col overflow-y-auto border-l border-ink-800 bg-ink-900 sm:flex">
              <div className="sticky top-0 z-10 border-b border-ink-800 bg-ink-900 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                {t('transcript.commands')} <span className="text-slate-500">{cmds.length}</span>
              </div>
              {cmds.map((c, i) => {
                const active = pos >= c.time && (i === cmds.length - 1 || pos < cmds[i + 1].time)
                return (
                  <button
                    key={i}
                    onClick={() => seek(Math.max(0, c.time))}
                    title={t('transcript.cmdJump', { cmd: c.text, time: fmt(c.time) })}
                    className={`flex items-start gap-2 border-b border-ink-800/60 px-3 py-1.5 text-left hover:bg-ink-800 ${active ? 'bg-ink-800' : ''}`}
                  >
                    <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${c.exitCode ? 'bg-red-400' : 'bg-emerald-400'}`} aria-hidden="true" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-xs text-slate-200">{c.text}</span>
                      <span className="text-[10px] tabular-nums text-slate-500">{fmt(c.time)}</span>
                    </span>
                  </button>
                )
              })}
            </aside>
          )}
        </div>

        {mode === 'text' ? null : err ? (
          <div className="border-t border-ink-800 px-4 py-3 text-sm wt-danger">{err}</div>
        ) : (
          <div className="flex items-center gap-3 border-t border-ink-800 px-4 py-2.5">
            <button
              onClick={() => setPlaying((v) => !v)}
              disabled={loading || dur === 0}
              aria-label={playing ? t('transcript.pause') : t('transcript.play')}
              className="shrink-0 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
            >
              {playing ? '❚❚' : '▶'}
            </button>
            <span className="shrink-0 font-mono text-xs tabular-nums text-slate-400">
              {fmt(pos)} / {fmt(dur)}
            </span>
            <input
              type="range"
              min={0}
              max={Math.max(dur, 0.1)}
              step={0.1}
              value={pos}
              aria-label={t('transcript.seekAria')}
              onChange={(e) => seek(Number(e.target.value))}
              className="min-w-0 flex-1 accent-sky-600"
            />
            <div className="flex shrink-0 gap-1">
              {[1, 2, 4].map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  className={`rounded px-2 py-1 text-xs ${
                    speed === s ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-400 hover:bg-ink-700'
                  }`}
                >
                  {s}×
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
