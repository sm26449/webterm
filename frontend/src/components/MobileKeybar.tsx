import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { applyMods } from '../lib/keymods'

const WHEEL_UP = '\x1b[<64;40;10M'.repeat(3) // rapoarte SGR de rotiță: tmux
const WHEEL_DOWN = '\x1b[<65;40;10M'.repeat(3) // derulează istoricul (copy-mode)

// `aria`: eticheta citită de cititorul de ecran — glifele (⇞ ↑ ^C |) sunt mute sau citite
// ca „caret C". Cheie de catalog (`keybar.*`) sau text neutru (Escape/Tab/Ctrl+C sunt la fel
// în orice limbă).
// `wheel`: rapoarte de rotiţă pentru tmux — NU primesc modificatori (n-ar mai fi rotiţă).
const KEYS: Array<{ label: string; seq: string; aria: string; wheel?: boolean }> = [
  { label: '⇞', seq: WHEEL_UP, aria: 'keybar.scrollUp', wheel: true },
  { label: '⇟', seq: WHEEL_DOWN, aria: 'keybar.scrollDown', wheel: true },
  { label: 'Esc', seq: '\x1b', aria: 'Escape' },
  { label: 'Tab', seq: '\t', aria: 'Tab' },
  { label: '↑', seq: '\x1b[A', aria: 'keybar.up' },
  { label: '↓', seq: '\x1b[B', aria: 'keybar.down' },
  { label: '←', seq: '\x1b[D', aria: 'keybar.left' },
  { label: '→', seq: '\x1b[C', aria: 'keybar.right' },
  // tastele de navigare REALE (ce trimite xterm pentru Home/End/PgUp/PgDn), nu rotiţa tmux de
  // mai sus: less/vim/htop/readline le înţeleg; ⇞/⇟ rămân pentru derularea istoricului tmux
  { label: 'Home', seq: '\x1b[H', aria: 'keybar.home' },
  { label: 'End', seq: '\x1b[F', aria: 'keybar.end' },
  { label: 'PgUp', seq: '\x1b[5~', aria: 'keybar.pageUp' },
  { label: 'PgDn', seq: '\x1b[6~', aria: 'keybar.pageDown' },
  { label: '^C', seq: '\x03', aria: 'Ctrl+C' },
  { label: '^D', seq: '\x04', aria: 'Ctrl+D' },
  { label: '^Z', seq: '\x1a', aria: 'Ctrl+Z' },
  { label: '^R', seq: '\x12', aria: 'Ctrl+R' },
  { label: '|', seq: '|', aria: 'keybar.pipe' },
  { label: '/', seq: '/', aria: 'keybar.slash' },
  { label: '-', seq: '-', aria: 'keybar.dash' },
  { label: '~', seq: '~', aria: 'keybar.tilde' },
]

/** Rândul de taste extra pentru tastaturile tactile. Apare pe orice dispozitiv cu pointer
    GROSIER (deget), indiferent de lăţime — era `md:hidden`, deci un iPad fără tastatură fizică
    rămânea fără Esc/Ctrl/săgeţi. Pe desktop (mouse) rămâne ascuns: vezi `.wt-keybar` în index.css. */
export default function MobileKeybar(props: {
  onKeys: (seq: string) => void
  onPaste: () => void
  backend?: string | null
}) {
  const { t } = useI18n()
  const [ctrl, setCtrl] = useState(false)
  const [alt, setAlt] = useState(false)
  // Publicăm înălţimea reală a keybar-ului în `--wt-keybar-h` (pe <html>), ca widgetul plutitor
  // de transferuri — portat în <body>, deci fără acces la acest DOM — să se aşeze DEASUPRA lui pe
  // mobil şi să nu acopere niciodată tastatura de comenzi. ResizeObserver: înălţimea variază cu
  // safe-area-inset şi cu wrap-ul. La demontare (desktop / fără sesiune vie) o resetăm → widgetul
  // coboară la marginea de jos. Ascuns prin CSS (desktop) → offsetHeight 0 → variabila e 0px.
  const rootRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = rootRef.current
    if (!el) return
    const setVar = () => document.documentElement.style.setProperty('--wt-keybar-h', `${el.offsetHeight}px`)
    setVar()
    const ro = new ResizeObserver(setVar)
    ro.observe(el)
    return () => { ro.disconnect(); document.documentElement.style.removeProperty('--wt-keybar-h') }
  }, [])
  // ⇞/⇟ injectează rapoarte de rotiță SGR pe care doar tmux le interpretează;
  // pe backend „pty" (fără tmux) octeții ar ajunge tastați în shell ca gunoi
  const keys = props.backend === 'tmux' ? KEYS : KEYS.filter((k) => !k.wheel)
  const ariaOf = (k: { aria: string; seq: string; wheel?: boolean }) => {
    const base = k.aria.startsWith('keybar.') ? t(k.aria) : k.aria
    if (k.wheel || (!ctrl && !alt)) return base
    // cu un modificator aprins, eticheta spune ce se va trimite (Ctrl+Alt+<tastă>)
    const name = k.seq.length === 1 && k.seq >= '@' ? k.seq : base
    return `${ctrl ? 'Ctrl+' : ''}${alt ? 'Alt+' : ''}${name}`
  }
  // modificator aprins = plin + inel, ca să se vadă dintr-o privire chiar în lumina zilei
  const modCls = (on: boolean) => `wt-touch shrink-0 rounded-md px-2.5 py-1 text-xs font-medium ${
    on ? 'bg-sky-600 text-white ring-2 ring-sky-300' : 'bg-ink-800 text-slate-300'}`

  return (
    <div ref={rootRef} data-testid="mobile-keybar"
      className="wt-keybar gap-1 border-t border-ink-800 bg-ink-900 px-2 pb-[max(0.375rem,env(safe-area-inset-bottom))] pt-1.5">
      {/* Ctrl/Alt FIXE în stânga, în afara zonei care derulează: starea lor aprinsă rămâne
          vizibilă şi când ai derulat rândul până la PgDn sau ~ */}
      <div className="flex shrink-0 gap-1 border-r border-ink-800 pr-1">
        <button
          className={modCls(ctrl)}
          onMouseDown={(e) => e.preventDefault()} // nu fura focusul terminalului
          onClick={() => setCtrl(!ctrl)}
          aria-pressed={ctrl}
          aria-label={t('keybar.ctrl')}
        >
          Ctrl
        </button>
        <button
          className={modCls(alt)}
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => setAlt(!alt)}
          aria-pressed={alt}
          aria-label={t('keybar.alt')}
        >
          Alt
        </button>
      </div>
      <div className="flex min-w-0 flex-1 gap-1 overflow-x-auto">
        {/* lipirea e aici, lângă degete — toolbar-ul de sus e departe când tastezi */}
        <button
          title={t('keybar.paste')}
          aria-label={t('keybar.paste')}
          className="wt-touch shrink-0 rounded-md bg-ink-800 px-2.5 py-1 text-xs text-slate-300 active:bg-ink-600"
          onMouseDown={(e) => e.preventDefault()} // tastatura virtuală rămâne deschisă
          onClick={props.onPaste}
        >
          ⎘
        </button>
        {keys.map((k) => (
          <button
            key={k.label}
            aria-label={ariaOf(k)}
            className="wt-touch shrink-0 rounded-md bg-ink-800 px-2.5 py-1 text-xs text-slate-300 active:bg-ink-600"
            onMouseDown={(e) => e.preventDefault()} // tastatura virtuală rămâne deschisă
            onClick={() => {
              props.onKeys(k.wheel ? k.seq : applyMods(k.seq, ctrl, alt))
              // modificatorii se consumă la ORICE apăsare — altfel rămân aprinşi
              // după o tastă nemascabilă (Esc, săgeți) și lovesc pe neașteptate
              // următoarea apăsare de '|' sau '~'
              if (ctrl) setCtrl(false)
              if (alt) setAlt(false)
            }}
          >
            {k.label}
          </button>
        ))}
      </div>
    </div>
  )
}
