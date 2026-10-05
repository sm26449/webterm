import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'

const WHEEL_UP = '\x1b[<64;40;10M'.repeat(3) // rapoarte SGR de rotiță: tmux
const WHEEL_DOWN = '\x1b[<65;40;10M'.repeat(3) // derulează istoricul (copy-mode)

// `aria`: eticheta citită de cititorul de ecran — glifele (⇞ ↑ ^C |) sunt mute sau citite
// ca „caret C". Cheie de catalog (`keybar.*`) sau text neutru (Escape/Tab/Ctrl+C sunt la fel
// în orice limbă).
const KEYS: Array<{ label: string; seq: string; aria: string }> = [
  { label: '⇞', seq: WHEEL_UP, aria: 'keybar.scrollUp' },
  { label: '⇟', seq: WHEEL_DOWN, aria: 'keybar.scrollDown' },
  { label: 'Esc', seq: '\x1b', aria: 'Escape' },
  { label: 'Tab', seq: '\t', aria: 'Tab' },
  { label: '↑', seq: '\x1b[A', aria: 'keybar.up' },
  { label: '↓', seq: '\x1b[B', aria: 'keybar.down' },
  { label: '←', seq: '\x1b[D', aria: 'keybar.left' },
  { label: '→', seq: '\x1b[C', aria: 'keybar.right' },
  { label: '^C', seq: '\x03', aria: 'Ctrl+C' },
  { label: '^D', seq: '\x04', aria: 'Ctrl+D' },
  { label: '^Z', seq: '\x1a', aria: 'Ctrl+Z' },
  { label: '^R', seq: '\x12', aria: 'Ctrl+R' },
  { label: '|', seq: '|', aria: 'keybar.pipe' },
  { label: '/', seq: '/', aria: 'keybar.slash' },
  { label: '-', seq: '-', aria: 'keybar.dash' },
  { label: '~', seq: '~', aria: 'keybar.tilde' },
]

/** Extra keys row for touch keyboards; hidden on desktop. */
export default function MobileKeybar(props: {
  onKeys: (seq: string) => void
  onPaste: () => void
  backend?: string | null
}) {
  const { t } = useI18n()
  const [ctrl, setCtrl] = useState(false)
  // Publicăm înălţimea reală a keybar-ului în `--wt-keybar-h` (pe <html>), ca widgetul plutitor
  // de transferuri — portat în <body>, deci fără acces la acest DOM — să se aşeze DEASUPRA lui pe
  // mobil şi să nu acopere niciodată tastatura de comenzi. ResizeObserver: înălţimea variază cu
  // safe-area-inset şi cu wrap-ul. La demontare (desktop / fără sesiune vie) o resetăm → widgetul
  // coboară la marginea de jos.
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
  const keys = props.backend === 'tmux' ? KEYS : KEYS.filter((k) => k.label !== '⇞' && k.label !== '⇟')
  const ariaOf = (k: { aria: string; seq: string }) => {
    const base = k.aria.startsWith('keybar.') ? t(k.aria) : k.aria
    // cu Ctrl aprins, tasta mascabilă devine Ctrl+<tastă> — eticheta spune ce se va trimite
    return ctrl && k.seq.length === 1 && k.seq >= '@' ? `Ctrl+${k.seq}` : base
  }

  return (
    <div ref={rootRef} className="flex gap-1 overflow-x-auto border-t border-ink-800 bg-ink-900 px-2 pb-[max(0.375rem,env(safe-area-inset-bottom))] pt-1.5 md:hidden">
      <button
        className={`wt-touch shrink-0 rounded-md px-2.5 py-1 text-xs font-medium ${
          ctrl ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-300'
        }`}
        onMouseDown={(e) => e.preventDefault()} // nu fura focusul terminalului
        onClick={() => setCtrl(!ctrl)}
        aria-pressed={ctrl}
        aria-label={t('keybar.ctrl')}
      >
        Ctrl
      </button>
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
            if (ctrl && k.seq.length === 1 && k.seq >= '@') {
              // Ctrl+<key>: mask to control character
              props.onKeys(String.fromCharCode(k.seq.toUpperCase().charCodeAt(0) & 0x1f))
            } else {
              props.onKeys(k.seq)
            }
            // modificatorul se consumă la ORICE apăsare — altfel rămâne aprins
            // după o tastă nemascabilă (Esc, săgeți) și lovește pe neașteptate
            // următoarea apăsare de '|' sau '~'
            if (ctrl) setCtrl(false)
          }}
        >
          {k.label}
        </button>
      ))}
    </div>
  )
}
