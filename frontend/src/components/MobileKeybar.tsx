import { useState } from 'react'
import { useI18n } from '../lib/i18n'

const WHEEL_UP = '\x1b[<64;40;10M'.repeat(3) // rapoarte SGR de rotiță: tmux
const WHEEL_DOWN = '\x1b[<65;40;10M'.repeat(3) // derulează istoricul (copy-mode)

const KEYS: Array<{ label: string; seq: string }> = [
  { label: '⇞', seq: WHEEL_UP },
  { label: '⇟', seq: WHEEL_DOWN },
  { label: 'Esc', seq: '\x1b' },
  { label: 'Tab', seq: '\t' },
  { label: '↑', seq: '\x1b[A' },
  { label: '↓', seq: '\x1b[B' },
  { label: '←', seq: '\x1b[D' },
  { label: '→', seq: '\x1b[C' },
  { label: '^C', seq: '\x03' },
  { label: '^D', seq: '\x04' },
  { label: '^Z', seq: '\x1a' },
  { label: '^R', seq: '\x12' },
  { label: '|', seq: '|' },
  { label: '/', seq: '/' },
  { label: '-', seq: '-' },
  { label: '~', seq: '~' },
]

/** Extra keys row for touch keyboards; hidden on desktop. */
export default function MobileKeybar(props: {
  onKeys: (seq: string) => void
  onPaste: () => void
  backend?: string | null
}) {
  const { t } = useI18n()
  const [ctrl, setCtrl] = useState(false)
  // ⇞/⇟ injectează rapoarte de rotiță SGR pe care doar tmux le interpretează;
  // pe backend „pty" (fără tmux) octeții ar ajunge tastați în shell ca gunoi
  const keys = props.backend === 'tmux' ? KEYS : KEYS.filter((k) => k.label !== '⇞' && k.label !== '⇟')

  return (
    <div className="flex gap-1 overflow-x-auto border-t border-ink-800 bg-ink-900 px-2 pb-[max(0.375rem,env(safe-area-inset-bottom))] pt-1.5 md:hidden">
      <button
        className={`wt-touch shrink-0 rounded-md px-2.5 py-1 text-xs font-medium ${
          ctrl ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-300'
        }`}
        onMouseDown={(e) => e.preventDefault()} // nu fura focusul terminalului
        onClick={() => setCtrl(!ctrl)}
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
