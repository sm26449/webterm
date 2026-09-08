import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

// Paste picker: history-ul de clipboard AL ACESTUI terminal (Cmd+Shift+V / buton / click-dreapta).
// Intrarea #0 = ultima copiere, preselectată — deci deschide + Enter = „lipeşte ultima". Paste
// normal = doar inserează (bracketed, sigur); „Paste & run" (⏎) lipeşte ŞI apasă Enter — opt-in,
// clar marcat, fiindcă auto-execuţia e exact ce previne bracketed paste.
export default function PastePicker(props: {
  items: string[]
  onPaste: (text: string) => void
  onPasteRun: (text: string) => void
  onClose: () => void
}) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [sel, setSel] = useState(0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); setSel((i) => Math.min(i + 1, props.items.length - 1)) }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((i) => Math.max(i - 1, 0)) }
      else if (e.key === 'Enter') {
        e.preventDefault()
        const text = props.items[sel]
        if (text != null) (e.shiftKey ? props.onPasteRun : props.onPaste)(text)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [sel, props])

  const preview = (s: string) => s.replace(/\s+/g, ' ').trim().slice(0, 120) || t('paste.blank')

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center bg-black/40 p-4 pt-20"
         onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('paste.title')}
        className="glass flex max-h-[70vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-ink-800 px-4 py-3">
          <h2 className="text-sm font-semibold">{t('paste.title')}</h2>
          <span className="text-[11px] text-slate-500">{t('paste.hint')}</span>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {props.items.length === 0
            ? <p className="px-2 py-8 text-center text-sm text-slate-500">{t('paste.empty')}</p>
            : <ul className="space-y-1">
                {props.items.map((item, i) => (
                  <li key={i}
                      className={`flex items-center gap-1 rounded-lg ${i === sel ? 'bg-ink-800 ring-1 ring-sky-500/50' : ''}`}
                      onMouseEnter={() => setSel(i)}>
                    <button
                      onClick={() => props.onPaste(item)}
                      title={t('paste.pasteTitle')}
                      className="min-w-0 flex-1 truncate px-2.5 py-2 text-left text-sm text-slate-200"
                    >
                      <span className="mr-2 text-[11px] text-slate-500">{i === 0 ? t('paste.last') : `#${i + 1}`}</span>
                      {preview(item)}
                    </button>
                    <button
                      onClick={() => props.onPasteRun(item)}
                      title={t('paste.pasteRunTitle')}
                      className="wt-touch mr-1 shrink-0 rounded-md px-2 py-1.5 text-[11px] font-medium text-amber-300/90 hover:bg-ink-700"
                    >
                      ⏎ {t('paste.run')}
                    </button>
                  </li>
                ))}
              </ul>}
        </div>
      </div>
    </div>
  )
}
