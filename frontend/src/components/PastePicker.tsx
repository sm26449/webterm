import { useEffect, useRef, useState } from 'react'
import type { ClipEntry } from '../lib/cliphistory'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

// Paste picker: history-ul de clipboard GLOBAL — ce s-a copiat din ORICE terminal al ferestrei
// (Cmd+Shift+V / buton / click-dreapta), cu sursa şi vârsta sub fiecare intrare.
// Intrarea #0 = ultima copiere, preselectată — deci deschide + Enter = „lipeşte ultima". Paste
// normal = doar inserează (bracketed, sigur); „Paste & run" (⏎) lipeşte ŞI apasă Enter — opt-in,
// clar marcat, fiindcă auto-execuţia e exact ce previne bracketed paste. ✕ scoate o intrare,
// „Clear history" le scoate pe toate (history-ul ţine des secrete).
export default function PastePicker(props: {
  items: ClipEntry[]
  onPaste: (text: string) => void
  onPasteRun: (text: string) => void
  onRemove: (text: string) => void
  onClear: () => void
  onClose: () => void
}) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [sel, setSel] = useState(0)
  // după ✕ lista se scurtează: selecţia nu rămâne după capăt
  const cur = Math.min(sel, Math.max(props.items.length - 1, 0))

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); setSel(Math.min(cur + 1, props.items.length - 1)) }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(Math.max(cur - 1, 0)) }
      else if (e.key === 'Enter') {
        // Enter pe ✕ / „Clear history" (ajunse prin Tab) îşi face treaba lor, nu lipeşte
        if ((e.target as HTMLElement | null)?.closest?.('[data-pp-own-enter]')) return
        e.preventDefault()
        const text = props.items[cur]?.text
        if (text != null) (e.shiftKey ? props.onPasteRun : props.onPaste)(text)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [cur, props])

  const preview = (s: string) => s.replace(/\s+/g, ' ').trim().slice(0, 120) || t('paste.blank')
  // ✕ / „Clear" demontează butonul focusat: ducem focusul înapoi în dialog (nu pe <body>)
  const refocus = () => requestAnimationFrame(() => {
    const el = dialogRef.current
    if (!el) return
    const btn = el.querySelector<HTMLElement>('ul button')
    if (btn) btn.focus()
    else { el.setAttribute('tabindex', '-1'); el.focus() }
  })
  // vârsta: TTL-ul e 1 h, deci minutele ajung (sub un minut = „acum")
  const ago = (at: number) => {
    const m = Math.floor((Date.now() - at) / 60_000)
    return m < 1 ? t('paste.agoNow') : t('paste.agoMin', { m })
  }

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
        <p className="border-b border-ink-800 px-4 py-1.5 text-[11px] text-slate-500">{t('paste.sharedNote')}</p>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {props.items.length === 0
            ? <p className="px-2 py-8 text-center text-sm text-slate-500">{t('paste.empty')}</p>
            : <ul className="space-y-1">
                {props.items.map((item, i) => (
                  <li key={item.at + ':' + i}
                      className={`flex items-center gap-1 rounded-lg ${i === cur ? 'bg-ink-800 ring-1 ring-sky-500/50' : ''}`}
                      onMouseEnter={() => setSel(i)}>
                    <button
                      onClick={() => props.onPaste(item.text)}
                      title={t('paste.pasteTitle')}
                      className="min-w-0 flex-1 px-2.5 py-1.5 text-left text-sm text-slate-200"
                    >
                      <span className="block truncate">
                        <span className="mr-2 text-[11px] text-slate-500">{i === 0 ? t('paste.last') : `#${i + 1}`}</span>
                        {preview(item.text)}
                      </span>
                      <span className="pp-source block truncate text-[11px] text-slate-500">
                        {(item.label || t('paste.sourceFallback')) + ' · ' + ago(item.at)}
                      </span>
                    </button>
                    <button
                      onClick={() => props.onPasteRun(item.text)}
                      title={t('paste.pasteRunTitle')}
                      className="wt-touch shrink-0 rounded-md px-2 py-1.5 text-[11px] font-medium wt-warn hover:bg-ink-700"
                    >
                      ⏎ {t('paste.run')}
                    </button>
                    <button
                      data-pp-own-enter
                      onClick={() => { props.onRemove(item.text); refocus() }}
                      title={t('paste.remove')}
                      aria-label={t('paste.removeAria', { item: preview(item.text).slice(0, 40) })}
                      className="wt-touch mr-1 flex h-7 min-w-7 shrink-0 items-center justify-center rounded-md px-1.5 text-xs text-slate-400 hover:bg-ink-700 hover:text-slate-100"
                    >
                      <span aria-hidden="true">✕</span>
                    </button>
                  </li>
                ))}
              </ul>}
        </div>
        {props.items.length > 0 && (
          <div className="flex justify-end border-t border-ink-800 px-3 py-2">
            <button
              data-pp-own-enter
              onClick={() => { props.onClear(); refocus() }}
              className="wt-touch min-h-7 rounded-md px-2.5 py-1 text-xs text-slate-400 hover:bg-ink-700 hover:text-slate-100"
            >
              {t('paste.clear')}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
