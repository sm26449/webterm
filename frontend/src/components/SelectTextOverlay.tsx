import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { cleanSelection } from '../lib/seltext'
import { CloseIcon, CopyIcon } from './Icons'
import { Button, IconButton } from './ui'

/** Modul „Selectează text" (3.6.32): textul terminalului ca text NATIV, peste panoul terminalului.

    xterm.js nu are selecţie pe touch (degetul derulează, apăsarea lungă deschide meniul), deci pe
    telefon nu se putea copia o bucată de output. Aici selecţia o face BROWSERUL: apăsare lungă pe
    un cuvânt, mânerele sistemului, „Copy" din bula sistemului sau butonul „Copiază" de sus.

    E un INSTANTANEU luat la deschidere (liniile logice din lib/seltext) — terminalul de dedesubt
    merge mai departe, dar textul nu-ţi fuge de sub deget cât selectezi.

    Nu e modal: stă în panoul terminalului (`absolute inset-0` în containerul lui), deci în split
    view acoperă doar panoul lui. Escape şi butonul X îl închid. */
export default function SelectTextOverlay(props: {
  lines: string[]
  background: string
  foreground: string
  fontSize: number
  /** copiază (clipboard + istoricul de clipboard al sesiunii); true = a reuşit */
  onCopy: (text: string) => Promise<boolean>
  /** copiere făcută de BROWSER (bula sistemului / Ctrl+C): textul e deja în clipboard */
  onNativeCopy: (text: string) => void
  onClose: () => void
}) {
  const { t } = useI18n()
  const rootRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const preRef = useRef<HTMLPreElement>(null)
  // selecţia curentă DIN textul nostru; `held` = ce era selectat când degetul a atins butonul
  // (pe iOS atingerea unui buton poate goli selecţia înainte de `click`)
  const [selected, setSelected] = useState('')
  const held = useRef('')

  const readSelection = (): string => {
    const s = window.getSelection()
    const pre = preRef.current
    if (!s || !pre || s.isCollapsed || !s.anchorNode || !s.focusNode) return ''
    if (!pre.contains(s.anchorNode) || !pre.contains(s.focusNode)) return ''
    return cleanSelection(s.toString())
  }

  useEffect(() => {
    const onSel = () => setSelected(readSelection())
    document.addEventListener('selectionchange', onSel)
    return () => document.removeEventListener('selectionchange', onSel)
  }, [])

  // la deschidere: jos de tot (acolo e promptul şi ultimul output), focusul pe foaie — iese din
  // textarea xterm-ului, deci tastatura virtuală se strânge şi rămâne loc de text
  useLayoutEffect(() => {
    const sc = scrollRef.current
    if (sc) sc.scrollTop = sc.scrollHeight
    rootRef.current?.focus({ preventScroll: true })
  }, [])

  const copy = async () => {
    const text = held.current || readSelection()
    held.current = ''
    if (!text) return
    if (await props.onCopy(text)) props.onClose()
  }

  const text = props.lines.join('\n')
  return (
    <div
      ref={rootRef}
      role="dialog"
      aria-label={t('seltext.title')}
      tabIndex={-1}
      data-testid="wt-seltext"
      className="absolute inset-0 z-20 flex flex-col outline-none"
      style={{ background: props.background }}
      // containerul terminalului are long-press → meniu contextual şi `contextmenu` anulat: aici
      // apăsarea lungă e gestul de SELECŢIE al sistemului, iar meniul nativ e cel cu „Copy"
      onPointerDown={(e) => e.stopPropagation()}
      onContextMenu={(e) => e.stopPropagation()}
      onKeyDown={(e) => {
        if (e.key === 'Escape') { e.stopPropagation(); props.onClose() }
      }}
    >
      <div className="flex shrink-0 items-center gap-2 border-b border-ink-800 bg-ink-900 px-2 py-1.5">
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium text-slate-200">{t('seltext.title')}</div>
          <div className="text-xs text-slate-400">{t('seltext.hint')}</div>
        </div>
        <Button
          type="button"
          variant="primary"
          size="sm"
          className="wt-touch shrink-0"
          disabled={!selected}
          data-testid="wt-seltext-copy"
          // prinde selecţia ÎNAINTE ca atingerea s-o poată goli şi nu lăsa butonul să ia focusul
          onPointerDown={(e) => { held.current = readSelection(); e.preventDefault() }}
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => { void copy() }}
        >
          <CopyIcon /> {t('session.copy')}
        </Button>
        <IconButton type="button" label={t('common.close')} className="shrink-0" onClick={props.onClose}>
          <CloseIcon size={14} />
        </IconButton>
      </div>
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto overscroll-contain px-1.5 py-1">
        {text ? (
          <pre
            ref={preRef}
            className="m-0 select-text whitespace-pre-wrap [overflow-wrap:anywhere]"
            style={{
              color: props.foreground,
              fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, monospace',
              fontSize: props.fontSize,
              lineHeight: 1.35,
              WebkitUserSelect: 'text',
              userSelect: 'text',
              WebkitTouchCallout: 'default',
            }}
            onCopy={(e) => {
              // bula sistemului / Ctrl+C: punem în clipboard textul CURĂŢAT (fără NBSP), nu ce
              // serializează browserul, şi îl trecem în istoricul de clipboard
              const sel = readSelection()
              if (!sel) return
              e.preventDefault()
              e.clipboardData.setData('text/plain', sel)
              props.onNativeCopy(sel)
            }}
          >
            {text}
          </pre>
        ) : (
          <p className="px-2 py-6 text-center text-sm text-slate-500">{t('seltext.empty')}</p>
        )}
      </div>
    </div>
  )
}
