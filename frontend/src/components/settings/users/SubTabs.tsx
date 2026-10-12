import { KeyboardEvent, useRef } from 'react'
import { tabListNav } from '../../../lib/tablist'
import { Badge } from '../../ui'

/* Tablist-ul sub-tab-urilor din Users & roles (3.6.6). Acelaşi aspect ca tablist-ul din AiToolsPanel
   (pastile mici, cea activă pe ink-700), cu tastatura din TabBar (roving tabindex, ←/→ cu wrap,
   Home/End) — dar ca WAI-ARIA tabs complet: `role=tab`, `aria-selected`, `aria-controls` spre
   panoul `role=tabpanel`. Activarea e AUTOMATĂ (săgeata şi selectează): panourile sunt deja
   încărcate, comutarea e instantanee.

   Pe telefon bara derulează orizontal în ea însăşi (overflow-x-auto pe tablist, nu pe pagină);
   trei etichete scurte încap la 320px, derularea e doar plasa de siguranţă pentru traduceri lungi. */

export type SubTab<T extends string> = { id: T; label: string; count?: number; warn?: number; warnLabel?: string }

export default function SubTabs<T extends string>(props: {
  tabs: SubTab<T>[]; active: T; onChange: (id: T) => void
  label: string; idPrefix: string
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const onKey = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    if (e.altKey || e.ctrlKey || e.metaKey) return
    const next = tabListNav(e.key, i, props.tabs.length)
    if (next == null) return
    e.preventDefault()
    props.onChange(props.tabs[next].id)
    refs.current[next]?.focus()
  }
  return (
    <div role="tablist" aria-label={props.label} data-users-subtabs
      className="-mx-1 flex gap-1 overflow-x-auto border-b border-ink-800 px-1 pb-2">
      {props.tabs.map((x, i) => {
        const on = x.id === props.active
        return (
          <button key={x.id} ref={(el) => { refs.current[i] = el }} type="button" role="tab"
            id={`${props.idPrefix}-tab-${x.id}`} aria-controls={`${props.idPrefix}-panel-${x.id}`}
            aria-selected={on} tabIndex={on ? 0 : -1} data-subtab={x.id}
            onClick={() => props.onChange(x.id)} onKeyDown={(e) => onKey(e, i)}
            className={`wt-touch flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium ${
              on ? 'border-b-2 border-sky-500 bg-ink-700 text-slate-100' : 'border-b-2 border-transparent text-slate-400 hover:bg-ink-800 hover:text-slate-200'}`}>
            {x.label}
            {x.count != null && <Badge tone={on ? 'accent' : 'neutral'}>{x.count}</Badge>}
            {!!x.warn && (
              <Badge tone="warn" title={x.warnLabel}>
                <span aria-hidden="true">!</span><span className="sr-only">{x.warnLabel}</span>
              </Badge>
            )}
          </button>
        )
      })}
    </div>
  )
}
