import { useRef, type KeyboardEvent, type ReactNode } from 'react'

/** Alegerea UNEIA dintre câteva opţiuni (Off · Daily · Weekly, Google Drive · SFTP…) — 3.7.1,
    auditul UX Setări M7. Înainte, opţiunea aleasă purta umplerea butonului PRIMAR (`bg-sky-600`),
    deci „Off" arăta exact ca „Download encrypted backup", iar acţiunea reală nu se mai distingea.
    Aici „ales" = suprafaţă ridicată + inel de accent; umplerea primară rămâne doar a lui Button.

    Semantica e tiparul ARIA radio group: `role="radiogroup"` cu nume, opţiuni `role="radio"` +
    `aria-checked`, un singur tab-stop (roving tabindex: opţiunea aleasă, altfel prima activă);
    săgeţile mută focusul ŞI aleg (ca la radio-urile native), Home/End sar la capete. */
export type SegmentedOption<T extends string> = { value: T; label: ReactNode; disabled?: boolean }

/** indexul la care duce o tastă, sau null dacă tasta nu e a noastră. Opţiunile dezactivate sunt
    sărite; săgeţile se rotesc la capete. Pur, ca să fie testat fără DOM. */
export function segmentedKeyTarget(key: string, current: number, enabled: readonly boolean[]): number | null {
  const n = enabled.length
  if (!n || !enabled.some(Boolean)) return null
  const step = (from: number, dir: 1 | -1) => {
    let i = from
    for (let k = 0; k < n; k++) {
      i = (i + dir + n) % n
      if (enabled[i]) return i
    }
    return from
  }
  switch (key) {
    case 'ArrowRight': case 'ArrowDown': return step(current, 1)
    case 'ArrowLeft': case 'ArrowUp': return step(current, -1)
    case 'Home': return step(-1 + n, 1)        // prima activă
    case 'End': return step(0, -1)             // ultima activă
    default: return null
  }
}

export default function SegmentedControl<T extends string>(props: {
  /** numele grupului pentru cititorul de ecran, dacă nu există o etichetă vizibilă (`labelledBy`) */
  label?: string
  labelledBy?: string
  describedBy?: string
  value: T | null | undefined
  options: readonly SegmentedOption<T>[]
  onChange: (value: T) => void
  disabled?: boolean
  className?: string
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const enabled = props.options.map((o) => !props.disabled && !o.disabled)
  const sel = props.options.findIndex((o) => o.value === props.value)
  // un singur tab-stop: opţiunea aleasă; fără alegere (sau aleasă dar dezactivată), prima activă
  const tabStop = sel >= 0 && enabled[sel] ? sel : enabled.indexOf(true)

  const onKey = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    const to = segmentedKeyTarget(e.key, i, enabled)
    if (to === null) return
    e.preventDefault()
    refs.current[to]?.focus()
    if (to !== sel) props.onChange(props.options[to].value)
  }

  return (
    <div role="radiogroup" aria-label={props.labelledBy ? undefined : props.label}
      aria-labelledby={props.labelledBy} aria-describedby={props.describedBy}
      aria-disabled={props.disabled || undefined}
      className={`inline-flex max-w-full flex-wrap gap-1 rounded-md bg-ink-900/60 p-1 ring-1 ring-ink-700${
        props.className ? ` ${props.className}` : ''}`}>
      {props.options.map((o, i) => {
        const on = i === sel
        return (
          <button key={o.value} type="button" role="radio" aria-checked={on}
            ref={(el) => { refs.current[i] = el }}
            tabIndex={i === tabStop ? 0 : -1}
            disabled={!enabled[i]}
            onClick={() => { if (!on) props.onChange(o.value) }}
            onKeyDown={(e) => onKey(e, i)}
            className={`wt-touch inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1 text-sm transition-colors `
              + 'disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400 '
              + (on
                ? 'bg-ink-700 font-medium text-slate-100 shadow-sm ring-1 ring-sky-500'
                : 'text-slate-400 hover:bg-ink-800 hover:text-slate-200')}>
            {o.label}
          </button>
        )
      })}
    </div>
  )
}
