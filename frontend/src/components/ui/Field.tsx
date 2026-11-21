import { cloneElement, isValidElement, useId, type AriaAttributes, type ReactElement, type ReactNode } from 'react'

type ControlProps = { id?: string } & Pick<AriaAttributes, 'aria-describedby' | 'aria-invalid'>

/** Un câmp de formular cu etichetă VIZIBILĂ deasupra, indiciu dedesubt şi eroare opţională
    (3.7.1, auditul UX Setări M8). Înainte, placeholder-ul ţinea loc de etichetă: după completare
    câmpul nu mai spunea ce conţine, iar pe Backup cinci câmpuri de parolă arătau identic.
    Placeholder-ul poate rămâne doar ca EXEMPLU („backup.example.com"), niciodată ca singurul nume.

    Copilul (input / select / textarea) primeşte `id`, `aria-describedby` (indiciul + eroarea,
    adăugate la ce avea deja) şi `aria-invalid` când există eroare. Un `id` pus de apelant pe copil
    e păstrat. `label` vine deja tradus. `inline` pune eticheta la stânga (câmpuri numerice scurte:
    „Keep the last [14]"). */
export default function Field(props: {
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  inline?: boolean
  className?: string
  children: ReactElement<ControlProps>
}) {
  const auto = useId()
  const child = props.children
  const childId = isValidElement(child) && child.props.id ? child.props.id : `f${auto}`
  const hintId = props.hint ? `${childId}-hint` : undefined
  const errId = props.error ? `${childId}-err` : undefined
  const prev = child.props['aria-describedby']
  const describedBy = [prev, hintId, errId].filter(Boolean).join(' ') || undefined
  const control = cloneElement<ControlProps>(child, {
    id: childId,
    'aria-describedby': describedBy,
    'aria-invalid': props.error ? true : child.props['aria-invalid'],
  })
  const label = (
    <label htmlFor={childId} className={`text-sm font-medium text-slate-300${props.inline ? ' shrink-0' : ''}`}>
      {props.label}
    </label>
  )
  return (
    <div className={`flex flex-col gap-1${props.className ? ` ${props.className}` : ''}`}>
      {props.inline ? <div className="flex items-center gap-2">{label}{control}</div> : <>{label}{control}</>}
      {props.hint && <p id={hintId} className="text-xs text-slate-500">{props.hint}</p>}
      {props.error && <p id={errId} className="text-xs wt-danger">{props.error}</p>}
    </div>
  )
}
