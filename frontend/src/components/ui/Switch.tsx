import { useId, type ReactNode } from 'react'

/** Comutator pornit/oprit care se aplică IMEDIAT (3.7.1, auditul UX Setări M6/Me8): alegerile
    (o preferinţă de alertă, „include transcripturile") se salvează la schimbare; formularele cu
    secrete au un Save al lor. Pe telefon bifele de 16 px din Alert events erau sub ţinta minimă.

    `role="switch"` + `aria-checked` pe un <button> (Space/Enter îl comută nativ). Eticheta e un
    <label for> — un <button> e element etichetabil, deci un clic pe text comută şi el. `.wt-touch`
    duce butonul la 44 px sub `pointer: coarse`; pista vizibilă rămâne mică, centrată în el.
    `ariaLabel` înlocuieşte numele accesibil când eticheta vizibilă e prea scurtă în context (o
    coloană „Email" repetată pe 20 de rânduri → „Email for: Host offline"). `labelVisibility`:
    `hidden` = doar pentru cititorul de ecran (antetul de coloană o spune deja vizual); `mobile` =
    vizibilă pe telefon, unde nu există antet de coloană, ascunsă de la `sm` în sus. */
export default function Switch(props: {
  checked: boolean
  onChange: (checked: boolean) => void
  label: ReactNode
  ariaLabel?: string
  hint?: ReactNode
  describedBy?: string
  disabled?: boolean
  labelVisibility?: 'always' | 'hidden' | 'mobile'
  className?: string
}) {
  const id = `sw${useId()}`
  const hintId = props.hint ? `${id}-hint` : undefined
  const describedBy = [props.describedBy, hintId].filter(Boolean).join(' ') || undefined
  return (
    <div className={`flex flex-col gap-0.5${props.className ? ` ${props.className}` : ''}`}>
      <div className="flex items-center gap-2">
        <button id={id} type="button" role="switch" aria-checked={props.checked}
          aria-label={props.ariaLabel} aria-describedby={describedBy}
          disabled={props.disabled}
          onClick={() => props.onChange(!props.checked)}
          className="wt-touch group inline-flex shrink-0 items-center justify-center rounded-md disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">
          <span aria-hidden="true"
            className={`relative inline-block h-5 w-9 rounded-full ring-1 transition-colors ${
              props.checked ? 'bg-sky-700 ring-sky-500' : 'bg-ink-700 ring-[rgb(var(--field-border))]'}`}>
            <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform ${
              props.checked ? 'translate-x-4' : 'translate-x-0.5'}`} />
          </span>
        </button>
        <label htmlFor={id}
          className={props.labelVisibility === 'hidden' ? 'sr-only'
            : `cursor-pointer text-sm text-slate-300${props.disabled ? ' opacity-60' : ''}${
              props.labelVisibility === 'mobile' ? ' sm:sr-only' : ''}`}>
          {props.label}
        </label>
      </div>
      {props.hint && <p id={hintId} className="text-xs text-slate-500">{props.hint}</p>}
    </div>
  )
}
