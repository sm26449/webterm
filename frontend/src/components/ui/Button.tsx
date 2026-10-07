import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { buttonClass, type ButtonSize, type ButtonVariant } from './classes'
import { Spinner } from './Spinner'

/** Butonul cu text al aplicaţiei. Patru intenţii (primary · secondary · danger · ghost), trei
    mărimi. `loading` arată un spinner, dezactivează butonul şi anunţă `aria-busy`, fără să-i schimbe
    lăţimea (textul rămâne).

    `type` NU primeşte implicit: un <button> fără tip într-un <form> e „submit", iar migrarea
    butoanelor existente pe componentă nu trebuie să schimbe ce face Enter într-un formular.
    Pentru butoane noi, scrie `type="button"` sau `type="submit"` explicit. */
export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', loading = false, disabled, className, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      {...rest}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`${buttonClass(variant, size)}${className ? ` ${className}` : ''}`}
    >
      {loading && <Spinner />}
      {children}
    </button>
  )
})

export default Button
