import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { iconButtonClass, type IconButtonSize, type IconButtonVariant } from './classes'

/** Buton doar cu pictogramă. `label` e OBLIGATORIU: devine `aria-label` (numele accesibil — o
    pictogramă singură nu spune nimic unui cititor de ecran) şi `title` (tooltip-ul global din
    TooltipLayer). `title` se poate da separat când tooltip-ul diferă de nume (ex. numele include
    fişierul: „Şterge raport.pdf", tooltip-ul doar „Şterge").

    Ţinta: 24px (`sm`, minimul WCAG 2.5.8) sau 32px (`md`); cu `touch` (implicit) primeşte
    `.wt-touch`, care o duce la 44px sub `pointer: coarse` (index.css). `touch={false}` doar în
    rânduri dense unde 44px ar sparge rândul şi există altă cale către acţiune.

    `active` (3.6.3, U24) = starea activă/selectată (panou deschis, comutator pornit): accent pe fundal
    ridicat, în locul culorii variantei. Doar vizual — `aria-pressed` / `aria-expanded` le pune locul,
    fiindcă numai el ştie dacă butonul e un comutator sau deschide ceva. `className` = doar aşezare
    (garda din design.guard.test.ts pică pe culori/fundal/font/padding).

    Ca la Button, `type` nu are valoare implicită (vezi comentariul de acolo). */
export type IconButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> & {
  label: string
  variant?: IconButtonVariant
  size?: IconButtonSize
  touch?: boolean
  active?: boolean
  children: ReactNode
}

const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, title, variant = 'ghost', size = 'sm', touch = true, active = false, className, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      {...rest}
      aria-label={label}
      title={title ?? label}
      className={`${iconButtonClass(variant, size, touch, active)}${className ? ` ${className}` : ''}`}
    >
      {children}
    </button>
  )
})

export default IconButton
