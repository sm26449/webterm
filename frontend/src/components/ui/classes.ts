/* Clasele de bază ale design system-ului (docs/design/DESIGN-SYSTEM.md). O singură sursă pentru
   butoane, câmpuri, titluri de secţiune şi carduri — componentele din ui/ le folosesc, iar locurile
   unde un <button> nativ trebuie să rămână (ex. `<a>` stilizat ca buton) pot lua clasa direct.

   Auditul UI (2026-10, §2-3) a numărat ~60 de combinaţii de clase pentru acelaşi buton: raze,
   padding şi culori hover alese din ochi. Regulile de aici:
   - fundalurile pline sunt alese ca albul să treacă AA: sky-600 (6,3:1), rose-600 (4,7:1);
     hover-ul merge spre ÎNCHIS (sky-700/rose-700) — `hover:bg-sky-500` cădea la 4,47:1;
   - raza unui control e `rounded-md` (6px), a unui card `rounded-xl`, a unui dialog `rounded-2xl`;
   - `disabled:` scade opacitatea (exceptat de WCAG 1.4.3) şi scoate cursorul de click.
   ATENŢIE la `className` suplimentar: Tailwind NU rezolvă conflictele după ordinea din atribut
   (`px-3` + `px-4` = câştigă cel generat ultimul în CSS). Pe componente se adaugă doar clase de
   aşezare (margini, lăţime, flex), nu padding/culori — pentru acelea există variant/size. */

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'
export type ButtonSize = 'sm' | 'md' | 'lg'

const BTN_BASE =
  'inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors ' +
  'disabled:cursor-not-allowed disabled:opacity-50'

const BTN_SIZE: Record<ButtonSize, string> = {
  sm: 'px-2 py-1 text-xs',
  md: 'px-3 py-1.5 text-sm',
  lg: 'px-4 py-2 text-sm',     // acţiunea principală a unui ecran gol / a unui dialog
}

const BTN_VARIANT: Record<ButtonVariant, string> = {
  primary: 'bg-sky-600 text-white hover:bg-sky-700',
  secondary: 'bg-ink-800 text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700',
  danger: 'bg-rose-600 text-white hover:bg-rose-700',
  ghost: 'text-slate-400 hover:bg-ink-800 hover:text-slate-200',
}

export function buttonClass(variant: ButtonVariant = 'secondary', size: ButtonSize = 'md'): string {
  return `${BTN_BASE} ${BTN_SIZE[size]} ${BTN_VARIANT[variant]}`
}

/** scurtături pentru locurile care au nevoie doar de string (ex. `<label>` stilizat ca buton) */
export const btn = {
  primary: buttonClass('primary'),
  secondary: buttonClass('secondary'),
  danger: buttonClass('danger'),
  ghost: buttonClass('ghost'),
} as const

export type IconButtonSize = 'sm' | 'md'
export type IconButtonVariant = 'ghost' | 'subtle' | 'danger'

const ICON_SIZE: Record<IconButtonSize, string> = {
  // min-w (nu w fix): pătrat cu o pictogramă, se lăţeşte pentru un glif + contor („❯12", „A+")
  sm: 'h-6 min-w-6 px-1',       // 24px — minimul WCAG 2.5.8; sub `pointer: coarse` .wt-touch îl duce la 44px
  md: 'h-8 min-w-8 px-1.5',
}

const ICON_VARIANT: Record<IconButtonVariant, string> = {
  ghost: 'text-slate-400 hover:bg-ink-800 hover:text-slate-200',
  subtle: 'bg-ink-800 text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 hover:text-slate-100',
  // distructiv: neutru în repaus (nu strigă pe fiecare rând), roşu la hover/focus
  danger: 'text-slate-400 hover:bg-ink-800 hover:text-danger focus-visible:text-danger',
}

export function iconButtonClass(variant: IconButtonVariant = 'ghost', size: IconButtonSize = 'sm', touch = true): string {
  return `${touch ? 'wt-touch ' : ''}grid shrink-0 place-items-center rounded-md transition-colors ` +
    `disabled:cursor-not-allowed disabled:opacity-40 ${ICON_SIZE[size]} ${ICON_VARIANT[variant]}`
}

/** acţiune text COMPACTĂ în rânduri dense (rândurile de transfer: Retry · Pause · Cancel…): 24px,
    44px la touch prin .wt-touch. Culoarea o dă locul (`wt-info`, `wt-danger`, `text-slate-300`). */
export const compactAction =
  'wt-touch inline-flex h-6 min-w-6 shrink-0 items-center justify-center rounded-md px-1.5 text-2xs font-medium ' +
  'hover:bg-ink-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400'

/** titlul de secţiune („eyebrow"): mic, majuscule, estompat — UN singur tratament */
export const eyebrow = 'text-xs font-semibold uppercase tracking-wide text-slate-500'

/** suprafaţa unui card: rază de card, contur fin, fundal uşor ridicat */
export const cardClass = 'rounded-xl border border-ink-700/70 bg-ink-800/40'
