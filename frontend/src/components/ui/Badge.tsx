import type { HTMLAttributes, ReactNode } from 'react'

/** Insignă mică (contor, stare, etichetă). Tonurile folosesc tokenii semantici (`text-ok` &
    co.) pe o tentă de 10 % din aceeaşi culoare — combinaţia trece AA pe suprafeţele ambelor teme.
    Culoarea nu e niciodată singurul semnal (WCAG 1.4.1): textul insignei spune starea. */
export type BadgeTone = 'neutral' | 'ok' | 'warn' | 'danger' | 'info' | 'accent'

const TONE: Record<BadgeTone, string> = {
  neutral: 'bg-ink-700 text-slate-300',
  ok: 'bg-ok/10 text-ok',
  warn: 'bg-warn/10 text-warn',
  danger: 'bg-danger/10 text-danger',
  info: 'bg-info/10 text-info',
  accent: 'wt-chip-accent',
}

/** `sm` = contor/etichetă inline (implicit); `md` = pilulă de sine stătătoare (rol, „doar citire"),
    cu puţin aer vertical. Mărimea textului rămâne text-2xs — insigna repetă o stare, nu e corp de text. */
export type BadgeSize = 'sm' | 'md'
const SIZE: Record<BadgeSize, string> = { sm: 'px-1.5', md: 'px-2 py-0.5' }

/** `caps`: majuscule spaţiate, pentru tipuri scurte („SSH", „ACTUALIZARE") — nu pentru propoziţii */
export function badgeClass(tone: BadgeTone = 'neutral', size: BadgeSize = 'sm', caps = false): string {
  return `inline-flex shrink-0 items-center gap-1 rounded-full text-2xs font-semibold ${SIZE[size]}`
    + `${caps ? ' uppercase tracking-wide' : ''} ${TONE[tone]}`
}

export default function Badge(props: HTMLAttributes<HTMLSpanElement> & {
  tone?: BadgeTone; size?: BadgeSize; caps?: boolean; children: ReactNode
}) {
  const { tone, size, caps, className, children, ...rest } = props
  return (
    <span {...rest} className={`${badgeClass(tone, size, caps)}${className ? ` ${className}` : ''}`}>
      {children}
    </span>
  )
}
