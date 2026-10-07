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

export function badgeClass(tone: BadgeTone = 'neutral'): string {
  return `inline-flex shrink-0 items-center gap-1 rounded-full px-1.5 text-2xs font-semibold ${TONE[tone]}`
}

export default function Badge(props: HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone; children: ReactNode }) {
  const { tone, className, children, ...rest } = props
  return (
    <span {...rest} className={`${badgeClass(tone)}${className ? ` ${className}` : ''}`}>
      {children}
    </span>
  )
}
