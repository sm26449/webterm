import type { ReactNode } from 'react'

/** Starea „nimic aici încă": pictogramă + titlu + explicaţie + (opţional) acţiunea care o rezolvă.
    E o stare GOALĂ, nu o eroare — pentru „n-am putut încărca" există ErrorState (altfel panoul
    ar minţi că lista e goală).

    - `size="page"` = ecran întreg (dashboard fără hosturi), `inline` = în interiorul unui panou;
    - `framed` = chenar punctat (zona „aici ar sta lista"), pe pagini cu mai multe secţiuni;
    - `tone`: `accent` (implicit) pentru primul pas al unui flux, `neutral` pentru o listă goală;
    - `titleAs` păstrează nivelul de titlu al locului (ex. `h1` pe un ecran gol de pagină). */
export default function EmptyState(props: {
  icon?: ReactNode
  title: ReactNode
  body?: ReactNode
  action?: ReactNode
  size?: 'page' | 'inline'
  tone?: 'accent' | 'neutral'
  framed?: boolean
  titleAs?: 'h1' | 'h2' | 'h3' | 'p'
  className?: string
}) {
  const page = (props.size ?? 'inline') === 'page'
  const Title = props.titleAs ?? 'p'
  const iconTone = (props.tone ?? 'accent') === 'accent' ? 'wt-accent bg-sky-500/15' : 'bg-ink-800 text-slate-500'
  const box = page ? 'gap-4 p-8' : props.framed ? 'gap-3 rounded-xl border border-dashed border-ink-700 px-6 py-10' : 'gap-3 px-4 py-6'
  return (
    <div className={`flex flex-col items-center justify-center text-center ${box}${props.className ? ` ${props.className}` : ''}`}>
      {props.icon && (
        <div className={`grid place-items-center ${iconTone} ${page ? 'h-14 w-14 rounded-2xl' : 'h-11 w-11 rounded-xl [&>svg]:h-5 [&>svg]:w-5'}`} aria-hidden="true">
          {props.icon}
        </div>
      )}
      <div>
        <Title className={page ? 'text-lg font-semibold text-slate-100' : 'text-sm text-slate-500'}>{props.title}</Title>
        {props.body && <p className={`mt-1 max-w-sm text-slate-500 ${page ? 'text-sm' : 'text-xs'}`}>{props.body}</p>}
      </div>
      {props.action}
    </div>
  )
}
