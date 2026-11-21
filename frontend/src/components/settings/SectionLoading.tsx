import { useI18n } from '../../lib/i18n'

/** Scheletul unei secţiuni de Setări care se încarcă (3.7.1, auditul UX Setări Mi6). Înainte era un
    „loading…" gri de 12 px, uşor de confundat cu un câmp gol; acum trei bare care au forma
    conţinutului care vine, plus textul pentru cititorul de ecran (`role="status"`, anunţat o dată).
    Pulsul se opreşte cu `prefers-reduced-motion`. */
export default function SectionLoading(props: { rows?: number; className?: string }) {
  const { t } = useI18n()
  const rows = props.rows ?? 3
  return (
    <div role="status" aria-busy="true" data-testid="settings-loading"
      className={`flex flex-col gap-2${props.className ? ` ${props.className}` : ''}`}>
      <span className="sr-only">{t('settings.loading')}</span>
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} aria-hidden="true"
          className={`block h-3 rounded-md bg-ink-700/70 animate-pulse motion-reduce:animate-none ${
            i === 0 ? 'w-2/3' : i % 2 ? 'w-full' : 'w-5/6'}`} />
      ))}
    </div>
  )
}
