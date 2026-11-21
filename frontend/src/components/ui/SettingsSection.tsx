import { useId, type HTMLAttributes, type ReactNode } from 'react'
import { useI18n } from '../../lib/i18n'
import Badge from './Badge'
import { cardClass } from './classes'

/** O secţiune de Setări ca un card (3.7.1, auditul UX Setări Me1/M6/Me3): titlu clar în culoarea
    textului (nu eyebrow-ul gri, majuscule, care făcea titlurile să arate ca etichete), o propoziţie
    de descriere, insigna „Instance-wide" când setarea priveşte toată instanţa, corpul şi un subsol
    opţional pentru UN singur Save, cu starea „Unsaved changes".

    `tone="danger"` = zona periculoasă (restaurare, ştergeri): contur roşu, aşezată ULTIMA în pagină,
    departe de acţiunile banale. `data-setting-id` / `data-testid` / `hidden` trec mai departe pe
    <section> (căutarea din Setări şi testele le caută acolo); `settingsIndex.test.ts` citeşte
    `data-setting-id="…"` ca text din *Tab.tsx, deci apelantul îl scrie literal pe componentă. */
export default function SettingsSection(props: Omit<HTMLAttributes<HTMLElement>, 'title'> & {
  title: ReactNode
  description?: ReactNode
  /** element lângă titlu (ex. <HelpTip/>) */
  titleExtra?: ReactNode
  instanceWide?: boolean
  tone?: 'default' | 'danger'
  footer?: ReactNode
  dirty?: boolean
  /** h3 implicit; h4 când tab-ul are deja titluri de grup (Notifications: Channels · Rules · …) */
  headingLevel?: 3 | 4
  children?: ReactNode
}) {
  const { t } = useI18n()
  const { title, description, titleExtra, instanceWide, tone = 'default', footer, dirty, headingLevel = 3, children, className, ...rest } = props
  const H = headingLevel === 4 ? 'h4' : 'h3'
  const hid = `ss${useId()}`
  const surface = tone === 'danger'
    ? 'rounded-xl border border-rose-500/40 bg-rose-500/5'
    : cardClass
  return (
    <section {...rest} aria-labelledby={hid} className={`${surface} p-4${className ? ` ${className}` : ''}`}>
      <div className="flex flex-wrap items-center gap-2">
        {tone === 'danger' && <Badge tone="danger" caps>{t('ui.section.dangerZone')}</Badge>}
        <H id={hid} className={`text-sm font-semibold ${tone === 'danger' ? 'wt-danger' : 'text-slate-100'}`}>{title}</H>
        {titleExtra}
        {instanceWide && <Badge tone="neutral" size="md">{t('ui.section.instanceWide')}</Badge>}
      </div>
      {description && <p className="mt-1 text-xs text-slate-400">{description}</p>}
      {children && <div className="mt-3">{children}</div>}
      {(footer || dirty) && (
        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-ink-700/70 pt-3">
          {footer}
          {dirty && <span className="text-xs wt-warn">{t('ui.section.unsaved')}</span>}
        </div>
      )}
    </section>
  )
}
