import { useRef } from 'react'
import { getBootVersion } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { LogoMark } from './Icons'

// „Despre" — ce e aplicația, cine a făcut-o, sub ce licență. Deschis din logo-ul
// sidebar-ului. Versiunea vine din headerul X-Webterm-Version (fără apel dedicat).
const REPO = 'https://github.com/sm26449/webterm'

export default function AboutModal(props: { onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const version = getBootVersion()

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('about.aria')}
        className="glass w-full max-w-sm rounded-2xl p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2.5">
            <span className="text-sky-400"><LogoMark /></span>
            <div>
              <h2 className="text-lg font-semibold leading-tight">WebTerm</h2>
              {version && <p className="tabular-nums text-xs text-slate-500">v{version}</p>}
            </div>
          </div>
          <button onClick={props.onClose} aria-label={t('common.close')} className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
        </div>

        <p className="mt-4 text-sm leading-relaxed text-slate-300">
          {t('about.description')}
        </p>
        <p className="mt-3 border-l-2 border-ink-700 pl-3 text-sm italic leading-relaxed text-slate-400">
          {t('about.tagline')}
        </p>

        <dl className="mt-5 space-y-2 border-t border-ink-800 pt-4 text-[13px]">
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">{t('about.author')}</dt>
            <dd className="text-right text-slate-300">Stefan Maldaianu</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">{t('about.dev')}</dt>
            <dd className="text-right text-slate-300">{t('about.devValue')}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">{t('about.license')}</dt>
            <dd className="text-right text-slate-300">{t('about.licenseValue')}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">{t('about.project')}</dt>
            <dd className="min-w-0 text-right">
              <a href={REPO} target="_blank" rel="noopener noreferrer" className="wt-link break-all hover:underline">
                github.com/sm26449/webterm
              </a>
            </dd>
          </div>
        </dl>

        <p className="mt-4 text-center text-[11px] text-slate-400">© 2026 Stefan Maldaianu</p>
      </div>
    </div>
  )
}
