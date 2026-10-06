import { lazy, Suspense, useRef, useState } from 'react'
import { getBootVersion } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { LogoMark, StarIcon } from './Icons'

const ChangelogModal = lazy(() => import('./ChangelogModal'))

// „Despre" — ce e aplicația, cine a făcut-o, sub ce licență. Deschis din logo-ul
// sidebar-ului. Versiunea vine din headerul X-Webterm-Version (fără apel dedicat).
const REPO = 'https://github.com/sm26449/webterm'

export default function AboutModal(props: { onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const version = getBootVersion()
  const [showChangelog, setShowChangelog] = useState(false)

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
              <p className="flex items-center gap-2 text-xs text-slate-500">
                {version && <span className="tabular-nums">v{version}</span>}
                <button onClick={() => setShowChangelog(true)} className="wt-link hover:underline">
                  {t('about.whatsNew')}
                </button>
              </p>
            </div>
          </div>
          <button onClick={props.onClose} aria-label={t('common.close')} className="wt-touch grid place-items-center rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
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

        <a
          href={REPO}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-5 flex items-center gap-3 rounded-xl border border-ink-700 px-3 py-2.5 text-left hover:border-amber-400/60 hover:bg-ink-800/60"
        >
          <span className="shrink-0 text-amber-400"><StarIcon size={18} /></span>
          <span className="min-w-0">
            <span className="block text-sm font-medium text-slate-200">{t('about.starTitle')}</span>
            <span className="block text-xs text-slate-400">{t('about.starBody')}</span>
          </span>
        </a>

        <p className="mt-4 text-center text-[11px] text-slate-400">© 2026 Stefan Maldaianu</p>
      </div>
      {showChangelog && (
        <Suspense fallback={null}>
          <ChangelogModal onClose={() => setShowChangelog(false)} />
        </Suspense>
      )}
    </div>
  )
}
