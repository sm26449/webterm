import { useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import AccountTab from './settings/AccountTab'
import SecurityTab from './settings/SecurityTab'
import AuditTab from './settings/AuditTab'
import AppearanceTab from './settings/AppearanceTab'
import NotificationsTab from './settings/NotificationsTab'
import BackupTab from './settings/BackupTab'
import PreferencesTab from './settings/PreferencesTab'

// Cadrul modalului de Setări: antet, rail-ul de categorii şi dispecerizarea tab-ului activ.
// God-component-ul de odinioară a fost spart pe tab-uri în ./settings/*Tab.tsx — fiecare îşi ţine
// starea şi se încarcă singur la montare (= la deschiderea secţiunii). Aici nu mai trăieşte logică.
export default function SettingsModal(props: {
  email: string | null
  webauthnAvailable: boolean
  initialCat?: 'cont' | 'securitate' | 'aspect' | 'notificari' | 'backup' | 'preferinte'
  onClose: () => void
  onAccountChanged: () => void   // refetch /api/state (refolosit și după salvarea watermark-ului)
}) {
  const { t } = useI18n()
  // categoria activă: modalul nu mai e un scroll lung — arată o secțiune odată
  const [cat, setCat] = useState<'cont' | 'securitate' | 'audit' | 'aspect' | 'notificari' | 'backup' | 'preferinte'>(props.initialCat ?? 'cont')
  const CATS = [
    { id: 'cont', label: t('settings.cat.account') },
    { id: 'securitate', label: t('settings.cat.security') },
    { id: 'audit', label: t('settings.cat.audit') },
    { id: 'aspect', label: t('settings.cat.appearance') },
    { id: 'notificari', label: t('settings.cat.notifications') },
    { id: 'backup', label: t('settings.cat.backup') },
    { id: 'preferinte', label: t('settings.cat.preferences') },
  ] as const

  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('settings.title')}
        className="glass flex h-[92vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl sm:h-[88vh] lg:max-w-4xl xl:max-w-5xl">
        {/* antet fix */}
        <div className="flex items-center justify-between border-b border-ink-800 px-5 py-3">
          <h2 className="text-lg font-semibold">{t('settings.title')}</h2>
          <button onClick={props.onClose} aria-label={t('settings.close')} className="wt-touch grid place-items-center rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
            ✕
          </button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col sm:flex-row">
          {/* rail de categorii: coloană pe desktop, bandă orizontală pe mobil */}
          <nav aria-label={t('settings.categoriesNav')}
            className="flex shrink-0 gap-1 overflow-x-auto border-b border-ink-800 p-2 sm:w-44 lg:w-52 sm:flex-col sm:overflow-x-visible sm:border-b-0 sm:border-r">
            {CATS.map((c) => (
              <button
                key={c.id}
                onClick={() => setCat(c.id)}
                aria-current={cat === c.id ? 'true' : undefined}
                className={`wt-touch shrink-0 rounded-lg px-3 py-2 text-left text-sm sm:w-full ${
                  cat === c.id ? 'bg-sky-600 text-white' : 'text-slate-300 hover:bg-ink-800'
                }`}
              >
                {c.label}
              </button>
            ))}
          </nav>

          {/* conținut: doar categoria activă, scrollabil */}
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            {/* coloană de lectură: peste ~70ch textul devine greu de urmărit;
                secţiunile cu liste (audit, backup) folosesc toată lăţimea */}
            <div className={cat === 'audit' || cat === 'backup' ? '' : 'max-w-3xl'}>

        {cat === 'cont' && <AccountTab email={props.email} onAccountChanged={props.onAccountChanged} />}

        {cat === 'preferinte' && <PreferencesTab />}

        {cat === 'aspect' && <AppearanceTab onAccountChanged={props.onAccountChanged} />}

        {cat === 'securitate' && <SecurityTab webauthnAvailable={props.webauthnAvailable} onAccountChanged={props.onAccountChanged} />}

        {cat === 'audit' && <AuditTab />}

        {cat === 'notificari' && <NotificationsTab />}

        {cat === 'backup' && <BackupTab onAccountChanged={props.onAccountChanged} />}
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
