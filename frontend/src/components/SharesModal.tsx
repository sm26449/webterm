import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errText, ShareRow, withSecondFactor, withStepup } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { notifyError, notifyToast } from '../lib/notify'
import { askSecret } from '../lib/secretPrompt'
import { fmtTs } from '../lib/tz'
import { useFocusTrap } from '../lib/useFocusTrap'
import { EyeIcon } from './Icons'
import LoadFailed from './LoadFailed'

/* Inventarul link-urilor de share active din flotă (3.5.4). Până acum un link trăia doar în
   bara sesiunii lui: ca să afli „ce am dat cui" deschideai sesiune cu sesiune. Aici le vezi pe
   toate, cu cine le-a creat, cât mai trăiesc şi câţi invitaţi sunt conectaţi ACUM.

   URL-ul nu apare — nici nu există: serverul ţine doar hash-ul tokenului. Rândurile de pe hosturi
   cu 2FA apar doar cu fereastra de step-up deschisă (ca lista de sesiuni); restul se numără. */
export default function SharesModal(props: { onClose: () => void; onChanged: () => void }) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [data, setData] = useState<{ shares: ShareRow[]; hidden: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    setError(null)
    api<{ shares: ShareRow[]; hidden: number }>('/api/shares')
      .then(setData)
      .catch((e) => setError(errText(e, t) || t('common.loadFailed')))
  }, [t])
  useEffect(() => { load() }, [load])

  async function revokeOne(s: ShareRow) {
    if (!(await confirm({
      title: t('session.revokeShareTitle'),
      message: t('shares.revokeOneConfirm', { title: s.title || t('dashboard.session'), host: s.host_name }),
      danger: true, confirmLabel: t('session.revoke'),
    }))) return
    setBusy(true)
    try {
      // pe un host 2FA, revocarea e o acţiune de host (ca la creare) — withStepup cere factorul
      await withStepup(s.host_id, () => api(`/api/sessions/${s.sid}/share`, { method: 'DELETE' }))
      props.onChanged()
      load()
    } catch (e) {
      notifyError(t('session.shareRevokeFailed'), errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  async function revokeAll() {
    if (!(await confirm({
      title: t('shares.revokeAllTitle'), message: t('shares.revokeAllConfirm'),
      danger: true, confirmLabel: t('shares.revokeAll'),
    }))) return
    // parola CONTULUI (mascată): un cookie furat singur nu rupe toate link-urile dintr-un POST
    const pw = await askSecret(t('shares.revokeAllPassword'))
    if (pw === null) return
    setBusy(true)
    try {
      const r = await withSecondFactor(t, (extra) => api<{ revoked: number }>('/api/shares/revoke-all', {
        method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }),
      }))
      notifyToast(t('shares.revokedAll', { count: r.revoked }))
      props.onChanged()
      load()
    } catch (e) {
      notifyError(t('shares.revokeAllFailed'), errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  const shares = data?.shares ?? []
  const total = shares.length + (data?.hidden ?? 0)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wt-shares-title"
        className="glass flex max-h-[88vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 border-b border-ink-800 px-5 py-3">
          <h2 id="wt-shares-title" className="text-lg font-semibold">{t('shares.title')}</h2>
          <div className="flex items-center gap-2">
            {total > 0 && (
              <button type="button" onClick={revokeAll} disabled={busy}
                className="rounded-lg bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 disabled:opacity-50">
                {t('shares.revokeAll')}
              </button>
            )}
            <button type="button" onClick={props.onClose} aria-label={t('common.close')}
              className="wt-touch grid place-items-center rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
              ✕
            </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <p className="text-xs text-slate-400">{t('shares.intro')}</p>
          {error ? (
            <LoadFailed message={error} onRetry={load} />
          ) : !data ? (
            <p className="mt-4 text-sm text-slate-500" aria-live="polite">{t('secsum.loading')}</p>
          ) : (
            <>
              {shares.length === 0 && data.hidden === 0 ? (
                <p data-testid="shares-empty" className="mt-4 rounded-xl border border-dashed border-ink-700 px-4 py-6 text-center text-sm text-slate-400">
                  {t('shares.empty')}
                </p>
              ) : (
                <ul aria-label={t('shares.title')} className="mt-3 flex flex-col gap-1.5">
                  {shares.map((s) => (
                    <li key={s.sid} data-share={s.sid}
                      className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-medium text-slate-200">{s.title || t('dashboard.session')}</span>
                        <span className="block truncate text-xs text-slate-400">
                          {s.host_name || t('dashboard.host')}
                          {s.by ? ` · ${t('shares.by', { email: s.by })}` : ''}
                          {' · '}{t('session.shareExpires', { time: fmtTs(s.expires) })}
                        </span>
                      </span>
                      {/* badge cu TEXT, nu doar culoare: „poate tasta" e ce contează la o privire */}
                      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${
                        s.writable ? 'wt-danger bg-rose-500/15' : 'text-slate-300 bg-ink-700'}`}>
                        {s.writable ? t('session.shareWritable') : t('session.shareReadOnly')}
                      </span>
                      <span className="flex shrink-0 items-center gap-1 text-xs text-slate-400"
                        aria-label={t('shares.viewers', { count: s.viewers })} role="img">
                        <EyeIcon /> {s.viewers}
                      </span>
                      <button type="button" onClick={() => revokeOne(s)} disabled={busy}
                        aria-label={t('shares.revokeOneAria', { title: s.title || t('dashboard.session') })}
                        className="shrink-0 rounded-md px-2 py-1 text-xs wt-danger ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-50">
                        {t('session.revoke')}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {data.hidden > 0 && (
                <p className="mt-3 text-xs text-slate-400">{t('shares.hidden', { count: data.hidden })}</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
