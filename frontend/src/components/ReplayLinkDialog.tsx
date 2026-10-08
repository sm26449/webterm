import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { api, errText, ReplayLinkCreated, ReplayLinkRow, withStepup } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { notifyToast } from '../lib/notify'
import { expiryKey, REPLAY_DEFAULT_EXPIRY, REPLAY_EXPIRY_HOURS, REPLAY_LABEL_MAX, ReplayExpiry } from '../lib/replay'
import { fmtTs } from '../lib/tz'
import { useFocusTrap } from '../lib/useFocusTrap'
import HelpTip from './HelpTip'
import { CloseIcon, CopyIcon, EyeIcon, WarningIcon } from './Icons'
import { Button, IconButton, cardClass, eyebrow } from './ui'

/* „Partajează replay" (3.5.12): un link PUBLIC, doar-citire, către înregistrarea unei sesiuni
   ÎNCHISE. Dialogul face trei lucruri: avertizează (înregistrarea poate conţine secrete, mascarea
   e best-effort), creează (expirare 1 h / 24 h / 7 zile, etichetă, mascare implicit pornită) şi
   arată link-urile existente ale înregistrării, cu numărul de deschideri şi revocare.

   URL-ul apare O SINGURĂ dată, după creare: serverul ţine doar hash-ul tokenului. */
export default function ReplayLinkDialog(props: { sid: string; hostId: number; title: string; onClose: () => void }) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  const uid = useId()
  const [expiry, setExpiry] = useState<ReplayExpiry>(REPLAY_DEFAULT_EXPIRY)
  const [label, setLabel] = useState('')
  const [redact, setRedact] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [created, setCreated] = useState<ReplayLinkCreated | null>(null)
  const [links, setLinks] = useState<ReplayLinkRow[] | null>(null)
  const [listErr, setListErr] = useState('')

  const load = useCallback(() => {
    setListErr('')
    api<{ links: ReplayLinkRow[]; hidden: number }>(`/api/replay-links?sid=${encodeURIComponent(props.sid)}`)
      .then((r) => setLinks(r.links))
      .catch((e) => setListErr(errText(e, t) || t('common.loadFailed')))
  }, [props.sid, t])
  useEffect(() => { load() }, [load])

  async function create() {
    setBusy(true)
    setErr('')
    try {
      // pe un host 2FA crearea cere step-up (ca citirea transcriptului): withStepup rulează ceremonia
      const r = await withStepup(props.hostId, () => api<ReplayLinkCreated>(
        `/api/sessions/${props.sid}/replay-links`,
        { method: 'POST', body: JSON.stringify({ expires_hours: expiry, label: label.trim(), redact }) }))
      setCreated(r)
      setLabel('')
      load()
    } catch (e) {
      setErr(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  async function revoke(l: ReplayLinkRow) {
    if (!(await confirm({
      title: t('replay.revokeTitle'),
      message: t('replay.revokeConfirm', { label: l.label || t('replay.unlabeled') }),
      danger: true, confirmLabel: t('session.revoke'),
    }))) return
    setBusy(true)
    try {
      await withStepup(props.hostId, () => api(`/api/replay-links/${l.id}`, { method: 'DELETE' }))
      if (created?.id === l.id) setCreated(null)
      notifyToast(t('replay.revoked'))
      load()
    } catch (e) {
      setErr(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  async function copy() {
    if (!created) return
    if (await copyText(created.url)) notifyToast(t('replay.copied'))
  }

  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={props.onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={`${uid}-t`} aria-describedby={`${uid}-w`}
        data-testid="replay-dialog"
        className="glass flex max-h-[88vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl text-sm"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between gap-3 border-b border-ink-800 px-5 py-3">
          <h2 id={`${uid}-t`} className="flex min-w-0 items-center gap-2 text-base font-semibold">
            <span className="truncate">{t('replay.dialogTitle')}</span>
            <HelpTip id="replayLinks" />
          </h2>
          <IconButton onClick={props.onClose} label={t('common.close')}><CloseIcon size={14} /></IconButton>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <p className="truncate text-xs text-slate-400">{t('replay.dialogFor', { title: props.title || t('transcript.sessionFallback') })}</p>
          <div id={`${uid}-w`} role="note"
            className="mt-3 flex gap-2 rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs wt-warn">
            <span className="mt-0.5 shrink-0"><WarningIcon /></span>
            <span>{t('replay.warning')}</span>
          </div>

          {created ? (
            <div className={`${cardClass} mt-4 p-3`} data-testid="replay-created">
              <label htmlFor={`${uid}-url`} className="block text-xs font-medium text-slate-300">{t('replay.createdLabel')}</label>
              <div className="mt-1 flex gap-1.5">
                <input id={`${uid}-url`} readOnly value={created.url} spellCheck={false}
                  onFocus={(e) => e.currentTarget.select()}
                  className="min-w-0 flex-1 rounded-md bg-ink-800 px-2 py-1.5 font-mono text-2xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
                <Button type="button" variant="primary" size="sm" onClick={() => void copy()} className="wt-touch shrink-0">
                  <CopyIcon size={12} /> {t('replay.copy')}
                </Button>
              </div>
              <p className="mt-2 text-2xs text-slate-400">
                {t('replay.createdOnce', { time: fmtTs(created.expires) })}
                {created.redact ? '' : ` ${t('replay.createdUnmasked')}`}
              </p>
              <Button type="button" size="sm" className="mt-2" onClick={() => setCreated(null)}>{t('replay.createAnother')}</Button>
            </div>
          ) : (
            <form className="mt-4 flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); void create() }}>
              <fieldset>
                <legend className="text-xs font-medium text-slate-300">{t('replay.expiry')}</legend>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {REPLAY_EXPIRY_HOURS.map((h) => (
                    <label key={h}
                      className={`wt-touch flex cursor-pointer items-center gap-1.5 rounded-md px-2.5 py-1 text-xs ring-1 has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-sky-400 ${
                        expiry === h ? 'bg-sky-600 text-white ring-sky-600' : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
                      <input type="radio" name={`${uid}-exp`} value={h} checked={expiry === h}
                        onChange={() => setExpiry(h)} className="sr-only" />
                      {t(expiryKey(h))}
                    </label>
                  ))}
                </div>
              </fieldset>
              <div>
                <label htmlFor={`${uid}-label`} className="block text-xs font-medium text-slate-300">{t('replay.label')}</label>
                <input id={`${uid}-label`} value={label} maxLength={REPLAY_LABEL_MAX}
                  onChange={(e) => setLabel(e.target.value)} placeholder={t('replay.labelPlaceholder')}
                  className="mt-1 w-full rounded-md bg-ink-800 px-2 py-1.5 text-sm text-slate-200 placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-500" />
              </div>
              <div>
                <label className="flex items-start gap-2 text-sm text-slate-200">
                  <input type="checkbox" checked={redact} onChange={(e) => setRedact(e.target.checked)}
                    aria-describedby={`${uid}-mh`} className="mt-1" />
                  <span>{t('replay.mask')}</span>
                </label>
                <p id={`${uid}-mh`} className={`ml-6 mt-0.5 text-2xs ${redact ? 'text-slate-400' : 'wt-danger'}`}>
                  {redact ? t('replay.maskHint') : t('replay.maskOff')}
                </p>
              </div>
              {err && <p role="alert" className="wt-danger">{err}</p>}
              <div className="flex justify-end gap-2">
                <Button type="button" onClick={props.onClose}>{t('files.cancel')}</Button>
                <Button type="submit" variant="primary" loading={busy} data-testid="replay-create">{t('replay.create')}</Button>
              </div>
            </form>
          )}

          <h3 className={`${eyebrow} mt-5`}>{t('replay.existing')}</h3>
          {listErr ? (
            <p className="mt-2 text-xs wt-danger">{listErr}</p>
          ) : links === null ? (
            <p className="mt-2 text-xs text-slate-500" aria-live="polite">{t('replay.loading')}</p>
          ) : links.length === 0 ? (
            <p className="mt-2 text-xs text-slate-400">{t('replay.none')}</p>
          ) : (
            <ul aria-label={t('replay.existing')} className="mt-2 flex flex-col gap-1.5">
              {links.map((l) => <ReplayLinkItem key={l.id} link={l} busy={busy} onRevoke={() => void revoke(l)} />)}
            </ul>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}

/** Un rând de link de replay — folosit şi în inventarul de share-uri (SharesModal). */
export function ReplayLinkItem(props: { link: ReplayLinkRow; busy?: boolean; onRevoke: () => void; showSession?: boolean }) {
  const { t } = useI18n()
  const l = props.link
  const name = l.label || t('replay.unlabeled')
  return (
    <li data-replay-link={l.id}
      className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium text-slate-200">
          {props.showSession ? `${l.title || t('dashboard.session')} · ${name}` : name}
        </span>
        <span className="block truncate text-xs text-slate-400">
          {props.showSession && l.host_name ? `${l.host_name} · ` : ''}
          {t('session.shareExpires', { time: fmtTs(l.expires) })}
          {' · '}
          {l.last_opened
            ? t('replay.lastOpened', { time: fmtTs(l.last_opened), ip: l.last_ip || '?' })
            : t('replay.neverOpened')}
        </span>
      </span>
      <span className={`shrink-0 rounded-md px-1.5 py-0.5 text-2xs font-medium ${
        l.redact ? 'bg-ink-700 text-slate-300' : 'wt-danger bg-rose-500/15'}`}>
        {l.redact ? t('replay.badgeMasked') : t('replay.badgeUnmasked')}
      </span>
      <span className="flex shrink-0 items-center gap-1 text-xs text-slate-400"
        role="img" aria-label={t('replay.opens', { count: l.opens })}>
        <EyeIcon /> {l.opens}
      </span>
      <button type="button" onClick={props.onRevoke} disabled={props.busy}
        aria-label={t('replay.revokeAria', { label: name })}
        className="wt-touch shrink-0 rounded-md px-2 py-1 text-xs wt-danger ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-50">
        {t('session.revoke')}
      </button>
    </li>
  )
}
