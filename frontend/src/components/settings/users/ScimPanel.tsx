import { useEffect, useState } from 'react'
import { api, errText, withSecondFactor as withSecondFactorT, type ReauthMe } from '../../../lib/api'
import { copyText } from '../../../lib/clipboard'
import { useConfirm } from '../../../lib/confirm'
import { useI18n } from '../../../lib/i18n'
import { docsUrl } from '../../../lib/help'
import { fmtTs } from '../../../lib/tz'
import { scimState, type ScimStatus } from '../../../lib/usersAdmin'
import { heading } from '../ui'
import { RETURN_USERS, useAccessReauth } from './shared'
import { Badge, Button, ErrorState } from '../../ui'
import HelpTip from '../../HelpTip'
import type { BadgeTone } from '../../ui'

/* SCIM provisioning (3.6.11), sub-tab-ul „SSO groups". IdP-ul (Authentik: un provider SCIM pus ca
   backchannel pe aplicaţia WebTerm) împinge creările, dezactivările, ştergerile şi grupurile pe loc.
   Oricine are users.manage vede STAREA (fără token); tokenul îl creează / roteşte / revocă şi
   provizionarea o porneşte DOAR un Owner — parola lui + al doilea factor (serverul le cere oricum).
   Tokenul apare O SINGURĂ DATĂ, imediat după creare/rotire; serverul păstrează doar hash-ul. */

const SCIM_DOC = 'docs/SSO.md#scim-provisioning-3611'
const TONE: Record<ReturnType<typeof scimState>, BadgeTone> = { off: 'neutral', paused: 'warn', noSso: 'danger', on: 'ok' }

/** `me` = rândul propriu din lista de conturi (UsersTab o are): decide planul de re-autentificare —
    parolă, passkey sau drumul SSO — pentru un Owner SSO-only, care n-are parolă de tastat (RB-03, 3.6.19) */
export default function ScimPanel(props: { isOwner: boolean; me?: ReauthMe; done: (text: string) => void; fail: (e: unknown) => void }) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const { reauth } = useAccessReauth(props.me, { returnTo: RETURN_USERS })
  const [st, setSt] = useState<ScimStatus | null>(null)
  const [err, setErr] = useState('')
  const [fresh, setFresh] = useState('')          // tokenul abia creat — arătat o dată
  const [copied, setCopied] = useState('')
  const [busy, setBusy] = useState(false)
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)

  const load = () => api<ScimStatus>('/api/settings/scim')
    .then((r) => { setSt(r); setErr('') })
    .catch((e) => { setSt(null); setErr(errText(e, t) || t('common.loadFailed')) })
  useEffect(() => { void load() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  async function copy(text: string, what: string) {
    if (await copyText(text)) { setCopied(what); setTimeout(() => setCopied(''), 1500) }
  }

  async function createToken() {
    const rotating = !!st?.configured
    if (rotating && !(await confirm({ title: t('scim.rotateTitle'), message: t('scim.rotateBody'),
      confirmLabel: t('scim.rotate'), danger: true }))) return
    setBusy(true)
    try {
      const r = await reauth(t(rotating ? 'scim.rotateConfirm' : 'scim.createConfirm'),
        (cred) => withSecondFactor((extra) => api<ScimStatus>('/api/settings/scim/token',
          { method: 'POST', body: JSON.stringify({ ...cred, ...extra }) })))
      if (r === null) { setBusy(false); return }       // anulat, sau plecat la IdP (revine în Setări)
      setFresh(r.token || '')
      const { token: _tok, ...rest } = r
      setSt(rest)
      props.done(t(rotating ? 'scim.rotated' : 'scim.created'))
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  async function revoke() {
    if (!(await confirm({ title: t('scim.revokeTitle'), message: t('scim.revokeBody'),
      confirmLabel: t('scim.revoke'), danger: true }))) return
    setBusy(true)
    try {
      const r = await reauth(t('scim.revokeConfirm'),
        (cred) => withSecondFactor((extra) => api<ScimStatus>('/api/settings/scim/revoke',
          { method: 'POST', body: JSON.stringify({ ...cred, ...extra }) })))
      if (r === null) { setBusy(false); return }
      setSt(r)
      setFresh('')
      props.done(t('scim.revoked'))
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  async function toggle(on: boolean) {
    setBusy(true)
    try {
      if (on) {
        // pornirea cere re-autentificare (+ al doilea factor); oprirea doar reduce accesul — fără
        const r = await reauth(t('scim.enableConfirm'),
          (cred) => withSecondFactor((extra) => api<ScimStatus>('/api/settings/scim/enabled',
            { method: 'POST', body: JSON.stringify({ enabled: true, ...cred, ...extra }) })))
        if (r === null) { setBusy(false); return }
        setSt(r)
      } else {
        setSt(await api<ScimStatus>('/api/settings/scim/enabled',
          { method: 'POST', body: JSON.stringify({ enabled: false }) }))
      }
      props.done(t(on ? 'scim.turnedOn' : 'scim.turnedOff'))
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  if (err) {
    return (
      <section className="mt-6 border-t border-ink-700 pt-4" data-scim-panel>
        <h3 className={heading + ' !mt-0'}>{t('scim.title')}</h3>
        <ErrorState compact title={t('scim.loadFailed')} message={err} onRetry={() => { void load() }} />
      </section>
    )
  }
  if (!st) return null
  const state = scimState(st)
  return (
    <section className="mt-6 border-t border-ink-700 pt-4" data-scim-panel aria-labelledby="scim-title">
      <div className="flex flex-wrap items-center gap-2">
        <h3 id="scim-title" className={heading + ' !mt-0 flex flex-1 items-center gap-2'}>{t('scim.title')}<HelpTip id="scim" /></h3>
        <Badge tone={TONE[state]} size="md" data-scim-state={state}>{t('scim.state.' + state)}</Badge>
      </div>
      <p className="mt-1 text-xs text-slate-500">{t('scim.hint')}</p>
      {state === 'noSso' && <p className="mt-2 rounded-md bg-danger/10 px-3 py-2 text-xs wt-danger">{t('scim.noSso')}</p>}

      <dl className="mt-3 grid grid-cols-1 gap-x-4 gap-y-1.5 text-xs sm:grid-cols-[auto_1fr]">
        <dt className="text-slate-500">{t('scim.url')}</dt>
        <dd className="flex min-w-0 flex-wrap items-center gap-2">
          <code className="min-w-0 break-all font-mono text-slate-200" data-scim-url>{st.url}</code>
          <Button type="button" size="sm" variant="ghost" onClick={() => copy(st.url, 'url')}
            aria-label={t('scim.copyUrl')}>{copied === 'url' ? t('scim.copied') : t('scim.copy')}</Button>
        </dd>
        <dt className="text-slate-500">{t('scim.token')}</dt>
        <dd className="text-slate-300">
          {st.configured && st.token_created
            ? t('scim.tokenCreated', { date: fmtTs(st.token_created, 'datetime'), who: st.token_created_by || '—' })
            : t('scim.tokenNone')}
        </dd>
        <dt className="text-slate-500">{t('scim.lastRequest')}</dt>
        <dd className="text-slate-300" data-scim-last-request>
          {st.last_request ? fmtTs(st.last_request, 'datetime') : t('scim.never')}
        </dd>
        <dt className="text-slate-500">{t('scim.lastError')}</dt>
        <dd className={st.last_error ? 'wt-danger' : 'text-slate-300'} data-scim-last-error>
          {st.last_error
            ? t('scim.lastErrorText', { date: fmtTs(st.last_error.ts, 'datetime'), status: st.last_error.status,
              detail: st.last_error.detail })
            : t('scim.noError')}
        </dd>
        <dt className="text-slate-500">{t('scim.accounts')}</dt>
        <dd className="text-slate-300">
          {t('scim.accountsText', { n: st.managed_accounts, disabled: st.disabled_accounts, groups: st.groups })}
        </dd>
      </dl>

      {fresh && (
        <div className="mt-3 flex flex-col gap-2 rounded-xl bg-warn/10 p-3 ring-1 ring-warn/40" data-scim-fresh-token>
          <p className="text-xs text-warn">{t('scim.copyNow')}</p>
          <div className="flex flex-wrap items-center gap-2">
            <input type="text" readOnly value={fresh} aria-label={t('scim.token')} spellCheck={false}
              className="min-w-0 flex-1 rounded-md bg-ink-900 px-2 py-1.5 font-mono text-xs text-slate-200 ring-1 ring-ink-700"
              onFocus={(e) => e.currentTarget.select()} />
            <Button type="button" size="sm" variant="primary" onClick={() => copy(fresh, 'token')}>
              {copied === 'token' ? t('scim.copied') : t('scim.copyToken')}
            </Button>
            <Button type="button" size="sm" onClick={() => setFresh('')}>{t('scim.hideToken')}</Button>
          </div>
        </div>
      )}

      {props.isOwner ? (
        <div className="mt-3 flex flex-wrap gap-2" data-scim-actions>
          <Button type="button" size="sm" variant={st.configured ? 'secondary' : 'primary'} loading={busy}
            onClick={createToken} data-scim-token>
            {st.configured ? t('scim.rotate') : t('scim.create')}
          </Button>
          {st.configured && (st.enabled
            ? <Button type="button" size="sm" onClick={() => toggle(false)} disabled={busy}>{t('scim.turnOff')}</Button>
            : <Button type="button" size="sm" variant="primary" onClick={() => toggle(true)} disabled={busy}>{t('scim.turnOn')}</Button>)}
          {st.configured && (
            <Button type="button" size="sm" variant="danger" onClick={revoke} disabled={busy}>{t('scim.revoke')}</Button>
          )}
        </div>
      ) : (
        <p className="mt-3 text-xs text-slate-400">{t('scim.ownerOnly')}</p>
      )}
      <ul className="mt-3 flex flex-col gap-1 text-xs text-slate-400">
        <li>{t('scim.what.syncs')}</li>
        <li>{t('scim.what.never')}</li>
        <li>{t('scim.what.groups')}</li>
      </ul>
      <a href={docsUrl(SCIM_DOC)} target="_blank" rel="noopener noreferrer"
        className="wt-link mt-2 inline-block text-xs underline">{t('scim.docs')}</a>
    </section>
  )
}
