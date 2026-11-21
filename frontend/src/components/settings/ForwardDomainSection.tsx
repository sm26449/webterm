import { useEffect, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { field } from './ui'
import { Button, Field, SettingsSection } from '../ui'
import { canSave, type LoadState } from '../../lib/loadable'
import HelpTip from '../HelpTip'
import NotLoaded from './NotLoaded'

// Domeniul de port-forwarding (wildcard DNS + certificat). Până în 3.6.3 stătea sub „Notificări",
// unde nu-l căuta nimeni (audit funcţional 3.6.3); acum e în Infrastructură. id-ul secţiunii
// (`forwardDomain`) e acelaşi, deci căutarea din Setări şi linkurile adânci merg mai departe.
type FwdCfg = {
  domain: string; app_domain: string; is_custom: boolean
  server_ip: string; dns_ip: string; dns_ok: boolean; cert_ok: boolean
}

export default function ForwardDomainSection(props: { 'data-setting-id': string; hidden?: boolean }) {
  const { t } = useI18n()
  const vis = useSectionVisible()
  // Port forwarding: domeniu configurabil
  const [fwd, setFwd] = useState<FwdCfg | null>(null)
  const [fwdDomain, setFwdDomain] = useState('')
  const [fwdMsg, setFwdMsg] = useState('')
  const [fwdErr, setFwdErr] = useState('')
  const [fwdBusy, setFwdBusy] = useState(false)
  const [fwdState, setFwdState] = useState<LoadState>({ status: 'loading' })
  const loadFwd = (quiet = false) => {
    if (!quiet) setFwdState({ status: 'loading' })
    return api<FwdCfg>('/api/settings/forward')
      .then((c) => { setFwd(c); setFwdDomain(c.domain); setFwdState({ status: 'ok' }) })
      .catch((e) => setFwdState({ status: 'error', error: errText(e, t) }))
  }
  async function saveFwd() {
    if (!canSave(fwdState)) return
    setFwdBusy(true); setFwdMsg(''); setFwdErr('')
    try {
      const c = await api<FwdCfg>('/api/settings/forward', {
        method: 'POST', body: JSON.stringify({ domain: fwdDomain.trim() }),
      })
      setFwd(c); setFwdDomain(c.domain); setFwdMsg(t('settings.forward.saved'))
    } catch (e) {
      setFwdErr(errText(e, t) || t('settings.error'))
    } finally { setFwdBusy(false) }
  }
  useEffect(() => { if (vis('forwardDomain')) void loadFwd() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  return (
      // data-setting-id vine din NetworkTab, scris literal acolo (indexul căutării citeşte *Tab.tsx)
    <SettingsSection data-setting-id={props['data-setting-id']} hidden={props.hidden} instanceWide
      title={t('settings.forward.title')} titleExtra={<HelpTip id="forwardDomain" />}
      description={t('settings.forward.desc')}>
      <NotLoaded state={fwdState} onRetry={() => { void loadFwd() }} />
      {canSave(fwdState) && (<div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-end gap-2">
          <Field label={t('settings.forward.ariaLabel')} className="min-w-0 flex-1">
            <input value={fwdDomain} onChange={(e) => setFwdDomain(e.target.value)}
              placeholder={t('settings.forward.inputPlaceholder')} spellCheck={false}
              aria-invalid={fwdErr ? true : undefined} aria-describedby={fwdErr ? 'fwd-error' : undefined}
              className={`${field} font-mono`} />
          </Field>
          <Button variant="primary" type="button" loading={fwdBusy} onClick={saveFwd} className="shrink-0">
            {t('settings.save')}
          </Button>
          <Button variant="secondary" type="button" disabled={fwdBusy} onClick={() => { setFwdMsg(''); setFwdErr(''); void loadFwd(true) }} className="shrink-0">
            {t('settings.recheck')}
          </Button>
        </div>
        {/* regiuni live montate permanent: confirmarea e `status`, eroarea `alert` (WCAG 4.1.3) */}
        <span role="status" className={fwdMsg ? 'text-sm wt-good' : 'sr-only'}>{fwdMsg}</span>
        <span id="fwd-error" role="alert" className={fwdErr ? 'text-sm wt-danger' : 'sr-only'}>{fwdErr}</span>
        {fwd && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <span className="flex items-center gap-1.5">
              <span aria-hidden="true" className={`h-2 w-2 rounded-full ${fwd.dns_ok ? 'bg-emerald-500' : 'bg-rose-500'}`} />
              {t('settings.forward.dnsWildcard')} {fwd.dns_ok
                ? <span className="font-mono text-slate-400">*.{fwd.domain} → {fwd.dns_ip}</span>
                : <span className="text-slate-500">{t('settings.forward.notResolving')}</span>}
            </span>
            <span className="flex items-center gap-1.5">
              <span aria-hidden="true" className={`h-2 w-2 rounded-full ${fwd.cert_ok ? 'bg-emerald-500' : 'bg-amber-500'}`} />
              {t('settings.forward.certificate')} {fwd.cert_ok ? <span className="text-slate-400">{t('settings.forward.certActive')}</span> : <span className="text-slate-500">{t('settings.forward.certPending')}</span>}
            </span>
          </div>
        )}
        {fwd && fwd.is_custom && !(fwd.dns_ok && fwd.cert_ok) && (
          <div className="rounded-md border border-ink-700 bg-ink-800/50 p-3 text-xs text-slate-400">
            <p className="mb-1.5 font-medium text-slate-300">{t('settings.forward.toActivateA')} <span className="font-mono">{fwd.domain}</span> {t('settings.forward.toActivateB')}</p>
            <ol className="ml-4 list-decimal space-y-1">
              <li>{t('settings.forward.step1Label')} <span className="font-mono wt-link">*.{fwd.domain}</span> → <span className="font-mono">A {fwd.server_ip || t('settings.forward.ipServerPlaceholder')}</span> (DNS-only)</li>
              <li>{t('settings.forward.step2In')} <span className="font-mono">/opt/webterm/.env</span>: <span className="font-mono wt-link">FORWARD_DOMAIN={fwd.domain}</span> {t('settings.forward.step2TokenA')} <span className="font-mono">.env</span> {t('settings.forward.step2TokenB')}</li>
              <li>Redeploy: <span className="font-mono">cd /opt/webterm &amp;&amp; ./deploy.sh</span> {t('settings.forward.step3Desc')}</li>
            </ol>
          </div>
        )}
      </div>)}
    </SettingsSection>
  )
}
