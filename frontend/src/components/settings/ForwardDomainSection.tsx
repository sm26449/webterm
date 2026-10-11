import { useEffect, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { field, heading } from './ui'
import { Button } from '../ui'
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

export default function ForwardDomainSection() {
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
      // <section data-setting-id> stă în InfrastructureTab (indexul căutării verifică tab-urile)
    <>
      {/* ── Port forwarding (domeniu) ── */}
      <h3 className={heading + ' flex items-center gap-2'}>{t('settings.forward.title')}<HelpTip id="forwardDomain" /></h3>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.forward.hintA')} <span className="font-mono">{t('settings.forward.subdomain')}</span>{t('settings.forward.hintB')} <span className="font-mono">{t('settings.forward.exampleDomain')}</span>{t('settings.forward.hintC')} <span className="font-mono">.env</span>{t('settings.forward.hintD')}
      </p>
      <NotLoaded state={fwdState} onRetry={() => { void loadFwd() }} />
      {canSave(fwdState) && (<div className="mt-2 flex flex-col gap-2">
        <div className="flex gap-2">
          <input value={fwdDomain} onChange={(e) => setFwdDomain(e.target.value)}
            placeholder={t('settings.forward.inputPlaceholder')} aria-label={t('settings.forward.ariaLabel')} spellCheck={false}
            aria-invalid={fwdErr ? true : undefined} aria-describedby={fwdErr ? 'fwd-error' : undefined}
            className={`${field} font-mono`} />
          <Button variant="primary" disabled={fwdBusy} onClick={saveFwd} className="shrink-0">
            {t('settings.save')}
          </Button>
          <Button variant="secondary" disabled={fwdBusy} onClick={() => { setFwdMsg(''); setFwdErr(''); loadFwd(true) }} className="shrink-0">
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
    </>
  )
}
