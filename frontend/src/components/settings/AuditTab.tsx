import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { fmtTs } from '../../lib/tz'
import { field, heading } from './ui'

// Jurnalul de audit (cine / ce / când / de la ce IP, pe fiecare acţiune care schimbă ceva).
// Extras din SettingsModal ca tab de sine stătător: îşi ţine propria stare şi se încarcă la
// montare (adică atunci când categoria devine activă — părintele randează doar tab-ul activ).
type AuditEntry = {
  ts: number; actor: string; ip: string; method: string; path: string
  status: number; detail: string
}
const AUDIT_PAGE = 100

export default function AuditTab() {
  const { t } = useI18n()
  const [audit, setAudit] = useState<AuditEntry[] | null>(null)
  const [auditQ, setAuditQ] = useState('')
  const [auditFailed, setAuditFailed] = useState(false)
  const [auditBusy, setAuditBusy] = useState(false)
  const [auditEnd, setAuditEnd] = useState(false)   // ultima pagină primită era incompletă
  const [auditDays, setAuditDays] = useState(0)

  // `reset` = filtre noi (pornim de la cel mai recent); altfel paginăm în trecut de la ts-ul
  // ultimei linii — offset-ul ar sări rânduri când apar acţiuni noi între cereri.
  async function loadAudit(reset: boolean) {
    setAuditBusy(true)
    try {
      const last = audit && audit.length ? audit[audit.length - 1] : null
      const before = reset || !last ? 0 : last.ts
      const qs = new URLSearchParams({ limit: String(AUDIT_PAGE) })
      if (before) qs.set('before', String(before))
      if (auditQ.trim()) qs.set('q', auditQ.trim())
      if (auditFailed) qs.set('failed_only', 'true')
      const r = await api<{ entries: AuditEntry[]; retention_days: number }>(`/api/audit?${qs}`)
      setAuditDays(r.retention_days)
      setAuditEnd(r.entries.length < AUDIT_PAGE)
      setAudit(reset ? r.entries : [...(audit ?? []), ...r.entries])
    } catch { /* jurnalul e informativ — o eroare nu blochează Setările */ }
    setAuditBusy(false)
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { loadAudit(true) }, [])   // încarcă la deschiderea tab-ului

  return (
    <div>
      <h3 className={heading + ' !mt-0'}>{t('settings.audit.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">{t('settings.audit.hint')}</p>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input
          value={auditQ}
          onChange={(e) => setAuditQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') loadAudit(true) }}
          placeholder={t('settings.audit.searchPlaceholder')}
          aria-label={t('settings.audit.searchAria')}
          spellCheck={false}
          className={field + ' min-w-40 flex-1'}
        />
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input type="checkbox" checked={auditFailed}
            onChange={(e) => { setAuditFailed(e.target.checked) }} />
          {t('settings.audit.failedOnly')}
        </label>
        <button onClick={() => loadAudit(true)} disabled={auditBusy}
          className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >{t('settings.audit.filter')}</button>
      </div>

      <ul className="mt-3 flex flex-col gap-1">
        {(audit ?? []).map((e, i) => (
          <li key={`${e.ts}-${i}`}
            className="rounded-lg bg-ink-800/60 px-3 py-2 text-xs ring-1 ring-ink-700">
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
              <span className="font-mono tabular-nums text-slate-400">
                {fmtTs(e.ts)}
              </span>
              {/* respins ≠ reușit: la audit, eșecurile sunt cele mai interesante */}
              <span className={`font-mono ${e.status >= 400 ? 'wt-danger' : 'wt-good'}`}>
                {e.status}
              </span>
              <span className="font-mono text-slate-300">{e.method} {e.path}</span>
            </div>
            <div className="mt-0.5 flex flex-wrap gap-x-3 text-slate-500">
              <span>{e.actor || t('settings.audit.anonymous')}</span>
              {e.ip && <span className="font-mono">{e.ip}</span>}
              {e.detail && <span className="font-mono text-slate-400">{e.detail}</span>}
            </div>
          </li>
        ))}
      </ul>

      {audit !== null && audit.length === 0 && (
        <p className="mt-3 text-xs text-slate-500">{t('settings.audit.empty')}</p>
      )}
      <div className="mt-3 flex items-center gap-3">
        {!auditEnd && audit !== null && audit.length > 0 && (
          <button onClick={() => loadAudit(false)} disabled={auditBusy}
            className="text-xs wt-link hover:underline disabled:opacity-50"
          >{auditBusy ? t('settings.audit.loading') : t('settings.audit.more')}</button>
        )}
        {auditDays > 0 && (
          <span className="text-xs text-slate-500">{t('settings.audit.retention', { days: auditDays })}</span>
        )}
      </div>
    </div>
  )
}
