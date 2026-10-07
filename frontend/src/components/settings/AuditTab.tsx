import { useEffect, useRef, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { fmtTs } from '../../lib/tz'
import { field, heading } from './ui'
import LoadFailed from '../LoadFailed'
import { Button } from '../ui'

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
  // eşecul are starea lui: înainte catch-ul înghiţea eroarea şi lista rămânea goală, fără
  // niciun semn — la un jurnal de AUDIT, „gol" pe un fetch picat e exact minciuna de evitat
  const [auditErr, setAuditErr] = useState<{ msg: string; reset: boolean } | null>(null)
  const seq = useRef(0)

  // `reset` = filtre noi (pornim de la cel mai recent); altfel paginăm în trecut de la ts-ul
  // ultimei linii — offset-ul ar sări rânduri când apar acţiuni noi între cereri.
  // Generaţie monotonă (F-05): Enter în căutare + click pe Filtrează + „mai multe" pot porni
  // cereri suprapuse; răspunsul unei cereri VECHI (filtru anterior) nu mai are voie să
  // suprascrie lista sau să dubleze pagina. Adăugarea foloseşte starea curentă, nu closure-ul.
  async function loadAudit(reset: boolean) {
    const my = ++seq.current
    setAuditBusy(true)
    setAuditErr(null)
    try {
      const last = audit && audit.length ? audit[audit.length - 1] : null
      const before = reset || !last ? 0 : last.ts
      const qs = new URLSearchParams({ limit: String(AUDIT_PAGE) })
      if (before) qs.set('before', String(before))
      if (auditQ.trim()) qs.set('q', auditQ.trim())
      if (auditFailed) qs.set('failed_only', 'true')
      const r = await api<{ entries: AuditEntry[]; retention_days: number }>(`/api/audit?${qs}`)
      if (my !== seq.current) return          // a pornit o cerere mai nouă între timp
      setAuditDays(r.retention_days)
      setAuditEnd(r.entries.length < AUDIT_PAGE)
      setAudit((cur) => (reset ? r.entries : [...(cur ?? []), ...r.entries]))
    } catch (e) {
      // jurnalul e informativ — o eroare nu blochează Setările, dar se VEDE (cu Reîncearcă)
      if (my === seq.current) { setAuditErr({ msg: errText(e, t), reset }); if (reset) setAudit(null) }
    }
    if (my === seq.current) setAuditBusy(false)
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { loadAudit(true) }, [])   // încarcă la deschiderea tab-ului

  return (
    <div>
      <section data-setting-id="audit">
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
          <Button variant="primary" onClick={() => loadAudit(true)} disabled={auditBusy}>{t('settings.audit.filter')}</Button>
        </div>

        <ul className="mt-3 flex flex-col gap-1">
          {(audit ?? []).map((e, i) => (
            <li key={`${e.ts}-${i}`}
              className="rounded-md bg-ink-800/60 px-3 py-2 text-xs ring-1 ring-ink-700">
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

        {audit === null && !auditErr && (
          <p className="mt-3 text-xs text-slate-500">{t('settings.audit.loading')}</p>
        )}
        {auditErr && (
          <div className="mt-3 rounded-md ring-1 ring-ink-700">
            <LoadFailed compact message={auditErr.msg} onRetry={() => loadAudit(auditErr.reset)} />
          </div>
        )}
        {!auditErr && audit !== null && audit.length === 0 && (
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
      </section>
    </div>
  )
}
