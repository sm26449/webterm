import { useEffect, useRef, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { fmtTs } from '../../lib/tz'
import { field } from './ui'
import LoadFailed from '../LoadFailed'
import { Button, Field, SettingsSection } from '../ui'
import HelpTip from '../HelpTip'
import SectionLoading from './SectionLoading'
import { can, usePerms } from '../../lib/perms'

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
  // 3.7.1 (audit UX Setări Codex #10 / Me5): ce acoperă lista. Fără `audit.view` serverul întoarce
  // DOAR rândurile tale; „Nothing recorded yet" îl făcea pe un Viewer să creadă că instanţa n-are
  // activitate. Filtrele aplicate la ultima încărcare decid între „nimic încă" şi „nimic pentru filtre".
  const perms = usePerms()
  const instance = can(perms, 'audit.view')
  const [filtered, setFiltered] = useState(false)

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
      const withFilters = !!auditQ.trim() || auditFailed
      const r = await api<{ entries: AuditEntry[]; retention_days: number }>(`/api/audit?${qs}`)
      if (my !== seq.current) return          // a pornit o cerere mai nouă între timp
      setAuditDays(r.retention_days)
      if (reset) setFiltered(withFilters)
      setAuditEnd(r.entries.length < AUDIT_PAGE)
      setAudit((cur) => (reset ? r.entries : [...(cur ?? []), ...r.entries]))
    } catch (e) {
      // jurnalul e informativ — o eroare nu blochează Setările, dar se VEDE (cu Reîncearcă)
      if (my === seq.current) { setAuditErr({ msg: errText(e, t), reset }); if (reset) setAudit(null) }
    }
    if (my === seq.current) setAuditBusy(false)
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { void loadAudit(true) }, [])   // încarcă la deschiderea tab-ului

  return (
    <div>
      <SettingsSection data-setting-id="audit" title={instance ? t('settings.audit.titleInstance') : t('settings.audit.titleMine')}
        titleExtra={<HelpTip id="audit" />} instanceWide={instance}
        description={instance ? t('settings.audit.hint') : t('settings.audit.hintMine')}>
        <form className="flex flex-wrap items-end gap-2" aria-label={t('settings.audit.searchAria')}
          onSubmit={(e) => { e.preventDefault(); void loadAudit(true) }}>
          <Field label={t('settings.audit.search')} className="min-w-40 flex-1">
            <input
              value={auditQ}
              onChange={(e) => setAuditQ(e.target.value)}
              placeholder={t('settings.audit.searchPlaceholder')}
              spellCheck={false}
              className={field}
            />
          </Field>
          {/* bifa (nu comutator): e un filtru aplicat cu „Filter", ca şi căutarea */}
          <label className="flex min-h-9 items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={auditFailed}
              onChange={(e) => { setAuditFailed(e.target.checked) }} />
            {t('settings.audit.failedOnly')}
          </label>
          <Button variant="primary" type="submit" disabled={auditBusy}>{t('settings.audit.filter')}</Button>
        </form>

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

        {audit === null && !auditErr && <SectionLoading className="mt-3" />}
        {auditErr && (
          <div className="mt-3 rounded-md ring-1 ring-ink-700">
            <LoadFailed compact message={auditErr.msg} onRetry={() => loadAudit(auditErr.reset)} />
          </div>
        )}
        {!auditErr && audit !== null && audit.length === 0 && (
          <p className="mt-3 text-xs text-slate-500" data-audit-empty={filtered ? 'filtered' : 'none'}>
            {filtered ? t('settings.audit.noMatch') : instance ? t('settings.audit.empty') : t('settings.audit.emptyMine')}
          </p>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {!auditEnd && audit !== null && audit.length > 0 && (
            <Button type="button" variant="secondary" size="sm" onClick={() => loadAudit(false)} loading={auditBusy}>
              {t('settings.audit.more')}
            </Button>
          )}
          {auditDays > 0 && (
            <span className="text-xs text-slate-500">{t('settings.audit.retention', { days: auditDays })}</span>
          )}
        </div>
      </SettingsSection>
    </div>
  )
}
