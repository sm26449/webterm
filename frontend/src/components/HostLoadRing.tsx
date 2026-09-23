import { Host } from '../lib/api'
import { useI18n } from '../lib/i18n'

// Indicator fin de încărcare a host-ului activ, în toolbar: două arce concentrice — CPU (exterior)
// şi memorie (interior) — colorate după presiune. Citeşte metricile pe care app-ul le ia oricum la
// poll-ul de 5s (fără request-uri noi, fără atingere de agent/gateway). Se mişcă DOAR la update
// (tranziţie CSS), respectă `prefers-reduced-motion`, iar cifrele exacte stau în tooltip.
//
// Praguri de culoare = presiune, nu decor: verde <70% · chihlimbar <90% · roşu peste.
function color(p: number): string {
  return p < 70 ? '#10b981' : p < 90 ? '#f59e0b' : '#f43f5e'
}

export default function HostLoadRing(props: { host: Host }) {
  const { t } = useI18n()
  const m = props.host.metrics
  // arătăm doar când avem metrici reale (host cu agent online); SSH/telnet n-au → m e null
  if (!props.host.online || !m || m.cpu_pct == null) return null

  const cpu = Math.max(0, Math.min(100, Math.round(m.cpu_pct)))
  const mem = m.mem_total && m.mem_used != null
    ? Math.max(0, Math.min(100, Math.round((m.mem_used / m.mem_total) * 100)))
    : null
  const gb = (n?: number) => (n != null ? (n / 1024 / 1024 / 1024).toFixed(1) : '—')
  const load = [m.load1, m.load5, m.load15].map((x) => (x != null ? x.toFixed(2) : '—')).join(' · ')

  // pathLength=100 → dashoffset e direct „100 − procent", fără să calculăm circumferinţe
  const arc = 'transition-[stroke-dashoffset,stroke] duration-500 ease-out motion-reduce:transition-none'

  return (
    // role="img" pe wrapper: aria-label pe un div generic e nume ARIA interzis (ignorat de unele
    // cititoare); tabIndex + focus-within fac tooltip-ul (singurul loc cu cifrele exacte)
    // accesibil şi de la tastatură, nu doar pe hover
    <div className="group relative hidden shrink-0 items-center rounded px-1 focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-500 sm:flex"
      role="img" tabIndex={0} aria-label={t('loadring.aria', { cpu, mem: mem ?? '—' })}>
      <svg viewBox="0 0 40 40" className="h-6 w-6 -rotate-90" aria-hidden="true">
        {/* CPU — arc exterior */}
        <circle cx="20" cy="20" r="16" fill="none" strokeWidth="3.2" className="stroke-ink-700" />
        <circle cx="20" cy="20" r="16" fill="none" strokeWidth="3.2" strokeLinecap="round"
          pathLength={100} strokeDasharray="100" strokeDashoffset={100 - cpu}
          className={arc} style={{ stroke: color(cpu) }} />
        {/* Memorie — arc interior */}
        {mem != null && (<>
          <circle cx="20" cy="20" r="10.5" fill="none" strokeWidth="3.2" className="stroke-ink-700" />
          <circle cx="20" cy="20" r="10.5" fill="none" strokeWidth="3.2" strokeLinecap="round"
            pathLength={100} strokeDasharray="100" strokeDashoffset={100 - mem}
            className={arc} style={{ stroke: color(mem) }} />
        </>)}
      </svg>

      {/* tooltip: sub indicator (toolbarul e sus). Cifrele exacte, aliniate. */}
      <div role="tooltip"
        className="pointer-events-none absolute right-0 top-full z-20 mt-2 w-max rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-xs opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
        <div className="flex items-baseline justify-between gap-6">
          <span className="text-[11px] uppercase tracking-wide text-slate-500">{t('loadring.cpu')}</span>
          <span className="font-mono font-semibold tabular-nums" style={{ color: color(cpu) }}>{cpu}%</span>
        </div>
        {mem != null && (
          <div className="mt-1 flex items-baseline justify-between gap-6">
            <span className="text-[11px] uppercase tracking-wide text-slate-500">{t('loadring.memory')}</span>
            <span className="font-mono font-semibold tabular-nums" style={{ color: color(mem) }}>
              {gb(m.mem_used)} / {gb(m.mem_total)} GB
            </span>
          </div>
        )}
        {m.load1 != null && (
          <div className="mt-1 flex items-baseline justify-between gap-6">
            <span className="text-[11px] uppercase tracking-wide text-slate-500">{t('loadring.load')}</span>
            <span className="font-mono tabular-nums text-slate-300">{load}</span>
          </div>
        )}
        <div className="mt-1.5 border-t border-ink-800 pt-1.5 text-[11px] text-slate-500">
          {t('loadring.swapHint')}
        </div>
      </div>
    </div>
  )
}
