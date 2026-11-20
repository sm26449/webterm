import { useI18n } from '../../lib/i18n'
import { fmtTs } from '../../lib/tz'
import { edgeDuration, edgeRuleKey, edgeSources, edgeTelemetryKey, type EdgeState } from '../../lib/health'
import { Badge } from '../ui'

// 3.6.38: episodes of refused agent handshakes (edgeguard.py). Two sources, kept apart on purpose:
// a PROXY limit stopped the request before anyone checked its token (authentication unknown — it may
// be a legitimate agent in a reconnect storm), a GATEWAY refusal checked the token and rejected it.
export default function AgentHandshakes({ edge }: { edge: EdgeState }) {
  const { t } = useI18n()
  const tm = edge.telemetry
  const telKey = edgeTelemetryKey(tm)
  return (
    <div className="mt-3" data-testid="agent-handshakes">
      <h4 className="text-sm font-semibold">{t('health.edge.title')}</h4>
      <p className="mt-1 text-xs text-slate-500">{t('health.edge.hint', { interval: edge.interval, quiet: Math.round(edge.quiet / 60) })}</p>
      <p className={'mt-1 text-xs ' + (tm.error_since ? 'wt-warn' : 'text-slate-500')} role="status">
        {t(telKey, { since: tm.error_since ? fmtTs(tm.error_since) : '', when: tm.last_ok ? fmtTs(tm.last_ok) : '' })}
      </p>
      {edge.lists && (
        <p className="mt-1 text-xs text-slate-500">
          {!edge.lists.enabled ? t('health.edge.listsOff')
            : edge.lists.supported === false ? t(edge.lists.off_reason === 'proxy' ? 'health.edge.listsBehindProxy' : 'health.edge.listsNoHost')
              : t('health.edge.lists', { allow: edge.lists.allow, deny: edge.lists.deny })}
        </p>
      )}
      {(edge.blocked_now ?? 0) > 0 && (
        <p className="mt-1 text-xs wt-warn">{t('health.edge.blockedNow', { count: edge.blocked_now ?? 0 })}</p>
      )}
      {edge.episodes.length === 0 ? (
        <p className="mt-2 text-xs text-slate-500">{t('health.edge.none')}</p>
      ) : (
        <div className="mt-2 overflow-x-auto" role="region" aria-label={t('health.edge.title')} tabIndex={0}>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500">
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.edge.col.rule')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.edge.col.source')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.edge.col.started')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.edge.col.lastSeen')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.edge.col.duration')}</th>
                <th scope="col" className="py-1 pr-3 text-right font-normal">{t('health.edge.col.refused')}</th>
                <th scope="col" className="py-1 pr-3 font-normal">{t('health.edge.col.sources')}</th>
                <th scope="col" className="py-1 font-normal">{t('health.edge.col.state')}</th>
              </tr>
            </thead>
            <tbody>
              {edge.episodes.map((e) => (
                <tr key={e.id} className="border-t border-slate-700/40 align-top">
                  <td className="py-1.5 pr-3">{t(edgeRuleKey(e))}</td>
                  <td className="py-1.5 pr-3">
                    {t('health.edge.source.' + e.source)}
                    <span className="block text-slate-500">{t('health.edge.auth.' + e.auth)}</span>
                  </td>
                  <td className="py-1.5 pr-3 whitespace-nowrap">{fmtTs(e.started)}</td>
                  <td className="py-1.5 pr-3 whitespace-nowrap">{fmtTs(e.last_seen)}</td>
                  <td className="py-1.5 pr-3 whitespace-nowrap">{edgeDuration(e.duration, t)}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{e.count}</td>
                  <td className="py-1.5 pr-3 font-mono break-all" title={(e.sources ?? []).map(([k, n]) => `${k} ×${n}`).join('\n')}>
                    {edgeSources(e.sources, 3, t) || '—'}
                  </td>
                  <td className="py-1.5">
                    <Badge tone={e.active ? (e.source === 'proxy' ? 'warn' : 'info') : 'neutral'}>
                      {t(e.active ? 'health.edge.active' : 'health.edge.ended')}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
