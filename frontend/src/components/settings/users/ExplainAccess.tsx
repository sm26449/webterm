import { useEffect, useId, useState } from 'react'
import { api, errText, Host } from '../../../lib/api'
import { useI18n } from '../../../lib/i18n'
import { roleLabel, scopeLabel } from '../../../lib/perms'
import { capabilities, type Explain, type ExplainBinding } from '../../../lib/usersAdmin'
import { field } from '../ui'
import { Badge } from '../../ui'
import { CrownIcon } from '../../Icons'
import { useExpiryText } from './shared'

/* „Explain access" (3.6.10, docs/ROLES.md#explain-access): de ce poate (sau nu poate) un cont ce
   poate pe UN host. Doar citeşte GET /api/authz/explain — serverul decide cine are voie să întrebe
   (contul însuşi; altul doar cu users.manage) şi răspunde 404 pentru un host pe care cel care
   întreabă nu-l vede. Lista de hosturi de aici e oricum cea pe care o vede el (/api/hosts).

   Răspunsul se citeşte ca o propoziţie: „Ana poate deschide terminale pe web01 datorită:
   Operator · tag db (grupul SSO wt-db)", apoi permisiunile efective şi notele (expirat, 2FA,
   crown-jewel, tokenuri plafonate). */

export default function ExplainAccess(props: { userId: number; email: string; self: boolean; hosts: Host[] }) {
  const { t } = useI18n()
  const uid = useId()
  const [hostId, setHostId] = useState<number | ''>('')
  const [data, setData] = useState<Explain | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const expiryText = useExpiryText()
  const hostName = (id: number) => props.hosts.find((h) => h.id === id)?.name

  useEffect(() => {
    if (hostId === '') { setData(null); return }
    let live = true
    setLoading(true); setErr('')
    api<Explain>(`/api/authz/explain?user=${props.userId}&host=${hostId}`)
      .then((r) => { if (live) setData(r) })
      .catch((e) => { if (live) { setData(null); setErr(errText(e, t)) } })
      .finally(() => { if (live) setLoading(false) })
    return () => { live = false }
  }, [hostId, props.userId])   // eslint-disable-line react-hooks/exhaustive-deps

  const who = props.self ? t('explain.you') : props.email
  const source = (b: ExplainBinding) => {
    if (b.source === 'sso') {
      return b.sso_groups?.length ? t('explain.fromSso', { groups: b.sso_groups.join(', ') }) : t('explain.fromSsoUnknown')
    }
    return b.source === 'migration' ? t('explain.migration') : t('explain.manual')
  }
  const what = data ? capabilities(data.effective).map((k) => t('explain.can.' + k)).join(', ') : ''

  return (
    <div className="flex flex-col gap-2" data-explain>
      <p className="text-xs text-slate-500">{t('explain.hint')}</p>
      <select value={hostId} aria-label={t('explain.pickHost')} className={field + ' sm:w-64'} data-explain-host
        onChange={(e) => setHostId(e.target.value ? Number(e.target.value) : '')}>
        <option value="">{t('explain.pickHost')}</option>
        {props.hosts.filter((h) => !h.ephemeral).map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
      </select>
      <div aria-live="polite" id={`${uid}-out`}>
        {loading && <p className="text-xs text-slate-400">{t('explain.loading')}</p>}
        {err && <p role="alert" className="text-sm wt-danger">{err}</p>}
        {data && !loading && (
          <div className="flex flex-col gap-2 rounded-md bg-ink-900/60 p-3 ring-1 ring-ink-700" data-explain-result>
            <p className="text-sm text-slate-200">
              {data.effective.length
                ? t('explain.summaryCan', { who, what, host: data.host.name })
                : t('explain.summaryNone', { who, host: data.host.name })}
              {data.host.crown_jewel && (
                <span role="img" aria-label={t('crown.badgeAria', { name: data.host.name })} title={t('crown.badge')}
                  className="ml-1.5 inline-flex align-middle text-warn"><CrownIcon /></span>
              )}
            </p>
            {data.bindings.length > 0 && (
              <ul className="flex flex-col gap-1.5">
                {data.bindings.map((b) => (
                  <li key={b.id} className={`flex flex-col gap-1 rounded-md px-2 py-1.5 ring-1 ring-ink-700 ${b.expired ? 'opacity-60' : ''}`}>
                    <div className="flex flex-wrap items-center gap-1.5 text-sm">
                      <Badge tone={b.role === 'owner' ? 'accent' : 'neutral'} size="md">
                        {t('roles.chip', { role: roleLabel(b, t), scope: scopeLabel(b, hostName, t) })}
                      </Badge>
                      <span className="text-xs text-slate-400">({source(b)})</span>
                      {b.expires && <span className={`text-xs ${b.expired ? 'text-warn' : 'text-slate-400'}`}>{expiryText(b.expires)}</span>}
                      {b.shell && !b.expired && <Badge tone="warn" title={t('roles.shellHint')}>{t('roles.shell')}</Badge>}
                    </div>
                    <p className="break-words font-mono text-2xs text-slate-500">{b.perms.join(' · ')}</p>
                  </li>
                ))}
              </ul>
            )}
            {data.effective.length > 0 && (
              <details className="text-xs text-slate-400">
                <summary className="cursor-pointer">{t('explain.effective')} ({data.effective.length})</summary>
                <p className="mt-1 break-words font-mono text-2xs">{data.effective.join(' · ')}</p>
              </details>
            )}
            {data.notes.length > 0 && (
              <ul className="flex flex-col gap-1 text-xs text-slate-400" data-explain-notes>
                {data.notes.map((n, i) => (
                  <li key={i} className={n.code === 'crownJewel' || n.code === 'expiredIgnored' ? 'text-warn' : ''}>
                    {t('explain.note.' + n.code, { n: n.n ?? 0 })}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
