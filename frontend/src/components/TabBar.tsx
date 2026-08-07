import { isSessionLive, Host, Session } from '../lib/api'
import { hostColor } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { CloseIcon, HomeIcon } from './Icons'

/** Sesiunile deschise ca tab-uri (setul de lucru), pe cromul întunecat.
   Fiecare tab arată host-ul (nume + culoare stabilă) ca să distingi instant
   „htop pe core-rtr-01" de „htop pe edge-fw-01". */
export default function TabBar(props: {
  tabs: Session[]
  activeSid: string | null
  activity: Set<string>
  hosts: Host[]
  sort: 'manual' | 'activity'
  onToggleSort: () => void
  onHome: () => void
  onSelect: (sid: string) => void
  onClose: (sid: string) => void
}) {
  const { t } = useI18n()
  return (
    <nav aria-label={t('tabbar.openSessions')} className="wt-tabstrip flex items-stretch gap-0.5 overflow-x-auto px-2 pt-1.5">
      <button
        onClick={props.onHome}
        title={t('tabbar.home')}
        aria-label={t('tabbar.home')}
        className={`wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center justify-center rounded-lg px-2.5 py-1.5 ${
          props.activeSid === null ? 'is-active' : ''
        }`}
      >
        <HomeIcon />
      </button>
      {/* ordinea taburilor DESCHISE: manual (stabil) ↔ activitate (ultima folosire). Opt-in. */}
      {props.tabs.length > 1 && (
        <button
          onClick={props.onToggleSort}
          title={props.sort === 'activity'
            ? t('tabbar.sortByActivityTitle')
            : t('tabbar.sortManualTitle')}
          aria-label={t('tabbar.toggleSort')}
          aria-pressed={props.sort === 'activity'}
          className={`wt-touch wt-tabbtn mb-1.5 flex shrink-0 items-center gap-1 rounded-lg px-2 py-1.5 text-[11px] ${
            props.sort === 'activity' ? 'is-active' : 'text-slate-500'}`}
        >
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"
            strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M4 3v10M4 3 2 5.2M4 3l2 2.2M12 13V3M12 13l-2-2.2M12 13l2-2.2" />
          </svg>
          {props.sort === 'activity' ? t('tabbar.activity') : t('tabbar.manual')}
        </button>
      )}
      <span className="mx-1 my-2 w-px shrink-0 bg-white/10" aria-hidden="true" />
      <div role="group" aria-label={t('tabbar.openSessions')} className="flex items-stretch gap-0.5">
        {props.tabs.map((s) => {
          const active = s.id === props.activeSid
          const hasActivity = !active && props.activity.has(s.id)
          const live = isSessionLive(s, props.hosts)
          const host = props.hosts.find((h) => h.id === s.host_id)
          const color = host ? hostColor(host) : '#64748b'
          // sesiune închisă cu exit ≠ 0: punct roșu, nu gri — o comandă care a
          // eșuat nu arată la fel ca una terminată normal
          const failed = !live && s.exit_status != null && s.exit_status !== 0
          const stateDot = live ? 'dot-live' : (s.state === 'lost' || failed) ? 'bg-rose-500' : ''
          return (
            <div
              key={s.id}
              style={active ? { background: `color-mix(in srgb, ${color} 18%, var(--chrome-elev))` } : undefined}
              className={`wt-tab group mb-1.5 flex shrink-0 items-stretch rounded-lg ${active ? 'is-active' : ''}`}
            >
              {/* accent vertical = identitatea host-ului (estompat când nu e activ) */}
              <span
                className={`my-[7px] ml-1.5 w-[3px] shrink-0 rounded-full transition-opacity ${active ? '' : 'opacity-45 group-hover:opacity-80'}`}
                style={{ background: color }}
                aria-hidden="true"
              />
              <button
                data-tab={s.id}
                aria-current={active ? 'page' : undefined}
                onClick={() => props.onSelect(s.id)}
                title={`${s.title || t('tabbar.session')}${host ? ` · ${host.name}` : ''}${hasActivity ? ` · ${t('tabbar.newOutput')}` : ''}${failed ? ` · exit ${s.exit_status}` : ''}`}
                className="flex min-w-0 flex-col justify-center py-1 pl-2 pr-1 text-left"
              >
                <span className="flex items-center gap-1.5 text-sm leading-tight">
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${stateDot}`}
                    title={failed ? t('tabbar.closedWithExit', { code: s.exit_status ?? '' }) : undefined}
                    style={live ? { background: color } : (s.state === 'lost' || failed) ? undefined : { background: '#475569' }}
                  />
                  <span className="max-w-[148px] truncate">{s.title || t('tabbar.session')}</span>
                  {/* output sosit cât tab-ul era în fundal (ambră ≠ culorile de host) */}
                  {hasActivity && (
                    <span data-activity className="h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400"
                      role="status" aria-label={t('tabbar.newOutput')} />
                  )}
                </span>
                {host && (
                  <span className="mt-0.5 max-w-[160px] truncate text-[11px] font-medium leading-none" style={{ color }}>
                    {host.name}
                  </span>
                )}
              </button>
              <button
                onClick={() => props.onClose(s.id)}
                title={t('tabbar.closeTabTitle')}
                aria-label={t('tabbar.closeTab')}
                className="wt-touch wt-tabbtn mr-1 mt-0.5 grid shrink-0 place-items-center self-start rounded p-1 opacity-0 focus-visible:opacity-100 group-hover:opacity-100 [@media(hover:none)]:opacity-100"
              >
                <CloseIcon size={13} />
              </button>
            </div>
          )
        })}
      </div>
    </nav>
  )
}
