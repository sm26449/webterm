import { useEffect, useState } from 'react'
import { api, Host, Session } from '../lib/api'
import { hostAt } from '../lib/host'
import { useI18n } from '../lib/i18n'
import SessionView from './SessionView'

/** Detached window: just the terminal, no sidebar. Drag it to another
    monitor. Connects to the same session (multi-device is native). */
export default function PopoutView(props: { sid: string }) {
  const { t } = useI18n()
  const [session, setSession] = useState<Session | null>(null)
  const [host, setHost] = useState<Host | undefined>(undefined)
  const [gone, setGone] = useState(false)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [sessions, hosts] = await Promise.all([
          api<Session[]>('/api/sessions'),
          api<Host[]>('/api/hosts'),
        ])
        if (!active) return
        const s = sessions.find((x) => x.id === props.sid) ?? null
        if (!s) {
          setGone(true)
          return
        }
        const h = hosts.find((x) => x.id === s.host_id)
        setSession(s)
        setHost(h)
        document.title = `${s.title || 'Terminal'}${h ? ' · ' + hostAt(h) : ''} · WebTerm`
      } catch {
        /* retry on next tick */
      }
    }
    load()
    const t = setInterval(() => { if (!document.hidden) load() }, 5000)
    return () => {
      active = false
      clearInterval(t)
    }
  }, [props.sid])

  if (gone) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 text-slate-500">
        <div className="text-lg">{t('popout.gone')}</div>
        <button onClick={() => window.close()} className="rounded-lg bg-ink-800 px-4 py-2 text-sm text-slate-300 hover:bg-ink-700">
          {t('popout.close')}
        </button>
      </div>
    )
  }
  if (!session) {
    return <div className="flex h-full items-center justify-center text-slate-500">{t('popout.connecting')}</div>
  }

  return (
    /* wt-workspace: cromul terminalului rămâne întunecat și pe tema Aurora,
       identic cu fereastra principală (tokenii dark se aplică prin clasă) */
    <div className="wt-workspace wt-main h-full">
      <SessionView
        session={session}
        host={host}
        popout
        onMenu={() => {}}
        onChanged={() => {}}
        onDeleted={() => window.close()}
      />
    </div>
  )
}
