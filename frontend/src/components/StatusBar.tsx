import { useEffect, useState } from 'react'
import { Host, Session } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { getTimezone, timeInZone, uiLocale } from '../lib/tz'
import { copyText } from '../lib/clipboard'

// trebuie să corespundă cu agentul: tmux -L <socket>, sesiune <prefix><sid>
const TMUX_SOCKET = 'webterm'
const TMUX_PREFIX = 'wt-'

function fmt(epoch: number | null): string {
  if (!epoch) return '—'
  try {
    return new Intl.DateTimeFormat(uiLocale(), {
      timeZone: getTimezone(), day: '2-digit', month: 'short',
      hour: '2-digit', minute: '2-digit',
    }).format(new Date(epoch * 1000))
  } catch {
    return new Date(epoch * 1000).toLocaleString()
  }
}

function duration(from: number, to: number): string {
  const s = Math.max(0, Math.round(to - from))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${Math.floor(s / 86400)}z ${Math.floor((s % 86400) / 3600)}h`
}

// scurtează calea pentru afișare: ~/… pentru home, altfel …/ultimele/2/segmente
function shortPath(p: string): string {
  const home = p.match(/^\/(?:home|Users|root)(?:\/[^/]+)?/)
  let s = p
  if (home && p.startsWith(home[0])) s = '~' + p.slice(home[0].length)
  const parts = s.split('/').filter(Boolean)
  if (parts.length > 3) return (s.startsWith('~') ? '~/…/' : '…/') + parts.slice(-2).join('/')
  return s
}

export default function StatusBar(props: { session: Session; host?: Host; rtt?: number | null; cwd?: string | null }) {
  const { t } = useI18n()
  const { session: s, host } = props
  const [showAttach, setShowAttach] = useState(false)
  const [copied, setCopied] = useState(false)

  const live = s.state === 'live' || s.state === 'creating'
  // „durată" pentru sesiunile vii curge la fiecare 30s — altfel rămâne
  // înghețată la momentul ultimului render (poate arăta ore în urmă)
  const [, tick] = useState(0)
  useEffect(() => {
    if (!live) return
    const t = setInterval(() => tick((n) => n + 1), 30000)
    return () => clearInterval(t)
  }, [live])
  // ceasul din fusul sesiunii (tick la 30s ca mai sus — minutele sunt de ajuns)
  const clock = timeInZone(getTimezone())
  const now = Date.now() / 1000
  const durText = duration(s.created, s.closed_at ?? now)

  const attachOneLiner =
    host && host.backend === 'tmux'
      ? `ssh -t ${host.agent_user ?? 'user'}@${host.hostname ?? 'host'} 'tmux -L ${TMUX_SOCKET} attach -t ${TMUX_PREFIX}${s.id}'`
      : null

  // Sesiunea trece pe `lost` abia după 180s (2 × heartbeat stale). În fereastra aia bara
  // afişa „Active" cu punct verde pulsând, deşi tastele nu mai ajungeau nicăieri — iar
  // ACEEAŞI pagină ştia deja: hostul apare offline în ~10 secunde. Aveam `host` în props
  // (îl foloseam pentru one-linerul de attach) şi nu-l citeam.
  const hostDown = s.state === 'live' && host && host.online === false
  const stateLabel =
    hostDown ? t('statusbar.stateHostOffline') :
    s.state === 'live' ? t('statusbar.stateLive') :
    s.state === 'creating' ? t('statusbar.stateCreating') :
    s.state === 'lost' ? t('statusbar.stateLost') : t('statusbar.stateClosed')
  const stateColor =
    hostDown ? 'wt-warn' :
    s.state === 'live' ? 'wt-good' :
    s.state === 'lost' ? 'wt-danger' : 'text-slate-500'

  return (
    <div className="wt-compact-y border-t border-ink-800 bg-ink-900 text-[11px] text-slate-400">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-1.5">
        <span className={`inline-flex items-center gap-1.5 font-medium ${stateColor}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${hostDown ? 'bg-amber-500' : live ? 'bg-emerald-500 dot-live' : s.state === 'lost' ? 'bg-rose-500' : 'bg-slate-500'}`} />
          {stateLabel}
        </span>
        {/* Hostul n-are tmux → sesiunea asta NU supravieţuieşte unei căderi de agent sau
            de reţea. Bara e locul în care omul se uită cât munceşte, deci e locul unde
            trebuie spus — nu doar în pagina hostului, pe care o deschizi o dată. */}
        {host?.backend === 'pty' && (
          <span className="wt-warn font-medium" title={t('statusbar.noTmuxTitle')}>
            {t('statusbar.noTmux')}
          </span>
        )}
        <span className="tabular-nums">{t('statusbar.startLabel')} {fmt(s.created)}</span>
        {s.closed_at && <span className="tabular-nums">{t('statusbar.finalLabel')} {fmt(s.closed_at)}</span>}
        <span className="tabular-nums">{t('statusbar.duration')} {durText}</span>
        {s.exit_status !== null && s.exit_status !== undefined && (
          <span className="tabular-nums">{t('statusbar.exitLabel')} {s.exit_status}</span>
        )}
        {/* alte dispozitive/ferestre atașate la ACEEAȘI sesiune: știi că
            telefonul sau un link de share privește înainte să tastezi o parolă */}
        {s.connected_clients > 1 && (
          <span
            className="wt-warn tabular-nums"
            title={t('statusbar.watchersTitle')}
          >
            {t('statusbar.watchers', { count: s.connected_clients })}
          </span>
        )}
        {/* ceasul serverului, în fusul sesiunii — răspunde la „cât e ceasul
            acolo?" fără să tastezi `date` în mijlocul unei comenzi */}
        {live && <span className="tabular-nums" title={t('statusbar.clockTitle', { tz: getTimezone() })}>🕒 {clock}</span>}
        {/* cwd raportat de shell prin OSC 7 — apare doar cu shell integration
            activă; panoul de fișiere urmărește aceeași cale */}
        {live && props.cwd && (
          <span className="min-w-0 max-w-[16rem] truncate font-mono wt-link" title={props.cwd}>
            📁 {shortPath(props.cwd)}
          </span>
        )}
        {props.rtt != null && (
          /* latența browser↔gateway pe websocket-ul sesiunii, sondată la 30s */
          <span
            className={`tabular-nums ${props.rtt < 120 ? 'wt-good' : props.rtt < 350 ? 'wt-warn' : 'wt-danger'}`}
            title={t('statusbar.rttTitle')}
          >
            ⇅ {props.rtt} ms
          </span>
        )}
        {attachOneLiner && (
          <button
            onClick={() => setShowAttach((v) => !v)}
            className="wt-link ml-auto rounded px-1.5 py-0.5 hover:bg-ink-800"
            title={t('statusbar.attachTitle')}
          >
            {/* „⌘" sugera tasta Cmd — eticheta spune acum ce face de fapt */}
            {showAttach ? t('statusbar.hide') : t('statusbar.attachSsh')}
          </button>
        )}
      </div>

      {showAttach && attachOneLiner && (
        <div className="border-t border-ink-800 px-3 py-2">
          <p className="mb-1.5 text-slate-500">
            {t('statusbar.attachIntro')}
          </p>
          <div className="flex items-stretch gap-2">
            <code className="flex-1 overflow-x-auto whitespace-nowrap rounded-md bg-black/40 px-2 py-1.5 font-mono text-[11px] text-emerald-400">
              {attachOneLiner}
            </code>
            <button
              onClick={async () => {
                try {
                  if (await copyText(attachOneLiner)) {
                    setCopied(true)
                    setTimeout(() => setCopied(false), 1500)
                  }
                } catch {
                  /* origine http / permisiune refuzată: selectează manual */
                }
              }}
              className="shrink-0 rounded-md bg-sky-600 px-2 text-xs font-medium text-white hover:bg-sky-700"
            >
              {copied ? '✓' : t('statusbar.copy')}
            </button>
          </div>
          <p className="mt-1.5 text-slate-600">
            {t('statusbar.detachHintBefore')}
            <code className="mx-1 font-mono text-slate-500">Ctrl-d</code>
            {t('statusbar.detachHintAfter')}
          </p>
        </div>
      )}
    </div>
  )
}
