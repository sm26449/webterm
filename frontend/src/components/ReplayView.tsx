import { useEffect, useMemo, useState } from 'react'
import { WatermarkConfig } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { replayHeaders } from '../lib/replay'
import { fmtTs } from '../lib/tz'
import { LogoMark, ShieldIcon } from './Icons'
import TranscriptPlayer from './TranscriptPlayer'
import Watermark from './Watermark'

type Meta = {
  title: string
  label: string
  redact: boolean
  expires: number
  started: number | null
  closed_at: number | null
  watermark?: WatermarkConfig | null
}

/** Cerere publică: tokenul DOAR în antet, fără cookie (`credentials: 'omit'` — pagina nu are
    nevoie de sesiunea cuiva, iar un owner logat care îşi deschide propriul link nu trebuie să-l
    vadă altfel decât invitatul), fără cache. */
async function pub(path: string, token: string): Promise<Response> {
  const r = await fetch(path, { headers: replayHeaders(token), credentials: 'omit', cache: 'no-store' })
  if (!r.ok) throw Object.assign(new Error(String(r.status)), { status: r.status })
  return r
}

/** Pune (sau refoloseşte) un <meta name=…> în <head> — noindex / no-referrer pe pagina publică. */
function setMeta(name: string, content: string) {
  let m = document.head.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)
  if (!m) {
    m = document.createElement('meta')
    m.name = name
    document.head.appendChild(m)
  }
  m.content = content
}

/** Pagina PUBLICĂ a unui link de replay (`#/replay/<token>`, 3.5.12): doar player-ul acelei
    înregistrări — fără cont, fără restul aplicaţiei, fără alte apeluri API. Tokenul stă în
    fragment (nu pleacă la server la încărcare, nu apare în Referer) şi călătoreşte în antetul
    `X-Replay-Token`. Orice eşec (necunoscut / expirat / revocat) arată ACEEAŞI pagină. */
export default function ReplayView(props: { token: string }) {
  const { t } = useI18n()
  const [meta, setMetaState] = useState<Meta | null>(null)
  const [failed, setFailed] = useState<'' | 'invalid' | 'busy'>('')

  useEffect(() => {
    setMeta('robots', 'noindex, nofollow')
    setMeta('referrer', 'no-referrer')
  }, [])

  useEffect(() => {
    let alive = true
    pub('/api/replay/meta', props.token)
      .then((r) => r.json())
      .then((m: Meta) => {
        if (!alive) return
        setMetaState(m)
        document.title = t('replay.docTitle', { title: m.title || t('transcript.sessionFallback') })
      })
      .catch((e: { status?: number }) => {
        if (!alive) return
        setFailed(e?.status === 429 ? 'busy' : 'invalid')
        document.title = t('replay.invalidTitle')
      })
    return () => { alive = false }
  }, [props.token, t])

  // stabil pe toată durata paginii: player-ul îşi încarcă înregistrarea o singură dată
  const source = useMemo(() => ({
    cast: () => pub('/api/replay/cast', props.token).then((r) => r.text()),
    text: () => pub('/api/replay/text', props.token).then((r) => r.text()),
  }), [props.token])

  if (failed) {
    return (
      <main className="wt-workspace flex h-full flex-col items-center justify-center gap-3 bg-ink-950 px-4 text-center"
        data-testid="replay-invalid">
        <LogoMark size={40} />
        <h1 className="text-lg font-semibold text-slate-100">
          {failed === 'busy' ? t('replay.busyTitle') : t('replay.invalidTitle')}
        </h1>
        <p className="max-w-sm text-sm text-slate-400">
          {failed === 'busy' ? t('replay.busyBody') : t('replay.invalidBody')}
        </p>
      </main>
    )
  }

  return (
    <div className="wt-workspace flex h-full flex-col bg-ink-950">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-ink-800 bg-ink-900 px-4 py-2">
        <LogoMark size={20} />
        <h1 className="min-w-0 truncate text-sm font-medium text-slate-200">
          {meta ? (meta.title || t('transcript.sessionFallback')) : t('replay.loading')}
        </h1>
        <span className="shrink-0 rounded-md bg-ink-800 px-2 py-0.5 text-2xs text-slate-300">{t('replay.publicBadge')}</span>
        {meta?.label && <span className="min-w-0 truncate text-xs text-slate-400">{meta.label}</span>}
        {meta && (
          <span className="ml-auto flex shrink-0 items-center gap-2 text-2xs text-slate-400">
            {meta.redact && (
              <span className="flex items-center gap-1" title={t('replay.maskedNoticeHint')}>
                <ShieldIcon size={12} /> {t('replay.maskedNotice')}
              </span>
            )}
            <span>{t('replay.expiresAt', { time: fmtTs(meta.expires) })}</span>
          </span>
        )}
      </header>
      <main className="flex min-h-0 flex-1 flex-col">
        {meta && (
          <TranscriptPlayer sid="replay" title={meta.title} source={source} embedded />
        )}
      </main>
      <Watermark config={meta?.watermark ?? null} />
    </div>
  )
}
