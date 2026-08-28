import { useEffect, useRef, useState } from 'react'
import { getBootVersion, getChangelog } from '../lib/api'
import { Block, Span, parseChangelog } from '../lib/changelog'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

// „Ce e nou" — CHANGELOG-ul randat în WebTerm, ca utilizatorul să vadă noutăţile fără să
// plece pe GitHub. Textul e Markdown de încredere (fişier din imagine, servit autentificat),
// dar îl randăm ca NODURI, nu ca HTML — zero suprafaţă de injectare.
function Spans({ spans }: { spans: Span[] }) {
  return (
    <>
      {spans.map((s, i) =>
        s.bold ? <strong key={i} className="font-semibold text-slate-100">{s.text}</strong>
          : s.code ? <code key={i} className="rounded bg-ink-800 px-1 py-0.5 text-[0.85em] text-sky-300">{s.text}</code>
            : <span key={i}>{s.text}</span>,
      )}
    </>
  )
}

function renderBlock(b: Block, i: number) {
  switch (b.kind) {
    case 'version':
      return (
        <h3 key={i} className={`mt-6 flex items-baseline gap-2 border-t border-ink-800 pt-4 text-base font-semibold first:mt-0 first:border-0 first:pt-0 ${b.current ? 'text-sky-300' : 'text-slate-100'}`}>
          {b.text}
        </h3>
      )
    case 'section':
      return <h4 key={i} className="mt-4 text-sm font-semibold text-slate-300">{b.text}</h4>
    case 'item':
      return (
        <li key={i} className="ml-4 list-disc text-[13px] leading-relaxed text-slate-400 marker:text-slate-600">
          <Spans spans={b.spans} />
        </li>
      )
    default:
      return <p key={i} className="mt-2 text-[13px] leading-relaxed text-slate-400"><Spans spans={b.spans} /></p>
  }
}

export default function ChangelogModal(props: { onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [blocks, setBlocks] = useState<Block[] | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let alive = true
    getChangelog()
      .then((r) => { if (alive) setBlocks(parseChangelog(r.text, r.version || getBootVersion())) })
      .catch(() => { if (alive) setError(true) })
    return () => { alive = false }
  }, [])

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 p-4" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('changelog.aria')}
        className="glass flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-ink-800 px-5 py-3.5">
          <h2 className="text-base font-semibold">{t('changelog.title')}</h2>
          <button onClick={props.onClose} aria-label={t('common.close')} className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {error
            ? <p className="text-sm text-slate-400">{t('changelog.error')}</p>
            : blocks === null
              ? <p className="text-sm text-slate-500">{t('changelog.loading')}</p>
              : <ul className="space-y-0.5">{blocks.map(renderBlock)}</ul>}
        </div>
      </div>
    </div>
  )
}
