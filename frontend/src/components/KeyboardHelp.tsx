import { useRef } from 'react'
import { fmt, SHORTCUTS } from '../lib/shortcuts'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useI18n } from '../lib/i18n'

/** Cheatsheet-ul de scurtături („?"). Se generează DIN registru, deci nu poate
    rămâne în urma codului. Grupat pe: Navigare / Sesiune / Aplicație. */
// Scurtături „display-only": familii de taste (nu o singură tastă) tratate de
// handlere dedicate în App, nu de matcher-ul din registru. Le arătăm aici ca să
// fie descoperibile, fără să polueze registrul cu N intrări. Vezi App.tsx (Alt+1..9).
const EXTRA: Record<string, { labelKey: string; keys: string }[]> = {
  nav: [{ labelKey: 'shortcuts.jumpToTab', keys: 'Alt+1…9' }],
}

// numele grupului e și identificator (filtrează SHORTCUTS după s.group) — nu-l
// traducem la sursă, ci doar la afișare, printr-o hartă cheie→cheie de catalog
const GROUP_KEY: Record<string, string> = {
  nav: 'shortcuts.groupNav',
  session: 'shortcuts.groupSession',
  app: 'shortcuts.groupApp',
}

export default function KeyboardHelp(props: { onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const groups = ['nav', 'session', 'app'] as const

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('shortcuts.title')}
        onClick={(e) => e.stopPropagation()}
        className="glass max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-2xl p-6"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('shortcuts.heading')}</h2>
          <button onClick={props.onClose} aria-label={t('common.close')} className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
            ✕
          </button>
        </div>

        {groups.map((g) => (
          <div key={g} className="mt-5">
            <h3 className="text-[13px] font-semibold uppercase tracking-wide text-slate-400">{t(GROUP_KEY[g])}</h3>
            <dl className="mt-2 divide-y divide-ink-800 text-sm">
              {SHORTCUTS.filter((s) => s.group === g).map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-4 py-2">
                  <dt className="min-w-0 text-slate-300">{t('shortcut.' + s.id)}</dt>
                  <dd className="shrink-0">
                    <kbd className="rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-300 ring-1 ring-ink-700">
                      {fmt(s.keys)}
                    </kbd>
                  </dd>
                </div>
              ))}
              {(EXTRA[g] ?? []).map((s) => (
                <div key={s.keys} className="flex items-center justify-between gap-4 py-2">
                  <dt className="min-w-0 text-slate-300">{t(s.labelKey)}</dt>
                  <dd className="shrink-0">
                    <kbd className="rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-300 ring-1 ring-ink-700">
                      {fmt(s.keys)}
                    </kbd>
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        ))}

        <p className="mt-5 text-xs text-slate-500">
          {t('shortcuts.footer1')} <code className="font-mono">Ctrl+C</code> {t('shortcuts.footer2')}{' '}
          <code className="font-mono">Ctrl+R</code> {t('shortcuts.footer3')}{' '}
          <code className="font-mono">{fmt('Mod')}+Shift</code> {t('shortcuts.footer4')}{' '}
          <code className="font-mono">{fmt('Alt')}</code>{t('shortcuts.footer5')}
        </p>
      </div>
    </div>
  )
}
