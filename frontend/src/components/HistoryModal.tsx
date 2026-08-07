import { useEffect, useMemo, useRef, useState } from 'react'
import { api, Host } from '../lib/api'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useI18n } from '../lib/i18n'
import { copyText } from '../lib/clipboard'

type HistItem = {
  id: number
  host_id: number | null
  host_name: string
  command: string
  exit_code: number | null
  cwd: string
  source: string
  created: number
}

/** Istoric global de comenzi: caută în toate comenzile rulate (interactive + pe
    flotă), pe toate hosturile și sesiunile. E și un audit-log ușor. */
export default function HistoryModal(props: { hosts: Host[]; onClose: () => void }) {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  const [hostId, setHostId] = useState<number | null>(null)
  const [items, setItems] = useState<HistItem[] | null>(null)
  const [copied, setCopied] = useState<number | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  useEffect(() => { setTimeout(() => inputRef.current?.focus(), 0) }, [])

  // debounce pe căutare + filtru
  useEffect(() => {
    const t = setTimeout(() => {
      const p = new URLSearchParams()
      if (q.trim()) p.set('q', q.trim())
      if (hostId != null) p.set('host_id', String(hostId))
      p.set('limit', '300')
      api<HistItem[]>(`/api/history?${p.toString()}`).then(setItems).catch(() => setItems([]))
    }, 200)
    return () => clearTimeout(t)
  }, [q, hostId])

  async function copy(it: HistItem) {
    if (!await copyText(it.command)) return      // fără bifă când copierea a eşuat
    setCopied(it.id); setTimeout(() => setCopied((c) => (c === it.id ? null : c)), 1400)
  }
  async function clearAll() {
    setConfirmClear(false)
    await api('/api/history', { method: 'DELETE' }).catch(() => {})
    setItems([])
  }

  const rel = (t: number) => {
    const s = Math.max(0, Math.floor(Date.now() / 1000 - t))
    if (s < 60) return `${s}s`
    if (s < 3600) return `${Math.floor(s / 60)}m`
    if (s < 86400) return `${Math.floor(s / 3600)}h`
    return `${Math.floor(s / 86400)}z`
  }
  const hostsWithHistory = useMemo(() => props.hosts, [props.hosts])

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center bg-black/50 p-4 pt-[10vh]">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('history.title')}
        className="flex max-h-[80vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-ink-700 bg-ink-900 shadow-2xl">
        <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} spellCheck={false}
            placeholder={t('history.searchPlaceholder')} aria-label={t('history.searchAria')}
            className="min-w-0 flex-1 bg-transparent px-1 py-1 text-sm text-slate-200 placeholder-slate-500 outline-none" />
          <select value={hostId ?? ''} onChange={(e) => setHostId(e.target.value ? Number(e.target.value) : null)}
            aria-label={t('history.filterByHost')}
            className="shrink-0 rounded bg-ink-800 px-1.5 py-1 text-xs text-slate-300 ring-1 ring-ink-700">
            <option value="">{t('history.allHosts')}</option>
            {hostsWithHistory.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
          </select>
          <button onClick={props.onClose} aria-label={t('common.close')}
            className="shrink-0 rounded px-2 text-slate-500 hover:bg-ink-800 hover:text-slate-300">✕</button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {items == null ? (
            <div className="p-6 text-center text-sm text-slate-500">{t('history.loading')}</div>
          ) : items.length === 0 ? (
            <div className="p-6 text-center text-sm text-slate-500">
              {q.trim() ? t('history.noResults') : t('history.empty')}
            </div>
          ) : (
            items.map((it) => {
              const failed = it.exit_code != null && it.exit_code !== 0
              return (
                <div key={it.id} className="group flex items-start gap-2.5 border-b border-ink-800/60 px-3 py-2 hover:bg-ink-800/40">
                  <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${it.exit_code == null ? 'bg-slate-600' : failed ? 'bg-rose-500' : 'bg-emerald-500'}`} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[13px] text-slate-200">{it.command}</div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10.5px] text-slate-500">
                      {it.host_name && <span className="wt-link">{it.host_name}</span>}
                      {it.source === 'fleet' && <span className="rounded bg-ink-800 px-1 text-sky-400">{t('history.fleet')}</span>}
                      {it.exit_code != null && <span className={failed ? 'wt-danger' : ''}>exit {it.exit_code}</span>}
                      {it.cwd && <span className="truncate font-mono">{it.cwd}</span>}
                      <span className="tabular-nums">{rel(it.created)}</span>
                    </div>
                  </div>
                  <button onClick={() => copy(it)} title={t('history.copyTitle')}
                    className="shrink-0 rounded px-1.5 py-0.5 text-[11px] wt-link opacity-0 hover:bg-ink-700 group-hover:opacity-100">
                    {copied === it.id ? '✓' : t('history.copy')}
                  </button>
                </div>
              )
            })
          )}
        </div>

        <footer className="flex items-center gap-2 border-t border-ink-800 px-3 py-2 text-[11px] text-slate-500">
          <span>{t('history.commandsCount', { count: items?.length ?? 0 })}</span>
          <span className="ml-auto">
            {confirmClear ? (
              <span className="flex items-center gap-2">
                {t('history.confirmClear')}
                <button onClick={clearAll} className="rounded bg-rose-600 px-2 py-0.5 font-medium text-white hover:bg-rose-700">{t('history.clearBtn')}</button>
                <button onClick={() => setConfirmClear(false)} className="rounded px-1.5 py-0.5 text-slate-400 hover:bg-ink-800">{t('history.no')}</button>
              </span>
            ) : (
              <button onClick={() => setConfirmClear(true)} className="rounded px-1.5 py-0.5 text-slate-400 hover:bg-ink-800 hover:text-rose-300">{t('history.clearAll')}</button>
            )}
          </span>
        </footer>
      </div>
    </div>
  )
}
