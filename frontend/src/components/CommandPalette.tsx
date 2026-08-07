import { useEffect, useMemo, useRef, useState } from 'react'
import { Host, Session, Snippet } from '../lib/api'
import { hostAt, hostColor, protoLabel, reachState } from '../lib/host'
import { applyTheme, currentTheme } from '../lib/theme'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useI18n } from '../lib/i18n'
import { FilesIcon, PlusIcon, ServerIcon, TerminalPromptIcon } from './Icons'
import { snippetParams } from './SnippetParams'

type Item = {
  key: string
  kind: 'session' | 'host' | 'action' | 'snippet'
  label: string
  sub: string
  color: string
  hint: string
  text: string // câmp de căutare (lowercase)
  icon?: React.ReactNode
  run: () => void
}

/** Subsequence fuzzy scoring: potrivire contiguă > cu goluri; mai devreme = mai bine. */
function score(query: string, text: string): number | null {
  if (!query) return 0
  const idx = text.indexOf(query)
  if (idx >= 0) return 1000 - idx
  let ti = 0
  let gaps = 0
  for (const qc of query) {
    const found = text.indexOf(qc, ti)
    if (found < 0) return null
    if (found > ti) gaps++
    ti = found + 1
  }
  return 500 - gaps
}

export default function CommandPalette(props: {
  open: boolean
  onClose: () => void
  hosts: Host[]
  sessions: Session[]
  openTabs: string[]
  onOpenSession: (sid: string) => void
  onNewSession: (host: Host) => void
  onSelectHost: (id: number) => void
  onAddHost: () => void
  onFiles: (host: Host) => void
  onOpenSettings: () => void
  onOpenStatus: () => void
  onOpenHistory: () => void
  /** snippet-urile sunt disponibile în paletă doar când există o sesiune activă */
  snippets?: Snippet[]
  onRunSnippet?: (s: Snippet) => void
  hasActiveSession?: boolean
}) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [sel, setSel] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  useEffect(() => {
    if (props.open) {
      setQuery('')
      setSel(0)
      // focus după montare
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [props.open])

  const items = useMemo<Item[]>(() => {
    const byId = new Map(props.hosts.map((h) => [h.id, h]))
    const out: Item[] = []
    // sesiuni: tab-urile deschise întâi, apoi restul active
    const live = props.sessions.filter((s) => s.state === 'live' || s.state === 'creating')
    const ordered = [
      ...props.openTabs.map((id) => live.find((s) => s.id === id)).filter(Boolean) as Session[],
      ...live.filter((s) => !props.openTabs.includes(s.id)),
    ]
    for (const s of ordered) {
      const h = byId.get(s.host_id)
      const hn = h?.name ?? 'host'
      out.push({
        key: `s:${s.id}`,
        kind: 'session',
        label: s.title || t('palette.sessionFallback'),
        sub: hn,
        color: h ? hostColor(h) : '#64748b',
        hint: props.openTabs.includes(s.id) ? t('palette.hintOpen') : t('palette.hintActive'),
        text: `${s.title} ${hn} ${h?.folder ?? ''}`.toLowerCase(),
        run: () => props.onOpenSession(s.id),
      })
    }
    // host-uri: Enter = sesiune nouă (conectare rapidă)
    for (const h of props.hosts) {
      out.push({
        key: `h:${h.id}`,
        kind: 'host',
        label: h.name,
        sub: `${protoLabel(h)} · ${hostAt(h)}`,
        color: hostColor(h),
        hint: reachState(h) === 'online' ? t('palette.hostOnline') : reachState(h) === 'ondemand' ? t('palette.hostOnDemand') : t('palette.hostOffline'),
        text: `${h.name} ${h.hostname ?? ''} ${h.ssh_username ?? ''} ${h.connection_type ?? 'agent'} ${h.folder ?? ''}`.toLowerCase(),
        run: () => props.onNewSession(h),
      })
    }
    // acțiuni-verb: paleta e hub de comenzi, nu doar switcher (audit iulie 2026)
    for (const h of props.hosts) {
      if (!h.online || (h.connection_type ?? 'agent') !== 'agent') continue
      out.push({
        key: `a:files:${h.id}`, kind: 'action', label: t('palette.filesLabel', { name: h.name }),
        sub: t('palette.filesSub'), color: hostColor(h), hint: t('palette.hintAction'),
        text: `fisiere files sftp upload download ${h.name}`.toLowerCase(),
        icon: <FilesIcon />, run: () => props.onFiles(h),
      })
    }
    // snippets: rulează în sesiunea activă (Warp le numește „workflows")
    if (props.hasActiveSession && props.onRunSnippet) {
      for (const s of props.snippets ?? []) {
        const params = snippetParams(s.body)
        out.push({
          key: `sn:${s.id}`, kind: 'snippet', label: s.title,
          sub: params.length ? t('palette.snippetSub', { preview: s.body.slice(0, 40), count: params.length }) : s.body.slice(0, 60),
          color: '#22d3ee', hint: params.length ? t('palette.snippetParams') : t('palette.snippetInsert'),
          text: `${s.title} ${s.body}`.toLowerCase(),
          icon: <TerminalPromptIcon />,
          run: () => props.onRunSnippet!(s),
        })
      }
    }
    out.push({
      key: 'a:add', kind: 'action', label: t('palette.addHost'), sub: t('palette.addHostSub'),
      color: '#818cf8', hint: t('palette.hintAction'), text: 'add host new server machine', run: props.onAddHost,
    })
    out.push({
      key: 'a:theme', kind: 'action', label: t('palette.toggleTheme'),
      sub: currentTheme() === 'dark' ? 'Midnight → Aurora' : 'Aurora → Midnight',
      color: '#818cf8', hint: t('palette.hintAction'),
      text: 'toggle theme aurora midnight dark light appearance',
      run: () => applyTheme(currentTheme() === 'dark' ? 'macos' : 'dark'),
    })
    out.push({
      key: 'a:settings', kind: 'action', label: t('palette.settings'), sub: t('palette.settingsSub'),
      color: '#818cf8', hint: t('palette.hintAction'), text: 'settings account password timezone passkey terminal colours',
      run: props.onOpenSettings,
    })
    out.push({
      key: 'a:status', kind: 'action', label: t('palette.status'), sub: t('palette.statusSub'),
      color: '#818cf8', hint: t('palette.hintAction'), text: 'status storage transcripts uptime version agent',
      run: props.onOpenStatus,
    })
    out.push({
      key: 'a:history', kind: 'action', label: t('palette.history'), sub: t('palette.historySub'),
      color: '#818cf8', hint: t('palette.hintAction'), text: 'command history search audit commands run',
      run: props.onOpenHistory,
    })
    return out
  }, [t, props.hosts, props.sessions, props.openTabs, props.snippets, props.hasActiveSession]) // eslint-disable-line react-hooks/exhaustive-deps

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) {
      // acțiunile globale (Adaugă host, Temă, Setări, Status) rămân mereu
      // accesibile — cu flote mari, slice-ul simplu le-ar tăia (sunt ultimele)
      const globals = items.filter((it) => ['a:add', 'a:theme', 'a:history', 'a:settings', 'a:status'].includes(it.key))
      const rest = items.filter((it) => !globals.includes(it))
      return [...rest.slice(0, 40 - globals.length), ...globals]
    }
    return items
      .map((it) => ({ it, sc: score(q, it.text) }))
      .filter((x) => x.sc !== null)
      .sort((a, b) => (b.sc as number) - (a.sc as number))
      .slice(0, 40)
      .map((x) => x.it)
  }, [items, query])

  useEffect(() => {
    if (sel >= results.length) setSel(0)
  }, [results.length]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${sel}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [sel])

  if (!props.open) return null

  const pick = (i: number) => {
    const it = results[i]
    if (!it) return
    props.onClose()
    it.run()
  }

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-black/50 p-4 pt-[12vh]"
      onClick={props.onClose}
    >
      <div
        ref={dialogRef}
        className="glass wt-command w-full max-w-xl overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={t('palette.dialogAria')}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => { setQuery(e.target.value); setSel(0) }}
          placeholder={t('palette.searchPlaceholder')}
          aria-label={t('palette.searchAria')}
          className="w-full bg-transparent px-5 py-4 text-base placeholder-slate-500 outline-none"
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(results.length - 1, s + 1)) }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(0, s - 1)) }
            else if (e.key === 'Enter') { e.preventDefault(); pick(sel) }
            else if (e.key === 'Escape') { e.preventDefault(); props.onClose() }
          }}
        />
        <div ref={listRef} className="max-h-[52vh] overflow-y-auto border-t border-white/5 py-1.5">
          {results.length === 0 && (
            <div className="px-5 py-6 text-center text-sm text-slate-500">{t('palette.noResults', { query })}</div>
          )}
          {results.map((it, i) => (
            <button
              key={it.key}
              data-idx={i}
              onMouseMove={() => setSel(i)}
              onClick={() => pick(i)}
              className={`flex w-full items-center gap-3 px-4 py-2 text-left ${
                i === sel ? 'bg-sky-500/15' : ''
              }`}
            >
              <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg" style={{ background: `${it.color}22`, color: it.color }}>
                {it.icon ?? (it.kind === 'session' ? <TerminalPromptIcon /> : it.kind === 'host' ? <ServerIcon /> : <PlusIcon />)}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-slate-100">{it.label}</span>
                <span className={`block truncate text-xs ${it.kind === 'action' ? '' : 'font-mono'}`} style={{ color: it.kind === 'action' ? undefined : it.color }}>
                  {it.sub}
                </span>
              </span>
              <span className="shrink-0 text-[11px] text-slate-400">{it.hint}</span>
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3 border-t border-white/5 px-4 py-2 text-[11px] text-slate-400">
          <span><kbd className="rounded bg-white/10 px-1 text-slate-300">↑</kbd><kbd className="ml-0.5 rounded bg-white/10 px-1 text-slate-300">↓</kbd> {t('palette.footNavigate')}</span>
          <span><kbd className="rounded bg-white/10 px-1 text-slate-300">↵</kbd> {t('palette.footOpen')}</span>
          <span><kbd className="rounded bg-white/10 px-1 text-slate-300">esc</kbd> {t('palette.footClose')}</span>
          <span className="ml-auto">{t('palette.footHostNew')}</span>
        </div>
      </div>
    </div>
  )
}
