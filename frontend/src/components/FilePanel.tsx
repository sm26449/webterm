import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
import { getCwd } from '../lib/cwd'
import { useI18n } from '../lib/i18n'
import { notify } from '../lib/notify'
import { uiLocale } from '../lib/tz'
import {
  DownloadIcon, FileIcon, FolderIcon, LinkIcon, PencilIcon,
  PlusIcon, RefreshIcon, TrashIcon,
} from './Icons'

// CodeMirror e greu → lazy: intră doar când deschizi un fișier
const FileEditor = lazy(() => import('./FileEditor'))

interface Entry {
  name: string
  dir: boolean
  link: boolean
  size: number
  mtime: number
  mode: number
}
interface Listing {
  path: string
  parent: string
  entries: Entry[]
  truncated: boolean
}

type SortKey = 'name' | 'size' | 'mtime'

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)}K`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)}M`
  return `${(n / 1024 ** 3).toFixed(1)}G`
}
// mode octal → rwxr-xr-x (ajută la „de ce n-am voie să scriu aici")
function fmtMode(m: number): string {
  const t = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']
  return t[(m >> 6) & 7] + t[(m >> 3) & 7] + t[m & 7]
}
function fmtMtime(s: number): string {
  const d = new Date(s * 1000)
  const diff = Date.now() - d.getTime()
  if (diff >= 0 && diff < 86400000)
    return d.toLocaleTimeString(uiLocale(), { hour: '2-digit', minute: '2-digit' })
  return d.toLocaleDateString(uiLocale(), { day: '2-digit', month: 'short' })
}
function join(dir: string, name: string): string {
  return `${dir.replace(/\/$/, '')}/${name}`
}

// fișier de încărcat + calea relativă la directorul curent (pentru foldere:
// „sub/dir/fisier.txt”; pentru fișiere simple, doar numele)
interface UpItem { file: File; rel: string }

// Traversează un FileSystemEntry (dintr-un drop) și adună fișierele cu calea lor
// relativă — așa merge drag&drop pe FOLDERE, nu doar pe fișiere izolate.
async function readEntry(entry: any, prefix: string, out: UpItem[]): Promise<void> {
  if (entry.isFile) {
    const file: File = await new Promise((res, rej) => entry.file(res, rej))
    out.push({ file, rel: prefix + entry.name })
  } else if (entry.isDirectory) {
    const reader = entry.createReader()
    const all: any[] = []
    await new Promise<void>((res) => {
      const step = () => reader.readEntries((batch: any[]) => {
        if (!batch.length) return res()
        all.push(...batch); step()
      }, () => res())
      step()
    })
    for (const e of all) await readEntry(e, prefix + entry.name + '/', out)
  }
}

export default function FilePanel(props: { host: Host; sessionId: string; onClose: () => void; overlay?: boolean }) {
  const { t } = useI18n()
  const isAgent = !props.host.connection_type || props.host.connection_type === 'agent'
  // pe pane-uri înguste (split pe iPad) panoul e DRAWER peste terminal, nu coloană
  // statică — altfel o coloană de 320px într-un pane de 240px strivește terminalul
  // la ~0px. Decizia vine pe lățimea REALĂ a pane-ului (nu pe viewport).
  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')
  const [listing, setListing] = useState<Listing | null>(null)
  const [path, setPath] = useState('~')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [uploads, setUploads] = useState<Record<string, { pct: number; state: 'up' | 'done' | 'err' }>>({})
  const xhrs = useRef<Record<string, XMLHttpRequest>>({})
  const [overwrite, setOverwrite] = useState<{ items: UpItem[]; count: number } | null>(null)
  const [drag, setDrag] = useState(false)
  const [editing, setEditing] = useState<{ path: string; name: string } | null>(null)
  // urmărește cwd-ul din terminal (OSC 7). Navigarea manuală îl oprește, ca să
  // poți explora în altă parte fără să fii „tras” înapoi la fiecare comandă.
  const [follow, setFollow] = useState(true)
  const [filter, setFilter] = useState('')
  const [showHidden, setShowHidden] = useState(false)
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: 'name', asc: true })
  const [sel, setSel] = useState(0)                 // index selectat (tastatură)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [newFolder, setNewFolder] = useState<string | null>(null)
  const [confirmDel, setConfirmDel] = useState<Entry | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const loadSeq = useRef(0)

  const load = useCallback(async (p: string) => {
    // generație monotonă: dacă navighezi rapid (sau un event OSC 7 întârziat
    // sosește după un click manual), doar răspunsul CEL MAI RECENT se aplică —
    // altfel un director lent ar suprascrie unul mai nou și operațiile
    // ulterioare (upload/delete) ar ținti calea greșită.
    const my = ++loadSeq.current
    setError('')
    try {
      const l = await api<Listing>(`/api/hosts/${props.host.id}/fs?path=${encodeURIComponent(p)}`)
      if (my !== loadSeq.current) return          // un load mai nou a pornit între timp
      setListing(l)
      setPath(l.path)
      setSel(0)
      setConfirmDel(null)
      setRenaming(null)
    } catch (e) {
      if (my !== loadSeq.current) return
      setError(errText(e, t) || t('files.genericErr'))
      // Listarea VECHE rămânea afişată sub eroare, iar calea din input devenea deja cea
      // nouă: vizual, fişierele din /root păreau să fie în directorul inexistent, iar
      // „Upload to:" arăta încă directorul anterior — deci un upload ar fi plecat altundeva
      // decât credeai. Golim listarea: eroarea rămâne singurul lucru de citit.
      setListing(null)
      setSel(0)
      setConfirmDel(null)
      setRenaming(null)
    }
  }, [props.host.id, t])

  // cwd-ul sesiunii: OSC 7 (dacă e activ shell integration) altfel îl cerem
  // agentului (tmux pane_current_path / /proc) → panoul se deschide unde ești,
  // nu în ~. Pe agenți vechi fără op-ul ăsta, .catch cade curat pe ~.
  const loadSessionCwd = useCallback(() => {
    const known = getCwd(props.sessionId)
    if (known) { load(known); return }
    api<{ cwd: string }>(`/api/hosts/${props.host.id}/fs/cwd?sid=${encodeURIComponent(props.sessionId)}`)
      .then((r) => load(r.cwd || '~'))
      .catch(() => load('~'))
  }, [props.host.id, props.sessionId, load])

  // pornire: deschide în directorul curent al terminalului
  useEffect(() => {
    if (!isAgent) return
    loadSessionCwd()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAgent])

  // follow: la fiecare `cd` din terminal (OSC 7), sari acolo
  useEffect(() => {
    if (!isAgent) return
    const onCwd = (e: Event) => {
      const d = (e as CustomEvent<{ sid: string; cwd: string }>).detail
      if (follow && d.sid === props.sessionId) load(d.cwd)
    }
    window.addEventListener('wt-cwd', onCwd)
    return () => window.removeEventListener('wt-cwd', onCwd)
  }, [follow, isAgent, props.sessionId, load])

  // navigare manuală = oprește follow (altfel te trage înapoi la cwd)
  const navigate = (p: string) => { setFollow(false); load(p) }
  const enableFollow = () => {
    setFollow(true)
    loadSessionCwd()
  }

  const view = useMemo(() => {
    const es = (listing?.entries ?? [])
      .filter((e) => showHidden || !e.name.startsWith('.'))
      .filter((e) => !filter || e.name.toLowerCase().includes(filter.toLowerCase()))
    const dir = sort.asc ? 1 : -1
    es.sort((a, b) => {
      if (a.dir !== b.dir) return a.dir ? -1 : 1   // directoarele mereu primele
      if (sort.key === 'size') return (a.size - b.size) * dir
      if (sort.key === 'mtime') return (a.mtime - b.mtime) * dir
      return a.name.localeCompare(b.name) * dir
    })
    return es
  }, [listing, filter, showHidden, sort])

  function download(e: Entry) {
    // avertisment peste 100MB: descărcarea stream-uiește tot fișierul în browser
    if (e.size > 100 * 1024 * 1024 && !window.confirm(t('files.dlBigConfirm', { name: e.name, size: fmtSize(e.size) }))) return
    const url = `/api/hosts/${props.host.id}/fs/download?path=${encodeURIComponent(join(listing!.path, e.name))}`
    const a = document.createElement('a')
    a.href = url
    a.download = e.name
    a.click()
  }

  // FileEditor încarcă singur conținutul (preview cu partial-read) și decide
  // editabil / view-only / binar — aici doar deschidem modalul.
  function edit(e: Entry) {
    setError('')
    setEditing({ path: join(listing!.path, e.name), name: e.name })
  }

  // un fișier prin XHR (fetch nu dă progres de upload) → procent + cancel
  function uploadOne(dest: string, key: string, file: Blob): Promise<void> {
    return new Promise((resolve) => {
      const xhr = new XMLHttpRequest()
      xhrs.current[key] = xhr
      xhr.open('POST', `/api/hosts/${props.host.id}/fs/upload?path=${encodeURIComponent(dest)}`)
      xhr.upload.onprogress = (ev) => {
        if (ev.lengthComputable) setUploads((u) => ({ ...u, [key]: { pct: Math.round((ev.loaded / ev.total) * 100), state: 'up' } }))
      }
      xhr.onload = () => {
        const good = xhr.status >= 200 && xhr.status < 300
        setUploads((u) => ({ ...u, [key]: { pct: 100, state: good ? 'done' : 'err' } }))
        if (!good) notify(t('files.uploadFailed'), `${key}: ${xhr.status}`, 'warn')
        delete xhrs.current[key]; resolve()
      }
      xhr.onerror = () => { setUploads((u) => ({ ...u, [key]: { pct: 0, state: 'err' } })); delete xhrs.current[key]; resolve() }
      xhr.onabort = () => { setUploads((u) => { const c = { ...u }; delete c[key]; return c }); delete xhrs.current[key]; resolve() }
      xhr.send(file)
    })
  }

  // punct de intrare: cere confirmare dacă suprascrie fișiere top-level existente
  function startUpload(items: UpItem[]) {
    if (!listing || !items.length) return
    const existing = new Set(listing.entries.map((e) => e.name))
    const collides = items.filter((it) => !it.rel.includes('/') && existing.has(it.rel))
    if (collides.length) setOverwrite({ items, count: collides.length })
    else reallyUpload(items)
  }

  async function reallyUpload(items: UpItem[]) {
    setOverwrite(null)
    if (!listing) return
    setBusy(true)
    // creează întâi subdirectoarele (upload de folder), idempotent
    const dirs = new Set<string>()
    for (const it of items) {
      const slash = it.rel.lastIndexOf('/')
      if (slash > 0) dirs.add(it.rel.slice(0, slash))
    }
    for (const d of [...dirs].sort()) {
      try { await api(`/api/hosts/${props.host.id}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: join(listing.path, d), parents: true }) }) } catch { /* există deja */ }
    }
    for (const it of items) {
      setUploads((u) => ({ ...u, [it.rel]: { pct: 0, state: 'up' } }))
      await uploadOne(join(listing.path, it.rel), it.rel, it.file)
    }
    setBusy(false)
    load(listing.path)
  }

  function pickFiles(files: FileList | File[]) {
    startUpload(Array.from(files).map((f) => ({ file: f, rel: f.name })))
  }

  async function doMkdir(name: string) {
    const n = name.trim()
    setNewFolder(null)
    if (!n || !listing) return
    try {
      await api(`/api/hosts/${props.host.id}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: join(listing.path, n) }) })
      load(listing.path)
    } catch (e) { setError(errText(e, t) || t('files.genericErr')) }
  }

  async function doRename(e: Entry, name: string) {
    const n = name.trim()
    setRenaming(null)
    if (!n || n === e.name || !listing) return
    try {
      await api(`/api/hosts/${props.host.id}/fs/rename`, {
        method: 'POST', body: JSON.stringify({ path: join(listing.path, e.name), to: join(listing.path, n) }),
      })
      load(listing.path)
    } catch (err) { setError(errText(err, t) || t('files.genericErr')) }
  }

  async function doDelete(e: Entry) {
    setConfirmDel(null)
    if (!listing) return
    try {
      await api(`/api/hosts/${props.host.id}/fs/delete`, {
        method: 'POST', body: JSON.stringify({ path: join(listing.path, e.name), recursive: e.dir }),
      })
      load(listing.path)
    } catch (err) { setError(errText(err, t) || t('files.genericErr')) }
  }

  function onKeyDown(ev: React.KeyboardEvent) {
    if (editing || renaming || newFolder) return
    if (ev.key === 'ArrowDown') { ev.preventDefault(); setSel((s) => Math.min(view.length - 1, s + 1)) }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); setSel((s) => Math.max(0, s - 1)) }
    else if (ev.key === 'Enter') {
      const e = view[sel]; if (!e) return
      ev.preventDefault()
      if (e.dir) navigate(join(listing!.path, e.name)); else edit(e)
    } else if (ev.key === 'Backspace') {
      ev.preventDefault(); if (listing && listing.path !== '/') navigate(listing.parent)
    } else if (ev.key === 'Delete') {
      const e = view[sel]; if (e) { ev.preventDefault(); setConfirmDel(e) }
    }
  }

  // menține selecția vizibilă la navigarea din tastatură
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${sel}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [sel])

  const header = (
    <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('files.title')}</span>
      <button
        onClick={props.onClose}
        aria-label={t('files.closeAria')}
        className="wt-touch ml-auto rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"
      >✕</button>
    </header>
  )

  if (!isAgent) {
    return (
      <>
        <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
        <aside aria-label={t('files.sessionAria')} className={asideCls}>
          {header}
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-4 text-center">
            <p className="text-xs leading-relaxed text-slate-500">
              {t('files.noAgent', { type: props.host.connection_type?.toUpperCase() ?? '' })}
            </p>
          </div>
        </aside>
      </>
    )
  }

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      <aside
        aria-label={t('files.sessionAria')}
        className={asideCls}
        onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={async (e) => {
          e.preventDefault(); setDrag(false)
          if (!listing) return
          // webkitGetAsEntry TREBUIE apelat sincron (items se golesc după handler)
          const entries = Array.from(e.dataTransfer.items || [])
            .map((it) => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null))
            .filter(Boolean)
          const out: UpItem[] = []
          if (entries.length) {
            for (const en of entries) await readEntry(en, '', out)
          } else {
            for (const f of Array.from(e.dataTransfer.files)) out.push({ file: f, rel: f.name })
          }
          startUpload(out)
        }}
      >
        {header}

        {/* agent în urmă: mkdir/rename/delete/salvarea atomică cer agentul nou */}
        {props.host.update_pending && (
          <div className="border-b border-ink-800 bg-amber-950/40 px-3 py-1.5 text-[11px] wt-warn">
            {t('files.oldAgent')}
          </div>
        )}

        {/* bara de cale + acțiuni pe director */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1.5">
          <button onClick={() => listing && navigate(listing.parent)} disabled={!listing || listing.path === '/'}
            className="wt-touch shrink-0 rounded px-1.5 text-slate-400 hover:bg-ink-800 disabled:opacity-30" title={t('files.upLevel')}>↰</button>
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && navigate(path)}
            spellCheck={false}
            className="min-w-0 flex-1 rounded bg-ink-800 px-2 py-1 font-mono text-[11px] text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500"
            title={t('files.pathHint')}
          />
          <button onClick={() => load(listing?.path ?? path)} className="wt-touch shrink-0 rounded px-1.5 text-slate-400 hover:bg-ink-800" title={t('files.reload')}><RefreshIcon /></button>
          <button onClick={() => setNewFolder('')} className="wt-touch shrink-0 rounded px-1.5 text-slate-400 hover:bg-ink-800" title={t('files.newDir')}><PlusIcon /></button>
          <button onClick={() => fileInput.current?.click()} disabled={busy || !listing} className="wt-touch shrink-0 rounded px-1.5 text-sky-400 hover:bg-ink-800 disabled:opacity-40" title={t('files.uploadHere')}>↑</button>
          <input ref={fileInput} type="file" multiple className="hidden" onChange={(e) => { if (e.target.files) pickFiles(e.target.files); e.target.value = '' }} />
        </div>

        {/* filtru + follow + hidden + sort */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1 text-[11px]">
          <input
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setSel(0) }}
            placeholder={t('files.filterPh')}
            className="min-w-0 flex-1 rounded bg-ink-800/60 px-2 py-0.5 text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500"
          />
          <button onClick={follow ? () => setFollow(false) : enableFollow}
            className={`shrink-0 rounded px-1.5 py-0.5 ${follow ? 'wt-good ring-1 ring-emerald-600/40' : 'text-slate-500 hover:bg-ink-800'}`}
            title={t('files.followCwd')}>⇄ cwd</button>
          <button onClick={() => setShowHidden((v) => !v)}
            className={`shrink-0 rounded px-1.5 py-0.5 ${showHidden ? 'wt-link' : 'text-slate-500 hover:bg-ink-800'}`}
            title={t('files.showHidden')}>.*</button>
        </div>
        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-0.5 text-[10px] uppercase tracking-wide text-slate-600">
          {(['name', 'size', 'mtime'] as SortKey[]).map((k) => (
            <button key={k} onClick={() => setSort((s) => ({ key: k, asc: s.key === k ? !s.asc : true }))}
              className={`hover:text-slate-400 ${sort.key === k ? 'text-slate-400' : ''}`}>
              {k === 'name' ? t('files.sortName') : k === 'size' ? t('files.sortSize') : t('files.sortDate')}{sort.key === k ? (sort.asc ? ' ▲' : ' ▼') : ''}
            </button>
          ))}
        </div>

        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}

        <div ref={listRef} tabIndex={0} onKeyDown={onKeyDown}
          className={`relative min-h-0 flex-1 overflow-y-auto outline-none ${drag ? 'ring-2 ring-inset ring-sky-500' : ''}`}>
          {drag && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-black/60 text-xs text-sky-200">
              {t('files.dropHere')}
            </div>
          )}
          {newFolder !== null && (
            <div className="flex items-center gap-2 border-b border-ink-800/60 px-3 py-1">
              <FolderIcon />
              <input autoFocus value={newFolder} onChange={(e) => setNewFolder(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') doMkdir(newFolder); if (e.key === 'Escape') setNewFolder(null) }}
                onBlur={() => doMkdir(newFolder)} placeholder={t('files.newDirPh')}
                className="min-w-0 flex-1 rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-200 ring-1 ring-sky-500" />
            </div>
          )}
          {view.map((e, i) => (
            <div key={e.name} data-idx={i}
              className={`group flex items-center gap-2 px-3 py-1 text-[12px] ${i === sel ? 'bg-ink-800' : 'hover:bg-ink-800/60'}`}
              onClick={() => setSel(i)}>
              <span className={`shrink-0 ${e.dir ? 'wt-link' : e.link ? 'text-slate-400' : 'text-slate-500'}`}>
                {e.dir ? <FolderIcon /> : e.link ? <LinkIcon /> : <FileIcon />}
              </span>
              {renaming === e.name ? (
                <input autoFocus defaultValue={e.name}
                  onKeyDown={(ev) => { if (ev.key === 'Enter') doRename(e, (ev.target as HTMLInputElement).value); if (ev.key === 'Escape') setRenaming(null) }}
                  onBlur={(ev) => doRename(e, ev.target.value)}
                  className="min-w-0 flex-1 rounded bg-ink-800 px-1 py-0.5 font-mono text-[11px] text-slate-100 ring-1 ring-sky-500" />
              ) : (
                <button onDoubleClick={() => e.dir && navigate(join(listing!.path, e.name))}
                  onClick={() => e.dir && navigate(join(listing!.path, e.name))}
                  className={`min-w-0 flex-1 truncate text-left font-mono ${e.dir ? 'wt-link' : 'text-slate-200'}`}
                  title={e.name}>{e.name}{e.dir ? '/' : ''}</button>
              )}
              {/* meta pe UN rând: mode · dim · data (ascunse când apar acțiunile) */}
              <span className="shrink-0 items-center gap-2 font-mono text-[10px] tabular-nums text-slate-600 hidden sm:flex group-hover:sm:hidden">
                <span>{fmtMode(e.mode)}</span>
                {!e.dir && <span className="w-10 text-right text-slate-500">{fmtSize(e.size)}</span>}
                <span className="w-12 text-right">{fmtMtime(e.mtime)}</span>
              </span>
              {/* acțiuni la hover (desktop) / mereu (touch) */}
              <div className="hidden shrink-0 items-center gap-0.5 group-hover:flex [@media(hover:none)]:flex">
                {!e.dir && (
                  <button onClick={() => edit(e)} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200" title={t('files.edit')}><PencilIcon /></button>
                )}
                {!e.dir && (
                  <button onClick={() => download(e)} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200" title={t('files.download')}><DownloadIcon /></button>
                )}
                <button onClick={() => setRenaming(e.name)} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200" title={t('files.rename')} aria-label={t('files.renameAria', { name: e.name })}><PencilIcon /></button>
                <button onClick={() => setConfirmDel(e)} className="rounded px-1 text-slate-500 hover:bg-ink-700 hover:text-rose-300" title={t('files.delete')}><TrashIcon /></button>
              </div>
            </div>
          ))}
          {listing && view.length === 0 && (
            <div className="px-3 py-6 text-center text-[11px] text-slate-500">
              {filter ? t('files.emptyFilter') : t('files.emptyDir')}
            </div>
          )}
          {listing?.truncated && (
            <div className="px-3 py-2 text-center text-[10px] wt-warn">{t('files.truncated')}</div>
          )}
        </div>

        {/* confirmare ștergere (inline, nu window.confirm) */}
        {confirmDel && (
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-[11px]">
            <p className="mb-1.5 text-slate-300">
              {t('files.deletePrefix')} <span className="font-mono wt-danger">{confirmDel.name}</span>
              {confirmDel.dir ? t('files.deleteSuffixDir') : '?'}
            </p>
            <div className="flex gap-2">
              <button onClick={() => doDelete(confirmDel)} className="rounded bg-rose-600 px-2 py-0.5 font-medium text-white hover:bg-rose-700">{t('files.delete')}</button>
              <button onClick={() => setConfirmDel(null)} className="rounded px-2 py-0.5 text-slate-400 hover:bg-ink-700">{t('files.cancel')}</button>
            </div>
          </div>
        )}

        {/* confirmare overwrite (pe coliziuni de fișiere existente) */}
        {overwrite && (
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-[11px]">
            <p className="mb-1.5 text-slate-300">{overwrite.count === 1 ? t('files.overwriteOne', { count: overwrite.count }) : t('files.overwriteMany', { count: overwrite.count })}</p>
            <div className="flex gap-2">
              <button onClick={() => reallyUpload(overwrite.items)} className="rounded bg-amber-600 px-2 py-0.5 font-medium text-white hover:bg-amber-700">{t('files.overwrite')}</button>
              <button onClick={() => setOverwrite(null)} className="rounded px-2 py-0.5 text-slate-400 hover:bg-ink-700">{t('files.cancel')}</button>
            </div>
          </div>
        )}

        {Object.keys(uploads).length > 0 && (
          <div className="max-h-28 overflow-y-auto border-t border-ink-800 px-3 py-1 text-[10px]">
            {Object.entries(uploads).map(([name, u]) => (
              <div key={name} className="flex items-center gap-2 py-0.5">
                <span className="truncate text-slate-400" title={name}>{name}</span>
                <span className={`ml-auto tabular-nums ${u.state === 'done' ? 'wt-good' : u.state === 'err' ? 'wt-danger' : 'wt-link'}`}>
                  {u.state === 'up' ? `${u.pct}%` : u.state === 'done' ? '✓' : '✗'}
                </span>
                {u.state === 'up' && (
                  <button onClick={() => xhrs.current[name]?.abort()} className="shrink-0 rounded px-1 text-slate-500 hover:text-rose-300" title={t('files.cancelUpload')}>✕</button>
                )}
              </div>
            ))}
          </div>
        )}
      </aside>

      {/* editor CodeMirror (lazy) — highlight, fișiere mari view-only, conflict */}
      {editing && (
        <Suspense fallback={<div className="wt-editor fixed inset-0 z-[60] flex items-center justify-center bg-black/60 text-sm text-slate-400">{t('files.loadingEditor')}</div>}>
          <FileEditor
            hostId={props.host.id}
            path={editing.path}
            name={editing.name}
            onClose={() => setEditing(null)}
            onSaved={() => load(listing!.path)}
          />
        </Suspense>
      )}
    </>
  )
}
