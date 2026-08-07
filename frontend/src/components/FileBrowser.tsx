import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ensureStepup, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { notify } from '../lib/notify'
import { DownloadIcon, FileIcon, FolderIcon, LinkIcon } from './Icons'

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

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(1)} GB`
}

export default function FileBrowser(props: { host: Host; onClose: () => void }) {
  const { t } = useI18n()
  const [listing, setListing] = useState<Listing | null>(null)
  const [path, setPath] = useState('~')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [uploads, setUploads] = useState<Record<string, 'up' | 'done' | 'err'>>({})
  const [drag, setDrag] = useState(false)
  const [editing, setEditing] = useState<{ path: string; name: string; content: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  // Operațiile de fișier folosesc `fetch` brut (stream binar), deci nu trec prin retry-ul de
  // step-up din `api()`. Pe un host cu 2FA a cărui fereastră a expirat, un 403 → ceremonia de
  // step-up + o reîncercare (H1). Restul erorilor curg normal către apelant.
  const fetchWithStepup = useCallback(async (input: string, init?: RequestInit): Promise<Response> => {
    let res = await fetch(input, { credentials: 'same-origin', ...init })
    if (res.status === 403 && (await ensureStepup(props.host.id))) {
      res = await fetch(input, { credentials: 'same-origin', ...init })
    }
    return res
  }, [props.host.id])

  const load = useCallback(async (p: string) => {
    setError('')
    try {
      const l = await api<Listing>(`/api/hosts/${props.host.id}/fs?path=${encodeURIComponent(p)}`)
      setListing(l)
      setPath(l.path)
    } catch (e) {
      setError(e instanceof Error ? e.message : t('browser.error'))
    }
  }, [t, props.host.id])

  useEffect(() => {
    load('~')
  }, [load])

  function fullPath(name: string) {
    return `${listing!.path.replace(/\/$/, '')}/${name}`
  }

  function download(entry: Entry) {
    const url = `/api/hosts/${props.host.id}/fs/download?path=${encodeURIComponent(fullPath(entry.name))}`
    const a = document.createElement('a')
    a.href = url
    a.download = entry.name
    a.click()
  }

  async function edit(entry: Entry) {
    if (entry.size > 2 * 1024 * 1024) {
      setError(t('browser.tooLarge'))
      return
    }
    const path = fullPath(entry.name)
    const res = await fetchWithStepup(`/api/hosts/${props.host.id}/fs/download?path=${encodeURIComponent(path)}`)
    if (!res.ok) {
      setError(t('browser.cantRead'))
      return
    }
    const buf = new Uint8Array(await res.arrayBuffer())
    if (buf.includes(0)) {
      setError(t('browser.binary'))
      return
    }
    setError('')
    setEditing({ path, name: entry.name, content: new TextDecoder().decode(buf) })
  }

  async function saveEdit() {
    if (!editing) return
    setSaving(true)
    try {
      const res = await fetchWithStepup(`/api/hosts/${props.host.id}/fs/upload?path=${encodeURIComponent(editing.path)}`, {
        method: 'POST',
        body: new TextEncoder().encode(editing.content),
      })
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? t('browser.saveFailed'))
      setEditing(null)
      load(listing!.path)
    } catch (e) {
      setError(e instanceof Error ? e.message : t('browser.error'))
    } finally {
      setSaving(false)
    }
  }

  async function upload(files: FileList | File[]) {
    setBusy(true)
    for (const file of Array.from(files)) {
      const dest = `${listing!.path.replace(/\/$/, '')}/${file.name}`
      setUploads((u) => ({ ...u, [file.name]: 'up' }))
      try {
        const res = await fetchWithStepup(
          `/api/hosts/${props.host.id}/fs/upload?path=${encodeURIComponent(dest)}`,
          { method: 'POST', body: file },
        )
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? t('browser.uploadFailed'))
        setUploads((u) => ({ ...u, [file.name]: 'done' }))
      } catch (e) {
        setUploads((u) => ({ ...u, [file.name]: 'err' }))
        notify(t('browser.uploadFailedTitle'), `${file.name}: ${e instanceof Error ? e.message : ''}`, 'warn')
      }
    }
    setBusy(false)
    load(listing!.path)
  }

  return (
    <>
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        className="glass flex h-[80vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl"
        onDragOver={(e) => {
          e.preventDefault()
          setDrag(true)
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDrag(false)
          // fără listing (load inițial în zbor / eșuat) nu există destinație —
          // upload() ar crăpa pe listing!.path și ar lăsa busy blocat pe true
          if (listing && e.dataTransfer.files.length) upload(e.dataTransfer.files)
        }}
      >
        <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-3">
          <span className="font-semibold">{t('browser.title', { name: props.host.name })}</span>
          <button onClick={props.onClose} aria-label={t('browser.close')} className="ml-auto rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
            ✕
          </button>
        </div>

        {/* cale de destinație — editabilă: scrii sau navighezi unde vrei să încarci */}
        <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-2 text-sm">
          <button
            onClick={() => listing && load(listing.parent)}
            disabled={!listing || listing.path === '/'}
            className="shrink-0 rounded px-2 py-0.5 text-slate-400 hover:bg-ink-800 disabled:opacity-30"
            title={t('browser.up')}
          >
            ↰
          </button>
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && load(path)}
            spellCheck={false}
            placeholder="~/uploads"
            className="min-w-0 flex-1 rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500"
            title={t('browser.pathTitle')}
          />
          <button onClick={() => load(path)} className="shrink-0 rounded px-2 py-0.5 text-xs text-slate-400 hover:bg-ink-800" title={t('browser.go')}>
            →
          </button>
          <button onClick={() => load('~')} className="shrink-0 rounded px-2 py-0.5 text-xs text-slate-500 hover:bg-ink-800">
            ~
          </button>
        </div>

        {/* zona de upload — arată clar unde ajung fișierele */}
        <div className="flex items-center gap-2 border-b border-ink-800 bg-ink-800/40 px-4 py-2">
          <span className="min-w-0 flex-1 truncate text-xs text-slate-500">
            {t('browser.uploadTo')} <code className="font-mono wt-link">{listing?.path ?? path}</code>
          </span>
          <button
            onClick={() => fileInput.current?.click()}
            disabled={busy || !listing}
            className="shrink-0 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
          >
            {t('browser.choose')}
          </button>
          <input
            ref={fileInput}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => e.target.files && upload(e.target.files)}
          />
        </div>

        {/* wt-danger pe suprafață de temă, nu rose pe rose-950: modalul e în
            afara .wt-workspace, deci pe Aurora combinația veche era ilizibilă */}
        {error && <div className="border-b border-ink-800 bg-ink-800 px-4 py-2 text-sm wt-danger">{error}</div>}

        <div className={`relative flex-1 overflow-y-auto ${drag ? 'ring-2 ring-inset ring-sky-500' : ''}`}>
          {drag && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-black/60 text-sky-200">
              {t('browser.dropHere')}
            </div>
          )}
          {listing?.entries.map((e) => (
            <div
              key={e.name}
              className="group flex items-center gap-3 px-4 py-1.5 hover:bg-ink-800"
            >
              <span className={`shrink-0 ${e.dir ? 'wt-link' : 'text-slate-500'}`}>
                {e.dir ? <FolderIcon /> : e.link ? <LinkIcon /> : <FileIcon />}
              </span>
              <button
                onClick={() => e.dir && load(`${listing.path.replace(/\/$/, '')}/${e.name}`)}
                className={`min-w-0 flex-1 truncate text-left text-sm ${e.dir ? 'wt-link font-medium' : 'text-slate-200'}`}
              >
                {e.name}
              </button>
              {/* slate-500, nu 600: modalul e în afara .wt-workspace, deci ia tokenii
                  temei de la :root — pe dark, tx-600 cade sub AA (3.3:1) la text mic */}
              {!e.dir && <span className="shrink-0 font-mono text-xs tabular-nums text-slate-500">{fmtSize(e.size)}</span>}
              {!e.dir && (
                <div className="flex shrink-0 items-center gap-0.5">
                  <button onClick={() => edit(e)} className="rounded px-1.5 py-0.5 text-slate-500 hover:bg-ink-700 hover:text-slate-200" title={t('browser.edit')}>
                    ✎
                  </button>
                  <button onClick={() => download(e)} className="rounded px-1.5 py-0.5 text-slate-500 hover:bg-ink-700 hover:text-slate-200" title={t('browser.download')}>
                    <DownloadIcon />
                  </button>
                </div>
              )}
            </div>
          ))}
          {listing?.entries.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-slate-500">{t('browser.empty')}</div>
          )}
          {listing?.truncated && (
            <div className="px-4 py-2 text-center text-xs wt-warn">{t('browser.truncated')}</div>
          )}
        </div>

        {Object.keys(uploads).length > 0 && (
          <div className="border-t border-ink-800 px-4 py-2 text-xs">
            {Object.entries(uploads).map(([name, st]) => (
              <div key={name} className="flex items-center gap-2 py-0.5">
                <span className="truncate text-slate-400">{name}</span>
                <span className={`ml-auto ${st === 'done' ? 'wt-good' : st === 'err' ? 'wt-danger' : 'wt-link'}`}>
                  {st === 'up' ? '…' : st === 'done' ? '✓' : '✗'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>

      {editing && (
        <div className="wt-editor fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4">
          <div className="glass flex h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl">
            <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-2">
              <span className="truncate font-mono text-xs text-slate-400">{editing.path}</span>
              <div className="ml-auto flex gap-2">
                <button
                  onClick={saveEdit}
                  disabled={saving}
                  className="rounded-lg bg-sky-600 px-3 py-1 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
                >
                  {saving ? t('browser.saving') : t('browser.save')}
                </button>
                <button onClick={() => setEditing(null)} className="rounded-lg px-3 py-1 text-sm text-slate-400 hover:bg-ink-800">
                  {t('browser.cancel')}
                </button>
              </div>
            </div>
            <textarea
              autoFocus
              value={editing.content}
              onChange={(e) => setEditing({ ...editing, content: e.target.value })}
              spellCheck={false}
              className="flex-1 resize-none bg-[#0b0e14] p-3 font-mono text-[13px] leading-relaxed text-slate-200 outline-none"
            />
          </div>
        </div>
      )}
    </>
  )
}
