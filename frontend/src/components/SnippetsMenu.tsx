import { useEffect, useRef, useState } from 'react'
import { api, Snippet } from '../lib/api'
import { useI18n } from '../lib/i18n'
import SnippetParams, { snippetParams } from './SnippetParams'

/** Dropdown cu comenzi salvate: click pe una → o inserează în sesiune.
    „Gestionează" deschide un mic editor (adaugă / editează / șterge). */
export default function SnippetsMenu(props: {
  onInsert: (body: string) => void
  /** control extern (scurtătura Alt+S din App) */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}) {
  const { t } = useI18n()
  const [openState, setOpenState] = useState(false)
  const open = props.open ?? openState
  const setOpen = (v: boolean | ((p: boolean) => boolean)) => {
    const next = typeof v === 'function' ? v(open) : v
    setOpenState(next)
    props.onOpenChange?.(next)
  }
  const [snips, setSnips] = useState<Snippet[]>([])
  const [managing, setManaging] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [filter, setFilter] = useState('')
  const [saveErr, setSaveErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [askParams, setAskParams] = useState<Snippet | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  const load = () => api<Snippet[]>('/api/snippets').then(setSnips).catch(() => {})
  useEffect(() => {
    if (open) {
      setFilter('')
      load()
    }
  }, [open])
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  async function save() {
    if (!title.trim() || !body) return
    setSaveErr('')
    setSaving(true)
    try {
      if (editId) await api(`/api/snippets/${editId}`, { method: 'PATCH', body: JSON.stringify({ title, body }) })
      else await api('/api/snippets', { method: 'POST', body: JSON.stringify({ title, body }) })
      // formularul se golește DOAR la succes — la eroare păstrăm ce ai scris
      setTitle('')
      setBody('')
      setEditId(null)
      load()
    } catch (e) {
      setSaveErr(e instanceof Error ? e.message : t('snippets.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  async function remove(id: number) {
    try {
      await api(`/api/snippets/${id}`, { method: 'DELETE' })
    } catch (e) {
      setSaveErr(e instanceof Error ? e.message : t('snippets.deleteFailed'))
    }
    load()
  }

  const q = filter.trim().toLowerCase()
  const visible = q
    ? snips.filter((s) => s.title.toLowerCase().includes(q) || s.body.toLowerCase().includes(q))
    : snips

  return (
    <div ref={ref} className="relative">
      <button
        title={t('snippets.savedCommands')}
        onMouseDown={(e) => e.preventDefault()}
        onClick={() => setOpen((v) => !v)}
        className="rounded-md px-1.5 py-1 text-sm text-slate-400 hover:bg-ink-700"
      >
        ❯_
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-1 w-72 rounded-xl border border-ink-700 bg-ink-900 p-1.5 shadow-2xl">
          {!managing ? (
            <>
              {/* filtrare: peste ~6 snippets, lista nu se mai scanează cu ochiul */}
              {snips.length > 6 && (
                <input
                  autoFocus
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder={t('snippets.filterPlaceholder')}
                  aria-label={t('snippets.filterAria')}
                  className="mb-1 w-full rounded-lg bg-ink-800 px-2 py-1.5 text-sm ring-1 ring-ink-700 placeholder:text-slate-600 focus:ring-sky-500"
                />
              )}
              <div className="max-h-64 overflow-y-auto">
                {snips.length === 0 && (
                  <div className="px-2 py-3 text-center text-xs text-slate-600">
                    {t('snippets.empty')}
                  </div>
                )}
                {visible.length === 0 && snips.length > 0 && (
                  <div className="px-2 py-3 text-center text-xs text-slate-600">
                    {t('snippets.noMatch', { q: filter })}
                  </div>
                )}
                {visible.map((s) => {
                  const params = snippetParams(s.body)
                  return (
                    <button
                      key={s.id}
                      onClick={() => {
                        setOpen(false)
                        // cu {{parametri}} → dialog; fără → inserare directă
                        if (params.length) setAskParams(s)
                        else props.onInsert(s.body)
                      }}
                      className="block w-full rounded-lg px-2 py-1.5 text-left hover:bg-ink-800"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-sm text-slate-200">{s.title}</span>
                        {params.length > 0 && (
                          <span className="shrink-0 rounded bg-ink-800 px-1 text-[10px] text-slate-400 ring-1 ring-ink-700">
                            {t('snippets.paramsCount', { n: params.length })}
                          </span>
                        )}
                      </div>
                      <div className="truncate font-mono text-[11px] text-slate-500">{s.body}</div>
                    </button>
                  )
                })}
              </div>
              <button
                onClick={() => setManaging(true)}
                className="mt-1 w-full rounded-lg px-2 py-1 text-left text-xs text-sky-400 hover:bg-ink-800"
              >
                {t('snippets.manage')}
              </button>
            </>
          ) : (
            <div className="space-y-1.5">
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder={t('snippets.titlePlaceholder')}
                className="w-full rounded-lg bg-ink-800 px-2 py-1.5 text-sm ring-1 ring-ink-700 focus:ring-sky-500"
              />
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder={t('snippets.bodyPlaceholder')}
                rows={2}
                className="w-full rounded-lg bg-ink-800 px-2 py-1.5 font-mono text-xs ring-1 ring-ink-700 focus:ring-sky-500"
              />
              {saveErr && <div className="px-1 text-xs wt-danger">{saveErr}</div>}
              <div className="flex gap-1.5">
                <button onClick={save} disabled={saving} className="rounded-lg bg-sky-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                  {saving ? t('snippets.saving') : editId ? t('common.save') : t('snippets.add')}
                </button>
                <button onClick={() => { setManaging(false); setEditId(null); setTitle(''); setBody('') }} className="rounded-lg px-2.5 py-1 text-xs text-slate-400 hover:bg-ink-800">
                  {t('snippets.back')}
                </button>
              </div>
              <div className="max-h-40 overflow-y-auto border-t border-ink-800 pt-1">
                {snips.map((s) => (
                  <div key={s.id} className="flex items-center gap-1 rounded-lg px-2 py-1 hover:bg-ink-800">
                    <button
                      onClick={() => { setEditId(s.id); setTitle(s.title); setBody(s.body) }}
                      className="min-w-0 flex-1 truncate text-left text-xs text-slate-300"
                    >
                      {s.title}
                    </button>
                    <button onClick={() => remove(s.id)} className="text-xs text-rose-500/80 hover:text-rose-400">
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {askParams && (
        <SnippetParams
          snippet={askParams}
          onRun={(body) => { props.onInsert(body); setAskParams(null) }}
          onCancel={() => setAskParams(null)}
        />
      )}
    </div>
  )
}
