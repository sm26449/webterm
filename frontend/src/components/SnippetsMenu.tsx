import { useEffect, useRef, useState } from 'react'
import { errText, api, Snippet } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import SnippetParams, { snippetParams } from './SnippetParams'
import SnippetTags from './SnippetTags'
import { parseTagInput, snippetTags, targetsPayload } from '../lib/snippets'
import { Button, ErrorState } from './ui'
import { CloseIcon, TerminalPromptIcon } from './Icons'

/** Dropdown cu comenzi salvate: click pe una → o inserează în sesiune.
    „Gestionează" deschide un mic editor (adaugă / editează / șterge). */
export default function SnippetsMenu(props: {
  onInsert: (body: string) => void
  /** control extern (scurtătura Alt+S din App) */
  open?: boolean
  onOpenChange?: (open: boolean) => void
  /** clase pentru butonul-declanşator (ex. `hidden sm:grid`): pe telefon butonul nu încape în
      bară, dar meniul TREBUIE să rămână montat — îl deschid itemul din ⋯ şi Alt+S */
  triggerClassName?: string
}) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const [openState, setOpenState] = useState(false)
  const open = props.open ?? openState
  const setOpen = (v: boolean | ((p: boolean) => boolean)) => {
    const next = typeof v === 'function' ? v(open) : v
    setOpenState(next)
    props.onOpenChange?.(next)
  }
  // `setOpen` se recreează la fiecare randare (nu e setter de stare, e un wrapper peste
  // `props.onOpenChange`). Listenerul de click-away de mai jos trebuie ataşat O SINGURĂ
  // dată, dar să apeleze mereu ULTIMUL `setOpen` — altfel ar închide meniul chemând un
  // `onOpenChange` capturat la montare.
  const setOpenRef = useRef(setOpen)
  setOpenRef.current = setOpen
  const [snips, setSnips] = useState<Snippet[]>([])
  const [managing, setManaging] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  // ţintele pentru consola de flotă, ca text liber („prod, web"); gol = fără ţinte
  const [tags, setTags] = useState('')
  const [filter, setFilter] = useState('')
  const [saveErr, setSaveErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [askParams, setAskParams] = useState<Snippet | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  // eroare ≠ gol (U17): „niciun snippet" pe un fetch picat te trimitea să le re-creezi
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const load = () => api<Snippet[]>('/api/snippets')
    .then((r) => { setSnips(r); setLoadErr(null) })
    .catch((e) => setLoadErr(errText(e, t) || t('common.loadFailed')))
  useEffect(() => {
    if (open) {
      setFilter('')
      load()
    }
  }, [open])
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      const target = e.target as Node
      // dialogul de confirmare e montat în afara meniului (provider global): un click pe
      // „Şterge" din el NU e „click-away" — altfel meniul se închidea sub dialog
      if (target instanceof Element && target.closest('[role="dialog"],[role="alertdialog"]')) return
      if (ref.current && !ref.current.contains(target)) setOpenRef.current(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  async function save() {
    if (!title.trim() || !body) return
    setSaveErr('')
    setSaving(true)
    try {
      const targets = targetsPayload(parseTagInput(tags))
      if (editId) await api(`/api/snippets/${editId}`, { method: 'PATCH', body: JSON.stringify({ title, body, targets }) })
      else await api('/api/snippets', { method: 'POST', body: JSON.stringify({ title, body, targets }) })
      // formularul se golește DOAR la succes — la eroare păstrăm ce ai scris
      setTitle('')
      setBody('')
      setTags('')
      setEditId(null)
      load()
    } catch (e) {
      setSaveErr(errText(e, t) || t('snippets.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  async function remove(id: number, title: string) {
    // Un clic pe „✕" ştergea definitiv, fără confirmare, fără undo, fără toast — singura
    // acţiune ireversibilă din produs fără nicio plasă. Restul confirmă lucruri mult mai
    // puţin costisitoare.
    if (!(await confirm({ title: t('snippets.deleteTitle', { title }), message: t('snippets.confirmDelete', { title }), danger: true }))) return
    try {
      await api(`/api/snippets/${id}`, { method: 'DELETE' })
    } catch (e) {
      setSaveErr(errText(e, t) || t('snippets.deleteFailed'))
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
        aria-label={t('snippets.savedCommands')}
        aria-expanded={open}
        onMouseDown={(e) => e.preventDefault()}
        onClick={() => setOpen((v) => !v)}
        className={`wt-touch place-items-center rounded-md px-1.5 py-1 text-sm text-slate-400 hover:bg-ink-700 ${props.triggerClassName ?? 'grid'}`}
      >
        <TerminalPromptIcon />
      </button>
      {open && (
        /* telefon (< sm): foaie de jos peste keybar — fără ancoră vizibilă în bară, un dropdown
           absolut ar apărea în colţul greşit sau în afara ecranului; de la sm: dropdown clasic */
        <div data-testid="snippets-menu"
          className="fixed inset-x-2 bottom-[calc(var(--wt-keybar-h,0px)+0.5rem)] z-40 rounded-xl border border-ink-700 bg-ink-900 p-1.5 shadow-2xl sm:absolute sm:inset-x-auto sm:bottom-auto sm:right-0 sm:z-30 sm:mt-1 sm:w-72">
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
                  className="mb-1 w-full rounded-md bg-ink-800 px-2 py-1.5 text-sm ring-1 ring-ink-700 placeholder:text-slate-600 focus:ring-sky-500"
                />
              )}
              <div className="max-h-64 overflow-y-auto">
                {loadErr !== null && (
                  <ErrorState compact title={t('common.loadFailed')} message={loadErr} onRetry={load} />
                )}
                {loadErr === null && snips.length === 0 && (
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
                      className="block w-full rounded-md px-2 py-1.5 text-left hover:bg-ink-800"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-sm text-slate-200">{s.title}</span>
                        {params.length > 0 && (
                          <span className="shrink-0 rounded-md bg-ink-800 px-1 text-2xs text-slate-400 ring-1 ring-ink-700">
                            {t('snippets.paramsCount', { n: params.length })}
                          </span>
                        )}
                        <SnippetTags tags={snippetTags(s)} className="ml-auto" />
                      </div>
                      <div className="truncate font-mono text-2xs text-slate-500">{s.body}</div>
                    </button>
                  )
                })}
              </div>
              <button
                onClick={() => setManaging(true)}
                className="mt-1 w-full rounded-md px-2 py-1 text-left text-xs wt-link hover:bg-ink-800"
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
                className="w-full rounded-md bg-ink-800 px-2 py-1.5 text-sm ring-1 ring-ink-700 focus:ring-sky-500"
              />
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder={t('snippets.bodyPlaceholder')}
                rows={2}
                className="w-full rounded-md bg-ink-800 px-2 py-1.5 font-mono text-xs ring-1 ring-ink-700 focus:ring-sky-500"
              />
              <input
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder={t('snippets.targetsPlaceholder')}
                aria-label={t('snippets.targetsLabel')}
                title={t('snippets.targetsHint')}
                className="w-full rounded-md bg-ink-800 px-2 py-1.5 text-xs ring-1 ring-ink-700 placeholder:text-slate-600 focus:ring-sky-500"
              />
              {saveErr && <div className="px-1 text-xs wt-danger">{saveErr}</div>}
              <div className="flex gap-1.5">
                <Button variant="primary" size="sm" onClick={save} disabled={saving}>
                  {saving ? t('snippets.saving') : editId ? t('common.save') : t('snippets.add')}
                </Button>
                <button onClick={() => { setManaging(false); setEditId(null); setTitle(''); setBody(''); setTags('') }} className="rounded-md px-2.5 py-1 text-xs text-slate-400 hover:bg-ink-800">
                  {t('snippets.back')}
                </button>
              </div>
              <div className="max-h-40 overflow-y-auto border-t border-ink-800 pt-1">
                {snips.map((s) => (
                  <div key={s.id} className="flex items-center gap-1 rounded-md px-2 py-1 hover:bg-ink-800">
                    <button
                      onClick={() => { setEditId(s.id); setTitle(s.title); setBody(s.body); setTags(snippetTags(s).join(', ')) }}
                      className="min-w-0 flex-1 truncate text-left text-xs text-slate-300"
                    >
                      {s.title}
                    </button>
                    <SnippetTags tags={snippetTags(s)} />
                    {/* ţintă de 24px (era textul „✕" gol, ~10px) şi culoare semantică, nu rose-500/80 */}
                    <button onClick={() => remove(s.id, s.title)}
                      title={t('snippets.deleteTitle', { title: s.title })}
                      aria-label={t('snippets.deleteTitle', { title: s.title })}
                      className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-xs wt-danger hover:bg-ink-700">
                      <CloseIcon size={14} />
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
