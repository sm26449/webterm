import { DragEvent, useEffect, useMemo, useRef, useState } from 'react'
import { api, errText, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { csvToRows, CsvRow, importPayload, IMPORT_MAX, previewRows, RowStatus } from '../lib/hostscsv'
import { field } from './settings/ui'
import { Button } from './ui'
import HelpTip from './HelpTip'
import InstallCommand from './InstallCommand'

/* Export / import CSV de hosturi (3.5.4). Mutarea unui subset de hosturi pe alt gateway, sau o
   listă editabilă într-un spreadsheet — FĂRĂ secrete (nici parole, nici chei, nici tokenuri).

   Unde stă în UI (alegerea cea mai puţin invazivă):
   - IMPORTUL e un al treilea mod în Add host („O maşină / Mai multe maşini / Import CSV") — e tot
     „adaug hosturi", deci locul unde omul deja le adaugă;
   - EXPORTUL e un dialog propriu, deschis din antetul unui folder din sidebar (preselectat pe
     folderul ăla) sau din modul Import CSV („Exportă hosturi…"). NU un tab nou în Settings: un
     tab ar fi atins navigarea cu tastatura verificată de a11y şi ar fi ascuns o acţiune pe
     hosturi într-un ecran de preferinţe. Selecţia pe folder/etichetă e în dialog. */

const label = 'mb-1 block text-xs font-medium text-slate-400'

type ImportResult = { index: number; ok: boolean; id?: number; name?: string; code?: string
  vars?: Record<string, string | number>; skipped?: boolean; install_command?: string
  install_command_dedicated?: string }

function statusText(s: RowStatus, t: (k: string, v?: Record<string, string | number>) => string): string {
  if (s.kind !== 'error') {
    return t(s.kind === 'new' ? 'hostcsv.status.new' : s.kind === 'agent' ? 'hostcsv.status.agent' : 'hostcsv.status.exists')
  }
  const key = 'err.' + s.code
  const msg = t(key, s.vars)
  return t('hostcsv.status.error', { reason: msg === key ? s.code : msg })
}

const statusClass = (s: RowStatus) =>
  s.kind === 'error' ? 'wt-danger' : s.kind === 'exists' ? 'text-slate-400' : s.kind === 'agent' ? 'wt-warn' : 'wt-good'

export function HostsCsvImport(props: { onClose: () => void; onImported?: () => void; onExport?: () => void }) {
  const { t } = useI18n()
  const [text, setText] = useState('')
  const [rows, setRows] = useState<CsvRow[] | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [selected, setSelected] = useState<boolean[]>([])
  const [folder, setFolder] = useState('')
  const [tags, setTags] = useState('')
  const [policy, setPolicy] = useState<'ask' | 'stored'>('ask')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [drag, setDrag] = useState(false)
  const [result, setResult] = useState<{ created: number; skipped: number; byRow: Record<number, ImportResult> } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const textRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    api<Host[]>('/api/hosts').then(setHosts).catch(() => {})
  }, [])

  const statuses = useMemo(() => (rows ? previewRows(rows, hosts, policy) : []), [rows, hosts, policy])

  function load(src: string) {
    setError(''); setResult(null)
    const { rows: rs, error: e } = csvToRows(src)
    if (e) { setRows(null); setError(t(e === 'empty' ? 'hostcsv.emptyFile' : 'hostcsv.noHeader')); return }
    if (!rs.length) { setRows(null); setError(t('hostcsv.emptyFile')); return }
    if (rs.length > IMPORT_MAX) { setRows(null); setError(t('err.hostcsv.tooMany', { max: IMPORT_MAX })); return }
    setRows(rs)
  }
  // bifa implicită: doar ce chiar se poate crea (noi + agenţi); duplicatele şi erorile rămân nebifate
  useEffect(() => {
    if (rows) setSelected(previewRows(rows, hosts, 'ask').map((s) => s.kind === 'new' || s.kind === 'agent'))
  }, [rows, hosts])

  async function readFile(f: File | undefined) {
    if (!f) return
    if (f.size > 2 * 1024 * 1024) { setError(t('hostcsv.fileTooBig')); return }
    const s = await f.text()
    setText(s)
    load(s)
  }
  function onDrop(e: DragEvent) {
    e.preventDefault(); setDrag(false)
    void readFile(e.dataTransfer.files?.[0])
  }

  async function doImport() {
    if (!rows) return
    setBusy(true); setError('')
    const idx = rows.map((_, i) => i).filter((i) => selected[i])
    try {
      const r = await api<{ created: number; skipped: number; results: ImportResult[] }>('/api/hosts/import', {
        method: 'POST',
        body: JSON.stringify({ rows: importPayload(rows, selected), options: { folder, tags, credential_policy: policy } }),
      })
      const byRow: Record<number, ImportResult> = {}
      for (const x of r.results) byRow[idx[x.index]] = x
      setResult({ created: r.created, skipped: r.skipped, byRow })
      props.onImported?.()
    } catch (err) {
      setError(errText(err, t) || String(err))
    } finally {
      setBusy(false)
    }
  }

  const nSel = selected.filter(Boolean).length
  const agents = result ? Object.values(result.byRow).filter((x) => x.ok && x.install_command) : []

  if (result && rows) {
    const failed = Object.entries(result.byRow).filter(([, x]) => !x.ok)
    return (
      <div className="space-y-3" data-testid="csv-import-result">
        <p role="status" className="text-sm text-slate-200">
          {t('hostcsv.imported', { created: result.created, skipped: result.skipped })}
        </p>
        {failed.length > 0 && (
          <ul className="max-h-40 space-y-1 overflow-y-auto text-xs">
            {failed.map(([i, x]) => (
              <li key={i} className={x.skipped ? 'text-slate-400' : 'wt-danger'}>
                <span className="font-medium">{rows[+i]?.name || `#${+i + 1}`}</span>{' — '}
                {x.code ? (t('err.' + x.code, x.vars) !== 'err.' + x.code ? t('err.' + x.code, x.vars) : x.code) : ''}
              </li>
            ))}
          </ul>
        )}
        {agents.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs text-slate-400">{t('hostcsv.agentsInstall', { n: agents.length })}</p>
            {agents.map((a) => (
              <div key={a.id} className="space-y-1">
                <p className="text-xs font-medium text-slate-300">{a.name}</p>
                <InstallCommand command={a.install_command!} commandDedicated={a.install_command_dedicated} />
              </div>
            ))}
          </div>
        )}
        <div className="text-right">
          <Button variant="primary" size="lg" type="button" onClick={props.onClose}>{t('addhost.done')}</Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3" data-testid="csv-import">
      <p className="flex items-start gap-2 text-xs text-slate-500">
        <span className="flex-1">{t('hostcsv.importDesc')}</span>
        <HelpTip id="hostsCsv" />
      </p>
      {!rows ? (
        <>
          <div onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={onDrop}
            className={`rounded-xl border border-dashed p-3 text-center text-sm ${drag ? 'border-sky-500 bg-sky-500/10' : 'border-ink-700'}`}>
            <p className="text-slate-400">{t('hostcsv.dropHere')}</p>
            <input ref={fileRef} type="file" accept=".csv,text/csv" className="sr-only" data-testid="csv-file"
              aria-label={t('hostcsv.chooseFile')} onChange={(e) => void readFile(e.target.files?.[0])} />
            <Button variant="secondary" type="button" onClick={() => fileRef.current?.click()} className="mt-2">
              {t('hostcsv.chooseFile')}
            </Button>
          </div>
          <label className="block">
            <span className={label}>{t('hostcsv.pasteLabel')}</span>
            <textarea ref={textRef} value={text} onChange={(e) => setText(e.target.value)} rows={5} spellCheck={false}
              data-testid="csv-text" placeholder="name,connection_type,hostname,port,username,…"
              className={`${field} font-mono text-xs`} />
          </label>
        </>
      ) : (
        <>
          <div className="max-h-64 overflow-auto rounded-md ring-1 ring-ink-700">
            <table className="w-full text-left text-xs">
              <caption className="sr-only">{t('hostcsv.previewCaption')}</caption>
              <thead className="sticky top-0 bg-ink-900 text-slate-400">
                <tr>
                  <th scope="col" className="w-8 px-2 py-1.5">
                    <input type="checkbox" aria-label={t('hostcsv.selectAllRows')}
                      checked={nSel > 0 && nSel === rows.length}
                      onChange={(e) => setSelected(rows.map(() => e.target.checked))} className="h-4 w-4 accent-sky-600" />
                  </th>
                  <th scope="col" className="px-2 py-1.5">{t('hostcsv.colName')}</th>
                  <th scope="col" className="px-2 py-1.5">{t('hostcsv.colType')}</th>
                  <th scope="col" className="px-2 py-1.5">{t('hostcsv.colAddress')}</th>
                  <th scope="col" className="px-2 py-1.5">{t('hostcsv.colStatus')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className="border-t border-ink-800" data-testid="csv-row">
                    <td className="px-2 py-1">
                      <input type="checkbox" checked={!!selected[i]}
                        aria-label={t('hostcsv.selectRow', { name: r.name || `#${i + 1}` })}
                        onChange={(e) => setSelected(selected.map((v, j) => (j === i ? e.target.checked : v)))}
                        className="h-4 w-4 accent-sky-600" />
                    </td>
                    <td className="max-w-[9rem] truncate px-2 py-1 text-slate-200">{r.name}</td>
                    <td className="px-2 py-1 text-slate-400">{r.connection_type}</td>
                    <td className="max-w-[9rem] truncate px-2 py-1 text-slate-400">
                      {r.connection_type === 'agent' ? '' : [r.username && `${r.username}@`, r.hostname, r.port && `:${r.port}`].filter(Boolean).join('')}
                    </td>
                    <td className={`px-2 py-1 ${statusClass(statuses[i])}`} data-testid="csv-row-status" data-kind={statuses[i]?.kind}>
                      {statuses[i] && statusText(statuses[i], t)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="block">
              <span className={label}>{t('hostcsv.folderOverride')}</span>
              <input value={folder} onChange={(e) => setFolder(e.target.value)} placeholder={t('hostcsv.folderKeep')} className={field} />
            </label>
            <label className="block">
              <span className={label}>{t('hostcsv.extraTags')}</span>
              <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="imported, lab" className={field} />
            </label>
          </div>
          <label className="block">
            <span className={label}>{t('hostcsv.policy')}</span>
            <select value={policy} onChange={(e) => setPolicy(e.target.value as 'ask' | 'stored')} className={field}>
              <option value="ask">{t('hostcsv.policyAsk')}</option>
              <option value="stored">{t('hostcsv.policyStored')}</option>
            </select>
            <span className="mt-1 block text-xs text-slate-500">{t('hostcsv.policyHint')}</span>
          </label>
        </>
      )}
      <div id="csv-import-error" role="alert" className={error ? 'text-sm wt-danger' : 'sr-only'}>{error}</div>
      <div className="flex flex-wrap items-center justify-end gap-2">
        {props.onExport && !rows && (
          <Button variant="ghost" type="button" onClick={props.onExport} className="mr-auto">{t('hostcsv.exportLink')}</Button>
        )}
        {rows && (
          <Button variant="ghost" type="button" onClick={() => { setRows(null); setError('') }} className="mr-auto">
            {t('hostcsv.back')}
          </Button>
        )}
        <Button variant="ghost" size="lg" type="button" onClick={props.onClose}>{t('addhost.cancel')}</Button>
        {!rows ? (
          <Button variant="primary" size="lg" type="button" disabled={!text.trim()} onClick={() => load(text)}>
            {t('hostcsv.preview')}
          </Button>
        ) : (
          <Button variant="primary" size="lg" type="button" disabled={busy || nSel === 0} onClick={doImport}>
            {t('hostcsv.importN', { n: nSel })}
          </Button>
        )}
      </div>
    </div>
  )
}

/** Dialogul de export: listă de hosturi cu bife + selecţie rapidă pe folder / etichetă. */
export function ExportHostsModal(props: { hosts: Host[]; presetFolder?: string; onClose: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  // aceeaşi vizibilitate ca sidebar-ul: ţintele „conectează o dată" nu sunt hosturi salvate
  const list = useMemo(() => props.hosts.filter((h) => !h.ephemeral)
    .sort((a, b) => a.name.localeCompare(b.name)), [props.hosts])
  const [sel, setSel] = useState<Set<number>>(() => new Set(
    props.presetFolder === undefined ? [] : list.filter((h) => (h.folder || '') === props.presetFolder).map((h) => h.id)))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const folders = [...new Set(list.map((h) => h.folder || ''))].sort()
  const tags = [...new Set(list.flatMap((h) => h.tags || []))].sort()

  const allOf = (ids: number[]) => ids.length > 0 && ids.every((id) => sel.has(id))
  function toggleGroup(ids: number[]) {
    const next = new Set(sel)
    if (allOf(ids)) ids.forEach((id) => next.delete(id))
    else ids.forEach((id) => next.add(id))
    setSel(next)
  }

  async function doExport() {
    setBusy(true); setError('')
    try {
      const ids = list.filter((h) => sel.has(h.id)).map((h) => h.id).join(',')
      const res = await fetch(`/api/hosts/export.csv?ids=${ids}`, { credentials: 'same-origin' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '')?.[1] || 'webterm-hosts.csv'
      const url = URL.createObjectURL(await res.blob())
      const a = document.createElement('a')
      a.href = url; a.download = name
      document.body.appendChild(a); a.click(); a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 10_000)
      props.onClose()
    } catch (err) {
      setError(errText(err, t) || String(err))
    } finally {
      setBusy(false)
    }
  }

  const chip = (on: boolean) => `rounded-full px-2.5 py-1 text-xs ring-1 transition ${
    on ? 'bg-sky-600 text-white ring-sky-600' : 'text-slate-300 ring-ink-700 hover:bg-ink-800'}`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="csv-export-title" data-testid="csv-export"
        className="glass flex max-h-[90vh] w-full max-w-lg flex-col gap-3 overflow-y-auto rounded-2xl p-6">
        <h2 id="csv-export-title" className="flex items-center gap-2 font-semibold">
          {t('hostcsv.exportTitle')}<HelpTip id="hostsCsv" />
        </h2>
        <p className="text-xs text-slate-500">{t('hostcsv.exportDesc')}</p>
        <div className="flex flex-wrap gap-1.5">
          <button type="button" aria-pressed={allOf(list.map((h) => h.id))} className={chip(allOf(list.map((h) => h.id)))}
            onClick={() => toggleGroup(list.map((h) => h.id))}>{t('hostcsv.selectAll')}</button>
          {folders.map((f) => {
            const ids = list.filter((h) => (h.folder || '') === f).map((h) => h.id)
            return (
              <button key={'f:' + f} type="button" aria-pressed={allOf(ids)} className={chip(allOf(ids))}
                onClick={() => toggleGroup(ids)}>
                {t('hostcsv.byFolder', { folder: f || t('sidebar.noFolder') })}
              </button>
            )
          })}
          {tags.map((tg) => {
            const ids = list.filter((h) => (h.tags || []).includes(tg)).map((h) => h.id)
            return (
              <button key={'t:' + tg} type="button" aria-pressed={allOf(ids)} className={chip(allOf(ids))}
                onClick={() => toggleGroup(ids)}>#{tg}</button>
            )
          })}
        </div>
        <fieldset className="max-h-64 overflow-y-auto rounded-md p-1 ring-1 ring-ink-700">
          <legend className="sr-only">{t('hostcsv.hostsLegend')}</legend>
          {list.length === 0 && <p className="p-2 text-sm text-slate-500">{t('hostcsv.noHosts')}</p>}
          {list.map((h) => (
            <label key={h.id} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-ink-800">
              <input type="checkbox" checked={sel.has(h.id)} className="h-4 w-4 accent-sky-600"
                onChange={() => { const n = new Set(sel); if (n.has(h.id)) n.delete(h.id); else n.add(h.id); setSel(n) }} />
              <span className="min-w-0 flex-1 truncate text-slate-200">{h.name}</span>
              <span className="shrink-0 text-xs text-slate-500">{h.connection_type || 'agent'}{h.folder ? ` · ${h.folder}` : ''}</span>
            </label>
          ))}
        </fieldset>
        <div role="alert" className={error ? 'text-sm wt-danger' : 'sr-only'}>{error}</div>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="lg" type="button" onClick={props.onClose}>{t('addhost.cancel')}</Button>
          <Button variant="primary" size="lg" type="button" disabled={busy || sel.size === 0} onClick={doExport}>
            {t('hostcsv.exportN', { n: sel.size })}
          </Button>
        </div>
      </div>
    </div>
  )
}
