import { useEffect, useRef, useState } from 'react'
import * as monaco from 'monaco-editor'
import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import jsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker'
import cssWorker from 'monaco-editor/esm/vs/language/css/css.worker?worker'
import htmlWorker from 'monaco-editor/esm/vs/language/html/html.worker?worker'
import tsWorker from 'monaco-editor/esm/vs/language/typescript/ts.worker?worker'
import { errText, api, ensureStepup } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

// Workerele Monaco, bundle-uite LOCAL de Vite (`?worker`) — fără CDN, fără phone-home, ca
// restul gateway-ului. Întregul modul e lazy-loaded din FilePanel, deci Monaco (~mare) + workerele
// se descarcă DOAR când deschizi editorul, nu în bundle-ul principal.
;(self as unknown as { MonacoEnvironment: monaco.Environment }).MonacoEnvironment = {
  getWorker(_id, label) {
    if (label === 'json') return new jsonWorker()
    if (label === 'css' || label === 'scss' || label === 'less') return new cssWorker()
    if (label === 'html' || label === 'handlebars' || label === 'razor') return new htmlWorker()
    if (label === 'typescript' || label === 'javascript') return new tsWorker()
    return new editorWorker()
  },
}

interface Preview {
  path: string
  size: number
  mtime: number
  editable: boolean
  truncated: boolean
  binary: boolean
  text: string
}

// extensie → id de limbaj Monaco (built-in). Monaco aduce gramaticile cu el; cele necunoscute
// (toml→ini, nginx→plaintext) cad pe cel mai apropiat, niciodată eroare.
function monacoLang(name: string, firstLine: string): string {
  const n = name.toLowerCase()
  if (n === 'dockerfile') return 'dockerfile'
  if (n.includes('nginx')) return 'ini'
  const ext = n.includes('.') ? n.split('.').pop()! : ''
  const map: Record<string, string> = {
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
    ts: 'typescript', tsx: 'typescript',
    json: 'json', json5: 'json', webmanifest: 'json',
    py: 'python', pyw: 'python',
    md: 'markdown', markdown: 'markdown',
    html: 'html', htm: 'html',
    css: 'css', scss: 'scss', less: 'less',
    xml: 'xml', svg: 'xml', xsl: 'xml', plist: 'xml',
    yaml: 'yaml', yml: 'yaml',
    sql: 'sql',
    c: 'cpp', h: 'cpp', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
    rs: 'rust', php: 'php', go: 'go', rb: 'ruby', java: 'java',
    sh: 'shell', bash: 'shell', zsh: 'shell', ksh: 'shell',
    toml: 'ini', conf: 'ini', cfg: 'ini', ini: 'ini', properties: 'ini', env: 'ini',
    dockerfile: 'dockerfile',
  }
  if (map[ext]) return map[ext]
  if (/^#!.*\b(sh|bash|zsh)\b/.test(firstLine)) return 'shell'
  return 'plaintext'
}

/** Editor de fișiere cu Monaco (motorul VS Code): highlight după tip, temă vs-dark, fișiere mari
    doar în citire (primii 256KB), salvare atomică cu verificare de conflict (mtime). Lazy-loaded
    din FilePanel → nici Monaco, nici workerele nu intră în bundle-ul principal. */
export default function FileEditor(props: {
  hostId: number
  path: string
  name: string
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useI18n()
  const host = useRef<HTMLDivElement>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)   // Tab trap + Escape + restaurare focus
  const editor = useRef<monaco.editor.IStandaloneCodeEditor>()
  const [pv, setPv] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [conflict, setConflict] = useState(false)

  useEffect(() => {
    let alive = true
    api<Preview>(`/api/hosts/${props.hostId}/fs/preview?path=${encodeURIComponent(props.path)}`)
      .then((p) => { if (alive) setPv(p) })
      .catch((e) => { if (alive) setError(errText(e, t) || t('files.readFail')) })
    return () => { alive = false }
  }, [props.hostId, props.path, t])

  useEffect(() => {
    if (!pv || pv.binary || !host.current) return
    const firstLine = pv.text.slice(0, (pv.text.indexOf('\n') + 1) || 200)
    const ed = monaco.editor.create(host.current, {
      value: pv.text,
      language: monacoLang(props.name, firstLine),
      theme: 'vs-dark',               // aspectul autentic VS Code
      readOnly: !pv.editable,
      automaticLayout: true,          // se redimensionează cu dialogul
      minimap: { enabled: true },
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 13,
      scrollBeyondLastLine: false,
      renderWhitespace: 'selection',
      tabSize: 2,
    })
    editor.current = ed
    // Ctrl/Cmd+S din interiorul editorului (Monaco prinde tastatura când are focus)
    ed.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => saveRef.current(false))
    return () => { ed.getModel()?.dispose(); ed.dispose(); editor.current = undefined }
  }, [pv, props.name])

  async function save(force = false) {
    if (!pv || !editor.current || pv.binary || !pv.editable) return
    setSaving(true)
    setError('')
    const body = new TextEncoder().encode(editor.current.getValue())
    // if_mtime = protecție contra suprascrierii unei modificări concurente; la „suprascrie oricum" o omitem
    const q = force ? '' : `&if_mtime=${pv.mtime}`
    try {
      const url = `/api/hosts/${props.hostId}/fs/upload?path=${encodeURIComponent(props.path)}${q}`
      const send = () => fetch(url, { method: 'POST', body, credentials: 'same-origin' })
      let res = await send()
      // editare lungă pe host cu 2FA → fereastra de step-up poate expira; 403 → ceremonie + reîncercare (H1)
      if (res.status === 403 && (await ensureStepup(props.hostId))) res = await send()
      if (res.status === 409) { setConflict(true); setSaving(false); return }
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? t('files.saveFail'))
      props.onSaved()
      props.onClose()
    } catch (e) {
      setError(errText(e, t) || t('files.genericErr'))
      setSaving(false)
    }
  }

  // Ctrl/Cmd+S global (când focusul NU e în editor — ex. pe butoane). save() e no-op pe
  // fișiere view-only/binare, deci apelul e sigur oricând.
  const saveRef = useRef(save)
  saveRef.current = save
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 's' || e.key === 'S')) {
        e.preventDefault()
        saveRef.current(false)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [])

  return (
    <div className="wt-editor fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('files.editAria', { name: props.name })}
        className="glass flex h-[85dvh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-2">
          <span className="truncate font-mono text-xs text-slate-400">{props.path}</span>
          {pv?.truncated && (
            <span className="shrink-0 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] wt-warn ring-1 ring-amber-500/25" title={t('files.bigFileTitle')}>
              {t('files.viewOnlyBadge')}
            </span>
          )}
          <div className="ml-auto flex shrink-0 gap-2">
            {pv && !pv.binary && pv.editable && (
              <button onClick={() => save(false)} disabled={saving} className="rounded-lg bg-sky-600 px-3 py-1 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                {saving ? t('files.saving') : t('files.save')}
              </button>
            )}
            <button onClick={props.onClose} className="rounded-lg px-3 py-1 text-sm text-slate-400 hover:bg-ink-800">{t('files.close')}</button>
          </div>
        </div>

        {error && <div className="border-b border-ink-800 bg-ink-800 px-4 py-1.5 text-xs wt-danger">{error}</div>}
        {conflict && (
          <div className="flex items-center gap-3 border-b border-ink-800 bg-amber-950/40 px-4 py-2 text-xs">
            <span className="wt-warn">{t('files.conflictMsg')}</span>
            <button onClick={() => { setConflict(false); save(true) }} className="rounded bg-amber-600 px-2 py-0.5 font-medium text-white hover:bg-amber-700">{t('files.overwriteAnyway')}</button>
            <button onClick={() => setConflict(false)} className="text-slate-400 hover:underline">{t('files.cancel')}</button>
          </div>
        )}

        {!pv && !error && <div className="flex flex-1 items-center justify-center text-sm text-slate-500">{t('files.loading')}</div>}
        {pv?.binary && (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 p-6 text-center text-sm text-slate-500">
            <p>{t('files.binaryMsg')}</p>
            <a href={`/api/hosts/${props.hostId}/fs/download?path=${encodeURIComponent(props.path)}`} download={props.name} className="wt-link hover:underline">{t('files.download')}</a>
          </div>
        )}
        {pv && !pv.binary && <div ref={host} className="min-h-0 flex-1 overflow-hidden text-[13px]" />}
      </div>
    </div>
  )
}
