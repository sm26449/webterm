import { useEffect, useRef, useState } from 'react'
import { EditorState, Extension } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import { indentWithTab } from '@codemirror/commands'
import { StreamLanguage } from '@codemirror/language'
import { oneDark } from '@codemirror/theme-one-dark'
import { basicSetup } from 'codemirror'
import { api, ensureStepup } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

interface Preview {
  path: string
  size: number
  mtime: number
  editable: boolean
  truncated: boolean
  binary: boolean
  text: string
}

// fiecare gramatică e un import DINAMIC (chunk separat): deschizi un .json și se
// încarcă doar gramatica json, nu toate. Nucleul editorului rămâne mic.
async function legacy(mod: Promise<Record<string, unknown>>, key: string): Promise<Extension> {
  return StreamLanguage.define((await mod)[key] as Parameters<typeof StreamLanguage.define>[0])
}

function loaderFor(name: string, firstLine: string): (() => Promise<Extension>) | null {
  const n = name.toLowerCase()
  const ext = n.includes('.') ? n.split('.').pop()! : ''
  if (n === 'dockerfile') return () => legacy(import('@codemirror/legacy-modes/mode/dockerfile'), 'dockerFile')
  if (n.includes('nginx')) return () => legacy(import('@codemirror/legacy-modes/mode/nginx'), 'nginx')
  switch (ext) {
    case 'js': case 'jsx': case 'mjs': case 'cjs':
      return () => import('@codemirror/lang-javascript').then((m) => m.javascript({ jsx: ext.endsWith('x') }))
    case 'ts': case 'tsx':
      return () => import('@codemirror/lang-javascript').then((m) => m.javascript({ typescript: true, jsx: ext.endsWith('x') }))
    case 'json': case 'json5': case 'webmanifest':
      return () => import('@codemirror/lang-json').then((m) => m.json())
    case 'py': case 'pyw':
      return () => import('@codemirror/lang-python').then((m) => m.python())
    case 'md': case 'markdown':
      return () => import('@codemirror/lang-markdown').then((m) => m.markdown())
    case 'html': case 'htm':
      return () => import('@codemirror/lang-html').then((m) => m.html())
    case 'css': case 'scss': case 'less':
      return () => import('@codemirror/lang-css').then((m) => m.css())
    case 'xml': case 'svg': case 'xsl': case 'plist':
      return () => import('@codemirror/lang-xml').then((m) => m.xml())
    case 'yaml': case 'yml':
      return () => import('@codemirror/lang-yaml').then((m) => m.yaml())
    case 'sql':
      return () => import('@codemirror/lang-sql').then((m) => m.sql())
    case 'c': case 'h': case 'cpp': case 'cc': case 'cxx': case 'hpp':
      return () => import('@codemirror/lang-cpp').then((m) => m.cpp())
    case 'rs':
      return () => import('@codemirror/lang-rust').then((m) => m.rust())
    case 'php':
      return () => import('@codemirror/lang-php').then((m) => m.php())
    case 'sh': case 'bash': case 'zsh': case 'ksh':
      return () => legacy(import('@codemirror/legacy-modes/mode/shell'), 'shell')
    case 'toml':
      return () => legacy(import('@codemirror/legacy-modes/mode/toml'), 'toml')
    case 'conf': case 'cfg': case 'ini': case 'properties': case 'env':
      return () => legacy(import('@codemirror/legacy-modes/mode/properties'), 'properties')
  }
  if (/^#!.*\b(sh|bash|zsh)\b/.test(firstLine))
    return () => legacy(import('@codemirror/legacy-modes/mode/shell'), 'shell')
  return null
}

/** Editor de fișiere cu CodeMirror 6: highlight după tip (gramatici lazy),
    fișiere mari doar în citire (primii 256KB), salvare atomică cu verificare de
    conflict (mtime). Lazy-loaded din FilePanel → nu intră în bundle-ul principal. */
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
  const view = useRef<EditorView>()
  const [pv, setPv] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [conflict, setConflict] = useState(false)

  useEffect(() => {
    let alive = true
    api<Preview>(`/api/hosts/${props.hostId}/fs/preview?path=${encodeURIComponent(props.path)}`)
      .then((p) => { if (alive) setPv(p) })
      .catch((e) => { if (alive) setError(e instanceof Error ? e.message : t('files.readFail')) })
    return () => { alive = false }
  }, [props.hostId, props.path])

  useEffect(() => {
    if (!pv || pv.binary || !host.current) return
    let v: EditorView | undefined
    let alive = true
    ;(async () => {
      const firstLine = pv.text.slice(0, (pv.text.indexOf('\n') + 1) || 200)
      const loader = loaderFor(props.name, firstLine)
      const lang = loader ? await loader().catch(() => null) : null
      if (!alive || !host.current) return
      const exts: Extension[] = [
        basicSetup, oneDark, keymap.of([indentWithTab]),
        EditorView.theme({ '&': { height: '100%' }, '.cm-scroller': { fontFamily: 'JetBrains Mono, monospace' } }),
      ]
      if (lang) exts.push(lang)
      if (!pv.editable) exts.push(EditorState.readOnly.of(true), EditorView.editable.of(false))
      v = new EditorView({ state: EditorState.create({ doc: pv.text, extensions: exts }), parent: host.current })
      view.current = v
    })()
    return () => { alive = false; v?.destroy(); view.current = undefined }
  }, [pv, props.name])

  async function save(force = false) {
    if (!pv || !view.current || pv.binary || !pv.editable) return
    setSaving(true)
    setError('')
    const body = new TextEncoder().encode(view.current.state.doc.toString())
    // if_mtime = protecție contra suprascrierii unei modificări concurente;
    // la „suprascrie oricum" o omitem
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
      setError(e instanceof Error ? e.message : t('files.genericErr'))
      setSaving(false)
    }
  }

  // Ctrl/Cmd+S salvează (Tab e prins de CodeMirror pentru indentare, deci fără
  // asta un utilizator pe tastatură nu poate ajunge la butonul Salvează). save()
  // e no-op pe fișiere view-only/binare, deci apelul e sigur oricând.
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
