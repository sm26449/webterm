import { useEffect, useRef, useState } from 'react'
import * as monaco from 'monaco-editor/editor/editor.api'
import './monacoSetup'          // feature-urile, limbajele şi workerul (Monaco slim, vezi acolo)
import { errText, api, ensureStepup } from '../lib/api'
import { detectLanguage } from '../lib/editorLang'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useTheme } from '../lib/theme'
import { fmtBytes } from '../lib/uploads'
import { notifyToast } from '../lib/notify'
import ConfirmModal from './ConfirmModal'

interface Preview {
  path: string
  size: number
  mtime: number
  editable: boolean
  truncated: boolean
  binary: boolean
  text: string
}

/** Editor de fișiere cu Monaco (motorul VS Code): highlight după tip, temă după tema aplicației
    (vs / vs-dark), fișiere mari doar în citire (primii 256KB), salvare atomică cu verificare de
    conflict (mtime), gardă „modificări nesalvate" la închidere. Lazy-loaded din FilePanel → nici
    Monaco, nici workerele nu intră în bundle-ul principal. */
export default function FileEditor(props: {
  hostId: number
  path: string
  name: string
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useI18n()
  const [, theme] = useTheme()
  const host = useRef<HTMLDivElement>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  const editor = useRef<monaco.editor.IStandaloneCodeEditor>()
  const [pv, setPv] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [conflict, setConflict] = useState(false)
  // dirty = conținutul diferă de ce s-a încărcat (versiunea „alternativă" a modelului Monaco:
  // undo până la original = din nou curat). Ref-ul e pentru handlerele care nu se re-creează
  // (Escape din capcana de focus, beforeunload, comanda Ctrl+S a lui Monaco).
  const [dirty, setDirty] = useState(false)
  const dirtyRef = useRef(false)
  const [confirmClose, setConfirmClose] = useState(false)
  const confirmRef = useRef(false)
  confirmRef.current = confirmClose
  const savingRef = useRef(false)

  // Orice cale de închidere (Escape, scrim, Close, ✕) trece pe aici: cu modificări nesalvate
  // cerem confirmare — un Escape în plus (reflex de VS Code după ce ai închis autocomplete-ul)
  // nu mai aruncă un config editat live pe server. Cât e deschisă confirmarea, Escape-ul de
  // document e al ei (ambele capcane îl prind — vezi FileBrowser pentru același pattern).
  const requestClose = () => {
    if (confirmRef.current) return
    if (dirtyRef.current) setConfirmClose(true)
    else props.onClose()
  }
  useFocusTrap(dialogRef, requestClose)   // Tab trap + Escape + restaurare focus

  // beforeunload: F5 / închiderea tab-ului cu text nesalvat → browserul întreabă. Doar cât e dirty,
  // ca să nu enervăm la navigare normală.
  useEffect(() => {
    if (!dirty) return
    const onUnload = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', onUnload)
    return () => window.removeEventListener('beforeunload', onUnload)
  }, [dirty])

  // Tema Monaco urmează tema aplicației (Aurora/macos = deschisă). setTheme e global pentru
  // toate instanțele, deci schimbarea din Settings se vede imediat, fără a re-crea editorul
  // (re-crearea ar pierde textul nesalvat) — de aceea tema inițială vine dintr-un ref.
  const monacoTheme = theme === 'macos' ? 'vs' : 'vs-dark'
  const themeRef = useRef(monacoTheme)
  themeRef.current = monacoTheme
  useEffect(() => { monaco.editor.setTheme(monacoTheme) }, [monacoTheme])

  // Stefan: utilizatorul trebuie NOTIFICAT activ când un fişier e prea mare ca să fie randat întreg,
  // nu doar printr-un badge discret. Toast-ul (o dată per deschidere) e dublat de bannerul din antet.
  const truncToastRef = useRef(false)
  useEffect(() => {
    let alive = true
    api<Preview>(`/api/hosts/${props.hostId}/fs/preview?path=${encodeURIComponent(props.path)}`)
      .then((p) => {
        if (!alive) return
        setPv(p)
        if (p.truncated && !truncToastRef.current) {
          truncToastRef.current = true
          notifyToast(t('files.bigFileToast', { name: props.name, size: fmtBytes(p.size) }), 'warn')
        }
      })
      .catch((e) => { if (alive) setError(errText(e, t) || t('files.readFail')) })
    return () => { alive = false }
  }, [props.hostId, props.path, props.name, t])

  const wrapLabel = useRef('')
  wrapLabel.current = t('files.toggleWrap')
  useEffect(() => {
    if (!pv || pv.binary || !host.current) return
    const firstLine = pv.text.slice(0, (pv.text.indexOf('\n') + 1) || 200)
    const ed = monaco.editor.create(host.current, {
      value: pv.text,
      language: detectLanguage(props.path, firstLine),
      theme: themeRef.current,        // vs / vs-dark după tema aplicației
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
    // Alt+Z ca în VS Code: încadrarea rândurilor lungi (loguri, config-uri cu linii lungi) —
    // apare şi în meniul de click-dreapta şi în paleta F1. Eticheta vine din ref: `t` în
    // dependenţe ar re-crea editorul (şi ar pierde textul nesalvat) la schimbarea limbii.
    let wrap = false
    ed.addAction({
      id: 'wt.toggleWordWrap',
      label: wrapLabel.current,
      keybindings: [monaco.KeyMod.Alt | monaco.KeyCode.KeyZ],
      contextMenuGroupId: '9_view',
      run: (e) => { wrap = !wrap; e.updateOptions({ wordWrap: wrap ? 'on' : 'off' }) },
    })
    // dirty față de versiunea încărcată; getAlternativeVersionId ignoră undo/redo care ajung
    // înapoi la același text, deci Ctrl+Z până la original stinge indicatorul.
    const model = ed.getModel()
    const cleanVersion = model?.getAlternativeVersionId() ?? 0
    const sub = ed.onDidChangeModelContent(() => {
      const d = (model?.getAlternativeVersionId() ?? 0) !== cleanVersion
      if (d !== dirtyRef.current) { dirtyRef.current = d; setDirty(d) }
    })
    return () => {
      sub.dispose()
      ed.getModel()?.dispose(); ed.dispose(); editor.current = undefined
      dirtyRef.current = false; setDirty(false)
    }
  }, [pv, props.path])

  async function save(force = false) {
    if (!pv || !editor.current || pv.binary || !pv.editable) return
    // nimic de salvat când e curat (Save e și dezactivat); „suprascrie oricum" trece mereu
    if (!force && !dirtyRef.current) return
    // gardă de reintrare: Ctrl+S ținut apăsat / dublu-click pe Save nu trimit două POST-uri
    if (savingRef.current) return
    savingRef.current = true
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
      if (res.status === 409) { setConflict(true); savingRef.current = false; setSaving(false); return }
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? t('files.saveFail'))
      // salvat = curat; altfel onClose-ul de mai jos ar cere confirmare de „renunțare"
      dirtyRef.current = false
      setDirty(false)
      props.onSaved()
      props.onClose()
    } catch (e) {
      setError(errText(e, t) || t('files.genericErr'))
      savingRef.current = false
      setSaving(false)
    }
  }

  // Ctrl/Cmd+S global (când focusul NU e în editor — ex. pe butoane). save() e no-op pe
  // fișiere view-only/binare sau curate, deci apelul e sigur oricând.
  // Listener-ul e pe window în fază de CAPTURE, deci rulează ÎNAINTEA serviciului de taste al
  // lui Monaco (care ascultă pe propriul nod DOM, în bubble, și face stopPropagation după ce
  // dispecerizează comanda din addCommand). Fără gardă, un Ctrl+S din editor salva de două ori:
  // o dată aici, o dată prin addCommand. Când ținta e în editor, lăsăm Monaco să fie singurul.
  const saveRef = useRef(save)
  saveRef.current = save
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || (e.key !== 's' && e.key !== 'S')) return
      if (host.current && e.target instanceof Node && host.current.contains(e.target)) return
      e.preventDefault()
      saveRef.current(false)
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [])

  return (
    // închidere la click DOAR pe scrim (target === currentTarget): confirmarea de mai jos e
    // randată în acest container, iar click-ul pe scrim-ul ei nu trebuie să redeschidă nimic
    <div className="wt-editor fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={(e) => { if (e.target === e.currentTarget) requestClose() }}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('files.editAria', { name: props.name })}
        className="glass flex h-[85dvh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-2">
          {/* punct „nesalvat" ca în VS Code — vizibil și pentru cititoare de ecran prin title/aria */}
          {dirty && (
            <span className="wt-accent shrink-0 text-base leading-none" title={t('files.unsaved')} aria-label={t('files.unsaved')} data-testid="editor-dirty">●</span>
          )}
          <span className="truncate font-mono text-xs text-slate-400">{props.path}</span>
          {pv?.truncated && (
            <span className="shrink-0 rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] wt-warn ring-1 ring-amber-500/25" title={t('files.bigFileTitle')}>
              {t('files.viewOnlyBadge')}
            </span>
          )}
          <div className="ml-auto flex shrink-0 gap-2">
            {pv && !pv.binary && pv.editable && (
              <button onClick={() => save(false)} disabled={saving || !dirty} className="rounded-lg bg-sky-600 px-3 py-1 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                {saving ? t('files.saving') : t('files.save')}
              </button>
            )}
            <button onClick={requestClose} className="rounded-lg px-3 py-1 text-sm text-slate-400 hover:bg-ink-800">{t('files.close')}</button>
          </div>
        </div>

        {/* Banner de fişier mare: badge-ul din antet e discret, iar Stefan vrea să fie EXPLICIT
            că vezi doar începutul, în citire. O linie cu dimensiunea reală (formaterul comun). */}
        {pv?.truncated && (
          <div role="status" data-testid="editor-bigfile-banner"
            className="flex items-center gap-2 border-b border-ink-800 bg-amber-500/10 px-4 py-1.5 text-xs wt-warn">
            {t('files.bigFileBanner', { size: fmtBytes(pv.size) })}
          </div>
        )}
        {/* `role="alert"` montat permanent: eroarea de salvare e anunţată, nu doar colorată
            (focusul rămâne în Monaco, unde nimic nu o semnalează) */}
        <div role="alert" className={error ? 'border-b border-ink-800 bg-ink-800 px-4 py-1.5 text-xs wt-danger' : 'sr-only'}>{error}</div>
        {conflict && (
          // alertdialog, nu banner mut: cere o decizie (suprascrie / renunţă) peste editări nesalvate
          <div role="alertdialog" aria-labelledby="editor-conflict-msg"
            className="flex items-center gap-3 border-b border-ink-800 bg-amber-500/10 px-4 py-2 text-xs">
            <span id="editor-conflict-msg" className="wt-warn">{t('files.conflictMsg')}</span>
            {/* amber-700, nu amber-600: alb pe amber-600 = 3,19:1 (sub AA); pe amber-700 = 4,7:1 */}
            <button onClick={() => { setConflict(false); save(true) }} className="rounded bg-amber-700 px-2 py-0.5 font-medium text-white hover:bg-amber-800">{t('files.overwriteAnyway')}</button>
            {/* focusul iniţial pe acţiunea SIGURĂ (APG alertdialog): un Enter din inerţie nu suprascrie */}
            <button autoFocus onClick={() => setConflict(false)} className="text-slate-400 hover:underline">{t('files.cancel')}</button>
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

      {/* confirmare de renunțare — în interiorul containerului z-[60], ca să stea deasupra
          dialogului (ConfirmModal e z-50 în propriul context de stivuire) */}
      {confirmClose && (
        <ConfirmModal
          title={t('files.discardTitle')}
          message={t('files.discardBody', { name: props.name })}
          confirmLabel={t('files.discardConfirm')}
          cancelLabel={t('files.keepEditing')}
          danger
          onCancel={() => setConfirmClose(false)}
          onConfirm={() => { setConfirmClose(false); props.onClose() }}
        />
      )}
    </div>
  )
}
