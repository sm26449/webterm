import { createContext, useCallback, useContext, useMemo, useRef, useState, ReactNode } from 'react'
import ConfirmModal from '../components/ConfirmModal'
import { useFocusTrap } from './useFocusTrap'
import { useI18n } from './i18n'

/* `window.confirm/prompt/alert` înlocuite cu dialoguri proprii, prin UN singur provider.
   De ce nu rămân cele native (auditul 2026-10, UI/UX + a11y):
     - arată diferit în fiecare browser, nu urmează tema, nu se pot traduce butoanele, iar pe
       mobil sunt o foaie de sistem fără context — în timp ce restul aplicaţiei are deja
       ConfirmModal (glass, focus-trap, Escape/backdrop);
     - un `confirm()` blochează TOATĂ pagina (inclusiv terminalele vii şi reconectările);
     - Chromium le suprimă după ce userul bifează „nu mai arăta" — şi atunci `confirm()`
       întoarce `false` în tăcere, deci acţiunea nu se mai poate face deloc;
     - cititoarele de ecran nu le pot reciti, iar `prompt()` nu poate avea etichetă/eroare.
   API: `const { confirm, promptText } = useConfirm()` → `if (!(await confirm({...}))) return`.
   Promisiunea se rezolvă cu `true/false` (confirm) sau `string | null` (prompt; null = anulat),
   exact semantica nativă — înlocuirea e mecanică. Un singur dialog deschis la un moment dat:
   al doilea apel aşteaptă (coadă), nu se suprapune. */

export type ConfirmOptions = {
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean          // acţiune distructivă: buton roşu, focusul iniţial pe Anulează
}
export type PromptOptions = {
  title: string
  message?: string
  label?: string            // eticheta câmpului (accesibilă); implicit = title
  defaultValue?: string
  placeholder?: string
  confirmLabel?: string
  cancelLabel?: string
  secret?: boolean          // type=password
  validate?: (v: string) => string | null   // mesaj de eroare sau null când e valid
}

type Ctx = {
  confirm: (o: ConfirmOptions) => Promise<boolean>
  promptText: (o: PromptOptions) => Promise<string | null>
}
const ConfirmCtx = createContext<Ctx | null>(null)

type Pending =
  | { kind: 'confirm'; o: ConfirmOptions; resolve: (v: boolean) => void }
  | { kind: 'prompt'; o: PromptOptions; resolve: (v: string | null) => void }

export function ConfirmProvider(props: { children: ReactNode }) {
  const [current, setCurrent] = useState<Pending | null>(null)
  const queue = useRef<Pending[]>([])

  const next = useCallback(() => {
    const n = queue.current.shift() ?? null
    setCurrent(n)
  }, [])
  const enqueue = useCallback((p: Pending) => {
    setCurrent((cur) => {
      if (cur) { queue.current.push(p); return cur }
      return p
    })
  }, [])

  const api = useMemo<Ctx>(() => ({
    confirm: (o) => new Promise<boolean>((resolve) => enqueue({ kind: 'confirm', o, resolve })),
    promptText: (o) => new Promise<string | null>((resolve) => enqueue({ kind: 'prompt', o, resolve })),
  }), [enqueue])

  // Ordinea contează: închidem ÎNTÂI dialogul şi rezolvăm promisiunea abia după ce React l-a
  // demontat (macrotask). Altfel continuarea `await confirm()` (microtask) rula ÎNAINTE de
  // unmount: apelantul muta focusul în terminal, apoi focus-trap-ul dialogului, la demontare,
  // îl întorcea pe butonul deschizător — şi tastele ajungeau în buton, nu în shell (prins de
  // e2e la „Enable shell integration"). Cu rezolvarea amânată, restaurarea focusului s-a
  // întâmplat deja când apelantul îşi face treaba, deci alegerea lui rămâne.
  const finish = (fn: () => void) => { next(); window.setTimeout(fn, 0) }

  return (
    <ConfirmCtx.Provider value={api}>
      {props.children}
      {current?.kind === 'confirm' && (
        <ConfirmModal
          title={current.o.title}
          message={current.o.message}
          confirmLabel={current.o.confirmLabel}
          cancelLabel={current.o.cancelLabel}
          danger={current.o.danger}
          onConfirm={() => finish(() => current.resolve(true))}
          onCancel={() => finish(() => current.resolve(false))}
        />
      )}
      {current?.kind === 'prompt' && (
        <PromptModal
          o={current.o}
          onSubmit={(v) => finish(() => current.resolve(v))}
          onCancel={() => finish(() => current.resolve(null))}
        />
      )}
    </ConfirmCtx.Provider>
  )
}

export function useConfirm(): Ctx {
  const ctx = useContext(ConfirmCtx)
  if (!ctx) {
    // Fără provider (teste izolate, pop-out fără App): cădem pe nativ, ca să nu blocăm acţiunea.
    return {
      confirm: async (o) => window.confirm(o.message),
      promptText: async (o) => window.prompt(o.message ?? o.title, o.defaultValue ?? ''),
    }
  }
  return ctx
}

function PromptModal(props: { o: PromptOptions; onSubmit: (v: string) => void; onCancel: () => void }) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onCancel)
  const [value, setValue] = useState(props.o.defaultValue ?? '')
  const [error, setError] = useState<string | null>(null)
  const submit = () => {
    const err = props.o.validate ? props.o.validate(value) : null
    if (err) { setError(err); return }
    props.onSubmit(value)
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onCancel}>
      <form
        ref={dialogRef as React.RefObject<HTMLFormElement & HTMLDivElement>}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wt-prompt-title"
        className="glass w-full max-w-sm rounded-2xl p-6"
        onClick={(e) => e.stopPropagation()}
        onSubmit={(e) => { e.preventDefault(); submit() }}
      >
        <h2 id="wt-prompt-title" className="text-lg font-semibold leading-tight">{props.o.title}</h2>
        {props.o.message && <p className="mt-2 text-sm leading-relaxed text-slate-300">{props.o.message}</p>}
        <label className="mt-4 block text-xs font-medium text-slate-400" htmlFor="wt-prompt-input">
          {props.o.label ?? props.o.title}
        </label>
        <input
          id="wt-prompt-input"
          autoFocus
          type={props.o.secret ? 'password' : 'text'}
          value={value}
          placeholder={props.o.placeholder}
          onChange={(e) => { setValue(e.target.value); if (error) setError(null) }}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? 'wt-prompt-error' : undefined}
          className="mt-1 w-full rounded-md border border-ink-700 bg-ink-900 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
        />
        {error && <p id="wt-prompt-error" role="alert" className="wt-danger mt-1 text-xs">{error}</p>}
        <div className="mt-6 flex justify-end gap-2">
          <button type="button" onClick={props.onCancel}
            className="rounded-md px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
            {props.o.cancelLabel ?? t('common.cancel')}
          </button>
          <button type="submit"
            className="rounded-md bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700">
            {props.o.confirmLabel ?? t('common.confirm')}
          </button>
        </div>
      </form>
    </div>
  )
}
