import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { keybarLayout, keybarRows, KeyDef, readKeybarExpanded, SHORT_VIEWPORT_QUERY, writeKeybarExpanded } from '../lib/keybar'
import { applyMods } from '../lib/keymods'
import { useMediaQuery } from '../lib/sheet'

/** Tastele extra pentru tastaturile tactile, pe DOUĂ rânduri: rândul 1 = ce-ţi trebuie mereu
    (Ctrl/Alt latch-uiţi, Esc, Tab, săgeţi), rândul 2 = restul (^C ^D ⇞ ⇟ | / - ~ Home/End/PgUp/PgDn
    ^Z ^R + lipire). Înainte era un singur rând derulant: tot ce era în dreapta lui PgDn nu-l
    descoperea nimeni. Pe viewport scund (telefon în peisaj) se strânge la rândul 1 + „⌄" — alegerea
    se ţine minte per dispozitiv (lib/keybar.ts).
    Apare pe orice dispozitiv cu pointer GROSIER (deget), indiferent de lăţime — era `md:hidden`,
    deci un iPad fără tastatură fizică rămânea fără Esc/Ctrl/săgeţi. Pe desktop (mouse) rămâne
    ascuns: vezi `.wt-keybar` în index.css. */
export default function MobileKeybar(props: {
  onKeys: (seq: string) => void
  onPaste: () => void
  backend?: string | null
}) {
  const { t } = useI18n()
  const [ctrl, setCtrl] = useState(false)
  const [alt, setAlt] = useState(false)
  const short = useMediaQuery(SHORT_VIEWPORT_QUERY)
  const [expanded, setExpanded] = useState(readKeybarExpanded)
  const layout = keybarLayout(short, expanded)
  // Publicăm înălţimea reală a keybar-ului în `--wt-keybar-h` (pe <html>), ca widgetul plutitor
  // de transferuri — portat în <body>, deci fără acces la acest DOM — să se aşeze DEASUPRA lui pe
  // mobil şi să nu acopere niciodată tastatura de comenzi. ResizeObserver: înălţimea variază cu
  // safe-area-inset, cu numărul de rânduri (1 ↔ 2) şi cu rotirea. La demontare (desktop / fără
  // sesiune vie) o resetăm → widgetul coboară la marginea de jos. Ascuns prin CSS (desktop) →
  // offsetHeight 0 → variabila e 0px. Terminalul se re-potriveşte singur: ResizeObserver-ul de pe
  // containerul lui (SessionView) vede înălţimea pierdută/câştigată → fit() + resize la PTY.
  const rootRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = rootRef.current
    if (!el) return
    const setVar = () => document.documentElement.style.setProperty('--wt-keybar-h', `${el.offsetHeight}px`)
    setVar()
    const ro = new ResizeObserver(setVar)
    ro.observe(el)
    return () => { ro.disconnect(); document.documentElement.style.removeProperty('--wt-keybar-h') }
  }, [])

  // rândul 2 derulează pe telefoane înguste: o umbră pe marginea dreaptă cât mai e ceva de văzut
  const row2Ref = useRef<HTMLDivElement>(null)
  const [moreRight, setMoreRight] = useState(false)
  useEffect(() => {
    const el = row2Ref.current
    if (!el) { setMoreRight(false); return }
    const upd = () => setMoreRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 2)
    upd()
    el.addEventListener('scroll', upd, { passive: true })
    const ro = new ResizeObserver(upd)
    ro.observe(el)
    return () => { el.removeEventListener('scroll', upd); ro.disconnect() }
  }, [layout.rows])

  const { row1, row2 } = keybarRows(props.backend)
  const ariaOf = (k: KeyDef) => {
    const base = k.aria.startsWith('keybar.') ? t(k.aria) : k.aria
    if (k.wheel || (!ctrl && !alt)) return base
    // cu un modificator aprins, eticheta spune ce se va trimite (Ctrl+Alt+<tastă>)
    const name = k.seq.length === 1 && k.seq >= '@' ? k.seq : base
    return `${ctrl ? 'Ctrl+' : ''}${alt ? 'Alt+' : ''}${name}`
  }
  // ţinte de 40px înălţime (nu `wt-touch`, care cere şi 44px LĂŢIME: 8 taste pe un ecran de 320px
  // n-ar mai încăpea pe rândul 1); lăţimea vine din flex-1 pe rândul 1, din padding pe rândul 2
  const keyCls = 'min-h-[40px] rounded-md bg-ink-800 px-2 text-xs text-slate-300 active:bg-ink-600'
  // modificator aprins = plin + inel, ca să se vadă dintr-o privire chiar în lumina zilei
  const modCls = (on: boolean) => `min-h-[40px] min-w-[44px] shrink-0 rounded-md px-2 text-xs font-medium ${
    on ? 'bg-sky-600 text-white ring-2 ring-sky-300' : 'bg-ink-800 text-slate-300'}`
  const press = (k: KeyDef) => {
    props.onKeys(k.wheel ? k.seq : applyMods(k.seq, ctrl, alt))
    // modificatorii se consumă la ORICE apăsare — altfel rămân aprinşi
    // după o tastă nemascabilă (Esc, săgeți) și lovesc pe neașteptate
    // următoarea apăsare de '|' sau '~'
    if (ctrl) setCtrl(false)
    if (alt) setAlt(false)
  }
  const keyBtn = (k: KeyDef, extra: string) => (
    <button
      key={k.label}
      aria-label={ariaOf(k)}
      className={`${keyCls} ${extra}`}
      onMouseDown={(e) => e.preventDefault()} // tastatura virtuală rămâne deschisă
      onClick={() => press(k)}
    >
      {k.label}
    </button>
  )

  return (
    <div ref={rootRef} data-testid="mobile-keybar" data-rows={layout.rows}
      className="wt-keybar flex-col gap-1 border-t border-ink-800 bg-ink-900 px-2 pb-[max(0.375rem,env(safe-area-inset-bottom))] pt-1.5">
      <div role="group" aria-label={t('keybar.essentials')} data-keybar-row="1" className="flex gap-1">
        <button
          className={modCls(ctrl)}
          onMouseDown={(e) => e.preventDefault()} // nu fura focusul terminalului
          onClick={() => setCtrl(!ctrl)}
          aria-pressed={ctrl}
          aria-label={t('keybar.ctrl')}
        >
          Ctrl
        </button>
        <button
          className={modCls(alt)}
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => setAlt(!alt)}
          aria-pressed={alt}
          aria-label={t('keybar.alt')}
        >
          Alt
        </button>
        {row1.map((k) => keyBtn(k, 'min-w-0 flex-1'))}
        {layout.toggle && (
          <button
            className="min-h-[40px] min-w-[44px] shrink-0 rounded-md bg-ink-800 px-2 text-xs text-slate-300 active:bg-ink-600"
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => { const v = !expanded; setExpanded(v); writeKeybarExpanded(v) }}
            aria-expanded={layout.rows === 2}
            aria-label={layout.rows === 2 ? t('keybar.collapse') : t('keybar.expand')}
            title={layout.rows === 2 ? t('keybar.collapse') : t('keybar.expand')}
          >
            <span aria-hidden="true">{layout.rows === 2 ? '⌄' : '⌃'}</span>
          </button>
        )}
      </div>
      {layout.rows === 2 && (
        <div className="relative">
          <div ref={row2Ref} role="group" aria-label={t('keybar.moreRow')} data-keybar-row="2"
            className="flex gap-1 overflow-x-auto [scrollbar-width:none]">
            {/* lipirea e aici, lângă degete — toolbar-ul de sus e departe când tastezi */}
            <button
              title={t('keybar.paste')}
              aria-label={t('keybar.paste')}
              className={`${keyCls} min-w-[44px] shrink-0`}
              onMouseDown={(e) => e.preventDefault()} // tastatura virtuală rămâne deschisă
              onClick={props.onPaste}
            >
              ⎘
            </button>
            {row2.map((k) => keyBtn(k, 'min-w-[44px] shrink-0 grow'))}
          </div>
          {moreRight && (
            <div aria-hidden="true"
              className="pointer-events-none absolute inset-y-0 right-0 w-8 bg-gradient-to-l from-ink-900 to-transparent" />
          )}
        </div>
      )}
    </div>
  )
}
