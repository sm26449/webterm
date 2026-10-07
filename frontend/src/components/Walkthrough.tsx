import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import {
  TOTAL_STEPS,
  clampStep,
  markWalkthroughDone,
  shouldMarkDoneOnClose,
} from '../lib/walkthrough'
import { Button } from './ui'

/* Walkthrough de primă rulare: un overlay clasic multi-pas (Next / Back / „Skip for now" /
   „Don't show again") cu titlu, descriere şi o ilustraţie SVG inline pe pas. Se deschide o
   dată la prima rulare (vezi shouldAutoOpen în lib/walkthrough.ts) şi se poate redeschide
   oricând din „?" sau din Setări. Modal real: role=dialog aria-modal, focus-trap, Escape.
   Vizual urmează ConfirmModal/KeyboardHelp (glass, scrim, rounded-2xl). */

// Ilustraţiile sunt LINE-ART inline, nu bitmap/screenshot: scalează curat, se adaptează
// la temă prin `currentColor` (moştenit din culoarea textului) + tokenul de accent `.wt-accent`,
// şi sunt DECORATIVE (aria-hidden) — sensul e în text, ca a11y-ul să nu depindă de ele.
function Illus({ children }: { children: React.ReactNode }) {
  return (
    <svg
      viewBox="0 0 240 150"
      className="h-[160px] w-auto text-slate-400"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

// 1. Welcome — o fereastră de terminal cu prompt şi cursor.
const WelcomeIllus = () => (
  <Illus>
    <rect x="40" y="28" width="160" height="96" rx="8" />
    <path d="M40 48h160" />
    <circle cx="54" cy="38" r="3" />
    <circle cx="66" cy="38" r="3" />
    <circle cx="78" cy="38" r="3" />
    <g className="wt-accent">
      <path d="M60 72l16 14-16 14" />
      <path d="M88 100h40" />
    </g>
  </Illus>
)

// 2. Add a host — un card de server cu un „+".
const AddHostIllus = () => (
  <Illus>
    <rect x="34" y="44" width="110" height="30" rx="5" />
    <rect x="34" y="82" width="110" height="30" rx="5" />
    <path d="M48 59h.01M48 97h.01" />
    <path d="M70 59h44M70 97h44" strokeOpacity="0.5" />
    <g className="wt-accent">
      <circle cx="178" cy="78" r="22" />
      <path d="M178 68v20M168 78h20" />
    </g>
  </Illus>
)

// 3. Sessions & terminal — taburi + panouri în split.
const SessionsIllus = () => (
  <Illus>
    <path d="M44 40h34v14H44z" />
    <path d="M82 40h34v14H82z" strokeOpacity="0.5" />
    <path d="M120 40h34v14h-34z" strokeOpacity="0.5" />
    <rect x="44" y="58" width="152" height="60" rx="6" />
    <path d="M120 58v60" />
    <g className="wt-accent">
      <path d="M56 74h40M56 86h26M56 98h34" />
    </g>
    <path d="M134 74h48M134 86h40M134 98h48" strokeOpacity="0.5" />
  </Illus>
)

// 4. Paste / drag & drop — clipboard → fişier → calea inserată la prompt.
const PasteIllus = () => (
  <Illus>
    <rect x="30" y="46" width="48" height="58" rx="6" />
    <path d="M44 46a8 8 0 0 1 16 0" />
    <path d="M40 66h28M40 78h28M40 90h18" strokeOpacity="0.5" />
    <g className="wt-accent">
      <path d="M86 75h34m0 0-8-8m8 8-8 8" />
    </g>
    <rect x="128" y="46" width="48" height="58" rx="6" />
    <path d="M162 46l14 14h-14z" />
    <path d="M188 118h28" className="wt-accent" />
    <path d="M30 118h150" strokeOpacity="0.4" />
  </Illus>
)

// 5. Toolbox — o cheie fixă peste o bară de unelte.
const ToolboxIllus = () => (
  <Illus>
    <rect x="44" y="40" width="152" height="24" rx="6" />
    <path d="M62 52h.01M82 52h.01M102 52h.01M122 52h.01" strokeOpacity="0.5" />
    <g className="wt-accent">
      <path d="M150 86a16 16 0 1 1-18-18l-28 28 8 8 28-28a16 16 0 0 1 10 10z" />
    </g>
  </Illus>
)

// 6. Security — scut cu gaură de cheie (2FA step-up).
const SecurityIllus = () => (
  <Illus>
    <path d="M120 30l44 18v26c0 28-18 46-44 56-26-10-44-28-44-56V48z" />
    <g className="wt-accent">
      <circle cx="120" cy="76" r="9" />
      <path d="M120 85v16" />
    </g>
  </Illus>
)

// 7. You're set — bifă într-un cerc.
const DoneIllus = () => (
  <Illus>
    <circle cx="120" cy="76" r="44" strokeOpacity="0.5" />
    <g className="wt-accent">
      <path d="M100 76l14 14 28-32" />
    </g>
  </Illus>
)

const STEPS = [
  WelcomeIllus,
  AddHostIllus,
  SessionsIllus,
  PasteIllus,
  ToolboxIllus,
  SecurityIllus,
  DoneIllus,
] as const

export default function Walkthrough(props: { auto: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const [step, setStep] = useState(0)
  const [dontShow, setDontShow] = useState(false)
  const dialogRef = useRef<HTMLDivElement>(null)
  const nextRef = useRef<HTMLButtonElement>(null)

  const total = TOTAL_STEPS
  const isLast = step === total - 1
  const titleId = 'wt-walk-title'

  // Închiderea decide marcajul „gata" printr-o regulă pură (lib/walkthrough.ts), ca să fie
  // identică pe toate căile şi testabilă. `skip` NU închide turul definitiv (reapare), decât
  // dacă e bifat „nu mai arăta".
  const close = (reason: 'finish' | 'skip') => {
    if (shouldMarkDoneOnClose({ auto: props.auto, reason, dontShowAgain: dontShow })) {
      markWalkthroughDone()
    }
    props.onClose()
  }

  // Escape = „Skip for now" (nu finalizare): e o ieşire, nu o parcurgere completă. Focus-trap-ul
  // tratează Escape + Tab-wrap + restaurarea focusului pe deschizător la demontare.
  useFocusTrap(dialogRef, () => close('skip'))

  const go = (to: number) => setStep(clampStep(to, total))

  // Refs citite din handlerul de taste montat o singură dată: aşa deps-urile efectului rămân
  // stabile (fără re-ataşări la fiecare pas) şi fără warning de exhaustive-deps.
  const stepRef = useRef(step); stepRef.current = step
  const closeRef = useRef(close); closeRef.current = close

  // Focus iniţial pe butonul primar (Next/Gata): rulează DUPĂ efectul focus-trap-ului (ordinea
  // de declarare), deci câştigă — astfel Enter avansează din reflex, iar cititorul de ecran intră
  // în card. La fiecare schimbare de pas nu mutăm focusul (ar fi agresiv); anunţul vine din live.
  useEffect(() => {
    nextRef.current?.focus()
  }, [])

  // ←/→ navighează. Enter e lăsat activării butonului primar focusat (nu-l dublăm). Ascultătorul
  // e la nivel de document (nu pe div-ul cu rol non-interactiv): focusul e oricum capturat în modal.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight') {
        e.preventDefault()
        if (stepRef.current >= total - 1) closeRef.current('finish')
        else setStep((s) => clampStep(s + 1, total))
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault()
        setStep((s) => clampStep(s - 1, total))
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [total])

  const Illustration = STEPS[clampStep(step, total)]

  // scrim: `role="presentation"` + închidere DOAR la clic pe el însuşi (nu pe card) — acelaşi tipar
  // ca wizard-ul de split din App, care evită avertismentele jsx-a11y fără onClick pe dialog.
  return (
    <div
      role="presentation"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) close('skip') }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="walkthrough"
        className="glass wt-step-anim flex w-full max-w-md flex-col rounded-2xl p-6"
      >
        {/* anunţ pentru cititoare de ecran: titlul pasului curent, la fiecare schimbare */}
        <div aria-live="polite" className="sr-only">{t(`walkthrough.step${step + 1}.title`)}</div>

        {/* ilustraţia: decorativă, înălţime constantă ca înălţimea cardului să nu salte între paşi */}
        <div key={step} className="wt-step-anim flex h-[168px] items-center justify-center">
          <Illustration />
        </div>

        <h2 id={titleId} className="mt-2 text-lg font-semibold leading-tight">
          {t(`walkthrough.step${step + 1}.title`)}
        </h2>
        <p className="mt-2 min-h-[3.5rem] text-sm leading-relaxed text-slate-300">
          {t(`walkthrough.step${step + 1}.body`)}
        </p>

        {/* dots de progres: butoane reale (jump la pas), cu aria-label „Step k of N" */}
        <div className="mt-4 flex items-center justify-center gap-2" role="group" aria-label={t('walkthrough.progress')}>
          {Array.from({ length: total }, (_, i) => (
            <button
              key={i}
              type="button"
              onClick={() => go(i)}
              aria-current={i === step ? 'step' : undefined}
              aria-label={t('walkthrough.dotLabel', { k: i + 1, n: total })}
              className={`wt-touch grid place-items-center rounded-full p-2 ${
                i === step ? 'wt-accent' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <span className={`block h-2 w-2 rounded-full ${i === step ? 'bg-current' : 'bg-current opacity-40'}`} />
            </button>
          ))}
        </div>

        <label className="mt-4 flex cursor-pointer items-center gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={dontShow}
            onChange={(e) => setDontShow(e.target.checked)}
            className="h-4 w-4 rounded-md accent-sky-600"
          />
          <span>{t('walkthrough.dontShow')}</span>
        </label>

        <div className="mt-5 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => close('skip')}
            className="wt-touch rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800 hover:text-slate-200"
          >
            {t('walkthrough.skip')}
          </button>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => go(step - 1)}
              disabled={step === 0}
              className="wt-touch rounded-md px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40"
            >
              {t('walkthrough.back')}
            </button>
            <Button variant="primary"
              ref={nextRef}
              type="button"
              onClick={() => (isLast ? close('finish') : go(step + 1))} className="wt-touch">
              {isLast ? t('walkthrough.getStarted') : t('walkthrough.next')}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
