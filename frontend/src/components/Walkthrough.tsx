import { useEffect, useMemo, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { usePerms } from '../lib/perms'
import { useFocusTrap } from '../lib/useFocusTrap'
import {
  PERMS_WAIT_MS,
  type WalkStep,
  buildSteps,
  clampStep,
  markWalkthroughDone,
  shouldMarkDoneOnClose,
  stepOnArrow,
  waitForPerms,
} from '../lib/walkthrough'
import { Button } from './ui'

/* Walkthrough de primă rulare: un overlay clasic multi-pas (Next / Back / „Skip for now" /
   „Don't show again") cu titlu, descriere şi o ilustraţie SVG inline pe pas. Se deschide o
   dată la prima rulare (vezi shouldAutoOpen în lib/walkthrough.ts) şi se poate redeschide
   oricând din „?" sau din Setări. Modal real: role=dialog aria-modal, focus-trap, Escape.
   Vizual urmează ConfirmModal/KeyboardHelp (glass, scrim, rounded-2xl).
   Paşii vin din permisiunile contului (buildSteps, audit 2026-10-17 UI-06/FL-11): un Viewer nu
   mai primeşte „Add a host" şi uneltele unui terminal pe care nu-l poate deschide. */

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

// 2b. Hosturile vin de la administrator — aceleaşi carduri de server, fără „+": un ecuson de
// persoană (Owner/Admin) care le „trimite" spre listă. Folosită şi la finalul turului scurt
// al unui cont fără niciun host.
const HostsByAdminIllus = () => (
  <Illus>
    <rect x="96" y="44" width="110" height="30" rx="5" />
    <rect x="96" y="82" width="110" height="30" rx="5" />
    <path d="M110 59h.01M110 97h.01" />
    <path d="M132 59h44M132 97h44" strokeOpacity="0.5" />
    <g className="wt-accent">
      <circle cx="50" cy="62" r="10" />
      <path d="M32 96c0-10 8-18 18-18s18 8 18 18" />
      <path d="M72 78h16m0 0-6-6m6 6-6 6" />
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

// ilustraţia fiecărui pas, după IDENTITATE (nu poziţie): lista e filtrată după permisiuni
const ILLUS: Record<WalkStep['id'], React.ComponentType> = {
  welcome: WelcomeIllus,
  addHost: AddHostIllus,
  hostsByAdmin: HostsByAdminIllus,
  sessions: SessionsIllus,
  paste: PasteIllus,
  tools: ToolboxIllus,
  security: SecurityIllus,
  done: DoneIllus,
  noHosts: HostsByAdminIllus,
}

type Props = { auto: boolean; onClose: () => void }

/** Poarta de permisiuni (waitForPerms, lib): la AUTO-deschidere dialogul NU se montează până nu
    sosesc permisiunile sau expiră PERMS_WAIT_MS — altfel un Viewer vedea „Step 1 of 7" o clipă,
    apoi lista se scurta. E o componentă separată pentru că focus-trap-ul şi focusul iniţial se
    leagă la MONTAREA dialogului (useFocusTrap citeşte ref-ul o singură dată): un `return null`
    din interiorul dialogului le-ar fi lăsat fără nod. Redeschiderea manuală (auto=false) nu
    aşteaptă nimic — permisiunile sunt demult în memorie. */
export default function Walkthrough(props: Props) {
  const perms = usePerms()
  const [timedOut, setTimedOut] = useState(false)
  const waiting = waitForPerms(props.auto, perms, timedOut)
  useEffect(() => {
    if (!waiting) return
    const id = window.setTimeout(() => setTimedOut(true), PERMS_WAIT_MS)
    return () => window.clearTimeout(id)
  }, [waiting])
  if (waiting) return null
  return <WalkthroughDialog auto={props.auto} onClose={props.onClose} />
}

function WalkthroughDialog(props: Props) {
  const { t } = useI18n()
  const [step, setStep] = useState(0)
  const [dontShow, setDontShow] = useState(false)
  const dialogRef = useRef<HTMLDivElement>(null)
  const nextRef = useRef<HTMLButtonElement>(null)

  // Paşii contului: `null` (fetch eşuat / expirat după PERMS_WAIT_MS) = tur complet; dacă sosesc
  // după montare, lista se recalculează iar indexul e ţinut în interval de clampStep.
  const perms = usePerms()
  const steps = useMemo(() => buildSteps(perms), [perms])
  const total = steps.length
  // `idx` = indexul AFIŞAT, mereu în interval chiar dacă `step` a rămas dintr-o listă mai lungă
  const idx = clampStep(step, total)
  const cur = steps[idx]
  const isLast = idx === total - 1
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

  // Starea şi afişajul nu diverg: dacă lista s-a scurtat sub `step` (permisiunile au sosit după
  // ce ai avansat), readucem starea la indexul afişat — altfel tastele ar porni de la un index
  // fantomă (vezi stepOnArrow). Nu re-randează decât în acest caz rar.
  useEffect(() => {
    if (step !== idx) setStep(idx)
  }, [step, idx])

  // Refs citite din handlerul de taste montat o singură dată: aşa deps-urile efectului rămân
  // stabile (fără re-ataşări la fiecare pas) şi fără warning de exhaustive-deps. Ref-ul ţine
  // indexul AFIŞAT (clamp-uit), nu starea brută.
  const stepRef = useRef(idx); stepRef.current = idx
  const closeRef = useRef(close); closeRef.current = close

  // Focus iniţial pe butonul primar (Next/Gata): rulează DUPĂ efectul focus-trap-ului (ordinea
  // de declarare), deci câştigă — astfel Enter avansează din reflex, iar cititorul de ecran intră
  // în card. La fiecare schimbare de pas nu mutăm focusul (ar fi agresiv); anunţul vine din live.
  useEffect(() => {
    nextRef.current?.focus()
  }, [])

  // ←/→ navighează. Enter e lăsat activării butonului primar focusat (nu-l dublăm). Ascultătorul
  // e la nivel de document (nu pe div-ul cu rol non-interactiv): focusul e oricum capturat în modal.
  // Mutarea e calculată de stepOnArrow (lib, testată): clamp întâi, apoi ±1, ca butoanele.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0
      if (dir === 0) return
      e.preventDefault()
      const next = stepOnArrow(stepRef.current, total, dir)
      if (next === 'finish') closeRef.current('finish')
      else setStep(next)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [total])

  const Illustration = ILLUS[cur.id]

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
        // max-h + scroll propriu (U12): pe un ecran scund (320×568, telefon în landscape) cardul
        // ieşea din ecran şi butoanele de jos nu se mai vedeau
        className="glass wt-step-anim flex max-h-[calc(100dvh-2rem)] w-full max-w-md flex-col overflow-y-auto rounded-2xl p-5 sm:p-6"
      >
        {/* anunţ pentru cititoare de ecran: titlul pasului curent, la fiecare schimbare */}
        <div aria-live="polite" className="sr-only">{t(`${cur.key}.title`)}</div>

        {/* ilustraţia: decorativă, înălţime constantă ca înălţimea cardului să nu salte între paşi */}
        <div key={cur.id} className="wt-step-anim flex h-[168px] items-center justify-center">
          <Illustration />
        </div>

        <h2 id={titleId} className="mt-2 text-lg font-semibold leading-tight">
          {t(`${cur.key}.title`)}
        </h2>
        <p className="mt-2 min-h-[3.5rem] text-sm leading-relaxed text-slate-300">
          {t(`${cur.key}.body`)}
        </p>

        {/* progres: „Pasul 2 din 7" + o bară decorativă (U12). Erau 7 butoane-punct de 44px pe
            telefon — 308px de ţinte care nu încăpeau la 320px; navigarea rămâne Înapoi/Înainte şi ←/→. */}
        <div className="mt-4 flex items-center gap-3">
          <span data-testid="walkthrough-step" className="shrink-0 text-xs font-medium text-slate-400">
            {t('walkthrough.dotLabel', { k: idx + 1, n: total })}
          </span>
          <div aria-hidden="true" className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-ink-700">
            <div className="h-full rounded-full bg-sky-500 transition-[width]"
              style={{ width: `${((idx + 1) / total) * 100}%` }} />
          </div>
        </div>

        <label className="mt-4 flex cursor-pointer items-center gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={dontShow}
            onChange={(e) => setDontShow(e.target.checked)}
            className="h-4 w-4 rounded-md accent-sky-600 [@media(pointer:coarse)]:h-6 [@media(pointer:coarse)]:w-6"
          />
          <span>{t('walkthrough.dontShow')}</span>
        </label>

        {/* subsol adaptiv (U12): pe telefon Înapoi/Înainte pe un rând întreg, „Sari" dedesubt —
            trei butoane de 44px nu încăpeau pe un rând la 320px */}
        <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            onClick={() => close('skip')}
            className="wt-touch rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800 hover:text-slate-200"
          >
            {t('walkthrough.skip')}
          </button>
          <div className="flex items-center gap-2 [&>*]:flex-1 sm:[&>*]:flex-none">
            <button
              type="button"
              onClick={() => go(idx - 1)}
              disabled={idx === 0}
              className="wt-touch rounded-md px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-40"
            >
              {t('walkthrough.back')}
            </button>
            <Button variant="primary"
              ref={nextRef}
              type="button"
              onClick={() => (isLast ? close('finish') : go(idx + 1))} className="wt-touch">
              {isLast ? t('walkthrough.getStarted') : t('walkthrough.next')}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
