import { useI18n } from '../lib/i18n'
import { ArrowLeftIcon } from './Icons'

/** Antetul FIX al unui panou deschis ca foaie pe telefon (vezi lib/sheet.ts): „← Terminal"
    mare + titlul panoului. Foaia nu derulează (doar lista din ea), deci bara stă mereu sus.
    Antetul propriu al panoului (refresh, ✕, tab-uri) rămâne dedesubt, neschimbat — cu excepţia
    celor care n-au decât titlu + ✕ (Files, Forwards): acolo ar fi un duplicat şi îl ascundem. */
export default function SheetBar(props: { title: string; onBack: () => void }) {
  const { t } = useI18n()
  return (
    <div className="flex shrink-0 items-center gap-2 border-b border-ink-800 bg-ink-900 px-2 py-1">
      <button
        type="button"
        data-testid="sheet-back"
        onClick={props.onBack}
        aria-label={t('sheet.backAria')}
        className="wt-touch flex min-h-[40px] shrink-0 items-center gap-1.5 rounded-md px-2 text-sm font-medium wt-link hover:bg-ink-800"
      >
        <ArrowLeftIcon /> {t('sheet.back')}
      </button>
      <h2 className="min-w-0 flex-1 truncate text-right text-sm font-semibold text-slate-200">{props.title}</h2>
    </div>
  )
}
