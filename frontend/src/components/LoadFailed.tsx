import { useI18n } from '../lib/i18n'

/* Starea „n-am putut încărca" — DISTINCTĂ de starea goală. Înainte, un fetch eşuat cădea pe
   `[]` şi panoul spunea „nimic aici", adică minţea: omul credea că n-are dispozitive/istoric/
   conexiuni. Aici spunem ce s-a întâmplat (mesajul serverului, dacă există) + Reîncearcă. */
export default function LoadFailed(props: { message?: string; onRetry: () => void; compact?: boolean }) {
  const { t } = useI18n()
  return (
    <div role="alert" className={`${props.compact ? 'p-3' : 'p-6'} text-center text-xs`}>
      <p className="wt-danger font-medium">{t('common.loadFailed')}</p>
      {props.message && <p className="mt-1 break-words text-slate-500">{props.message}</p>}
      <button type="button" onClick={props.onRetry}
        className="mt-2 rounded-md px-3 py-1 text-xs font-medium text-slate-200 ring-1 ring-ink-700 hover:bg-ink-800">
        {t('common.retry')}
      </button>
    </div>
  )
}
