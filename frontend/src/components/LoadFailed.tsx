import { useI18n } from '../lib/i18n'
import { ErrorState } from './ui'

/* Starea „n-am putut încărca" — DISTINCTĂ de starea goală. Înainte, un fetch eşuat cădea pe
   `[]` şi panoul spunea „nimic aici", adică minţea: omul credea că n-are dispozitive/istoric/
   conexiuni. Aici spunem ce s-a întâmplat (mesajul serverului, dacă există) + Reîncearcă.
   Design system: e ErrorState (ui/) cu titlul „n-am putut încărca"; API-ul rămâne cel vechi. */
export default function LoadFailed(props: { message?: string; onRetry: () => void; compact?: boolean }) {
  const { t } = useI18n()
  return <ErrorState title={t('common.loadFailed')} message={props.message} onRetry={props.onRetry} compact={props.compact} />
}
