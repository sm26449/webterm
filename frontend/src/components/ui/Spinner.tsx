/** Spinner mic (currentColor), decorativ: starea de încărcare o anunţă cine îl foloseşte
    (`aria-busy` pe Button, textul „Se încarcă…" etc.). Animaţia e oprită de regula globală
    `prefers-reduced-motion` din index.css. */
export function Spinner({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="shrink-0 animate-spin" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.5" opacity="0.25" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  )
}
