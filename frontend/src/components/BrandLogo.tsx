import { useI18n } from '../lib/i18n'
import { isLight, useTheme } from '../lib/theme'

/* Sigla EverShell (3.7.0) — SVG-urile din kitul de brand (docs/brand/cursor), copiate în public/.
   Varianta urmează modul efectiv al temei, ca restul cromului: literele crem pe suprafeţe închise
   (-dark), literele petrol pe suprafeţe deschise (-light). Ca <img>, nu inline: fişierul de brand
   rămâne singura sursă, iar CSP-ul permite deja imagini de pe aceeaşi origine. */
export default function BrandLogo(props: { className?: string }) {
  const { t } = useI18n()
  const [, theme] = useTheme()
  const src = isLight(theme) ? '/evershell-logo-light.svg' : '/evershell-logo-dark.svg'
  // raport 930×168 din viewBox: lăţimea vine din înălţime (h-*) şi w-auto
  return <img src={src} alt={t('brand.logoAlt')} width={930} height={168} className={props.className} draggable={false} />
}

/** Marca compactă (favicon-ul) pentru anteturi înguste: are fundal petrol propriu, deci aceeaşi
    pe orice temă. Decorativă (alt gol): numele e dat de textul sau eticheta de lângă ea. */
export function BrandMark(props: { size?: number }) {
  const size = props.size ?? 22
  return <img src="/favicon.svg" alt="" width={size} height={size} className="shrink-0" draggable={false} />
}
