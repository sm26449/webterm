import { useI18n } from '../lib/i18n'
import { pressureColor } from '../lib/thresholds'

/** Sparkline SVG minimal (fără librărie): tendința ultimelor ~5 minute.
    Scala e FIXĂ 0-100% — un grafic auto-scalat ar face 3% CPU să arate ca o
    criză. Culoarea urmează valoarea curentă (verde/ambră/roșu), ca privirea să
    prindă starea înainte să citească cifra. */
export default function Sparkline(props: {
  values: number[]
  width?: number
  height?: number
  label: string
  /** întinde-te pe toată lăţimea containerului (tile de metrică), păstrând coordonatele logice */
  fluid?: boolean
}) {
  const { t } = useI18n()
  const w = props.width ?? 56
  const h = props.height ?? 16
  const vals = props.values.slice(-60)
  if (vals.length < 2) {
    return <span className={props.fluid ? 'block w-full' : 'inline-block'} style={{ height: h, width: props.fluid ? undefined : w }} aria-hidden="true" />
  }

  const last = vals[vals.length - 1]
  const color = pressureColor(last)   // lib/thresholds: aceleaşi praguri ca HostLoadRing şi gauge-urile
  const step = w / (vals.length - 1)
  const y = (v: number) => h - (Math.max(0, Math.min(100, v)) / 100) * (h - 2) - 1
  const line = vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
  const area = `${line} L${w},${h} L0,${h} Z`

  return (
    <svg
      width={props.fluid ? '100%' : w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio={props.fluid ? 'none' : undefined}
      role="img"
      aria-label={t('sparkline.ariaLabel', { label: props.label, value: Math.round(last) })}
      className={props.fluid ? 'block w-full overflow-visible' : 'shrink-0 overflow-visible'}
    >
      <path d={area} style={{ fill: color }} opacity={0.14} />
      <path d={line} fill="none" style={{ stroke: color }} strokeWidth={1.25} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={w} cy={y(last)} r={1.6} style={{ fill: color }} />
    </svg>
  )
}
