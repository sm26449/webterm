import { useI18n } from '../lib/i18n'

/** Sparkline SVG minimal (fără librărie): tendința ultimelor ~5 minute.
    Scala e FIXĂ 0-100% — un grafic auto-scalat ar face 3% CPU să arate ca o
    criză. Culoarea urmează valoarea curentă (verde/ambră/roșu), ca privirea să
    prindă starea înainte să citească cifra. */
export default function Sparkline(props: {
  values: number[]
  width?: number
  height?: number
  label: string
}) {
  const { t } = useI18n()
  const w = props.width ?? 56
  const h = props.height ?? 16
  const vals = props.values.slice(-60)
  if (vals.length < 2) {
    return <span className="inline-block" style={{ width: w, height: h }} aria-hidden="true" />
  }

  const last = vals[vals.length - 1]
  const color = last >= 90 ? '#f87171' : last >= 70 ? '#fbbf24' : '#34d399'
  const step = w / (vals.length - 1)
  const y = (v: number) => h - (Math.max(0, Math.min(100, v)) / 100) * (h - 2) - 1
  const line = vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
  const area = `${line} L${w},${h} L0,${h} Z`

  return (
    <svg
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      role="img"
      aria-label={t('sparkline.ariaLabel', { label: props.label, value: Math.round(last) })}
      className="shrink-0 overflow-visible"
    >
      <path d={area} fill={color} opacity={0.14} />
      <path d={line} fill="none" stroke={color} strokeWidth={1.25} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={w} cy={y(last)} r={1.6} fill={color} />
    </svg>
  )
}
