import { useEffect, useState } from 'react'
import { WatermarkConfig } from '../lib/api'
import { currentTheme } from '../lib/theme'
import { fmtTs } from '../lib/tz'

/** ${email} ${host} ${date} ${time} → text; time/date sunt „live" (refresh 60s). */
function resolveTemplate(tpl: string, vars: { email?: string; host?: string }): string {
  const now = new Date()
  const map: Record<string, string> = {
    email: vars.email ?? '',
    host: vars.host ?? '',
    date: fmtTs(now.getTime() / 1000, 'date'),
    time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }
  return tpl.replace(/\$\{(email|host|date|time)\}/g, (_, k) => map[k] ?? '')
}

/** Un singur tile canvas (text rotit) → dataURL; overlay-ul îl repetă pe tot viewportul. */
function makeTile(text: string, cfg: WatermarkConfig): string {
  const dpr = Math.min(2, window.devicePixelRatio || 1)   // claritate pe retina/mobil, plafonat
  const dark = currentTheme() === 'dark'
  const color = dark ? `rgba(255,255,255,${cfg.opacity})` : `rgba(15,23,42,${cfg.opacity})`
  const font = `${cfg.fontSize}px ui-sans-serif, system-ui, -apple-system, sans-serif`

  const meas = document.createElement('canvas').getContext('2d')
  if (!meas) return ''
  meas.font = font
  const textW = Math.ceil(meas.measureText(text).width)
  // tile suficient de mare cât să lase spațiu între repetări (aerisit, discret)
  const tileW = textW + 140
  const tileH = Math.max(120, cfg.fontSize * 9)

  const c = document.createElement('canvas')
  c.width = tileW * dpr
  c.height = tileH * dpr
  const ctx = c.getContext('2d')
  if (!ctx) return ''
  ctx.scale(dpr, dpr)
  ctx.font = font
  ctx.fillStyle = color
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.translate(tileW / 2, tileH / 2)
  ctx.rotate((cfg.angle * Math.PI) / 180)
  ctx.fillText(text, 0, 0)
  return c.toDataURL('image/png')
}

/**
 * Overlay de identitate pentru trasabilitatea scurgerilor (foto/screenshot).
 * Strat DOM separat DEASUPRA conținutului, dar `pointer-events:none` — nu blochează
 * niciodată selecția/scroll/click din terminal și nu atinge canvas-ul WebGL.
 * `email`/`host` vin din props (workspace: contul + host-ul activ; shared: pre-rezolvate
 * server-side, deci props goale). Pe boot/login nu se montează (fără date sensibile).
 */
export default function Watermark(props: {
  config?: WatermarkConfig | null
  email?: string | null
  host?: string | null
}) {
  const { config } = props
  const [url, setUrl] = useState('')

  useEffect(() => {
    if (!config?.enabled || !config.content) {
      setUrl('')
      return
    }
    const draw = () => {
      const text = resolveTemplate(config.content, {
        email: props.email ?? undefined,
        host: props.host ?? undefined,
      })
      setUrl(text.trim() ? makeTile(text, config) : '')
    }
    draw()
    const timer = window.setInterval(draw, 60_000)   // ${time} la zi (la minut)
    return () => clearInterval(timer)
  }, [config, props.email, props.host])

  if (!url) return null
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-[100] select-none"
      style={{ backgroundImage: `url(${url})`, backgroundRepeat: 'repeat' }}
    />
  )
}
