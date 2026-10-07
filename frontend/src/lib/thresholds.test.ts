import { describe, expect, it } from 'vitest'
import { pressureColor, pressureLevel, pressureTextColor } from './thresholds'

describe('praguri de presiune (Sparkline + HostLoadRing + gauge-urile paginii de host)', () => {
  it('verde sub 70, chihlimbar 70–89, roşu de la 90', () => {
    expect(pressureLevel(0)).toBe('ok')
    expect(pressureLevel(69.9)).toBe('ok')
    expect(pressureLevel(70)).toBe('warn')
    expect(pressureLevel(89.9)).toBe('warn')
    expect(pressureLevel(90)).toBe('danger')
    expect(pressureLevel(100)).toBe('danger')
  })
  it('culorile sunt tokenii temei, nu hexuri (grafic vs. text)', () => {
    expect(pressureColor(10)).toBe('rgb(var(--viz-ok))')
    expect(pressureColor(75)).toBe('rgb(var(--viz-warn))')
    expect(pressureColor(95)).toBe('rgb(var(--viz-danger))')
    expect(pressureTextColor(95)).toBe('rgb(var(--danger))')
  })
})
