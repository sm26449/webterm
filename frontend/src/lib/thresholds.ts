/* Praguri de presiune pentru metrici procentuale (CPU, memorie, disc): verde <70 % · chihlimbar
   <90 % · roşu de la 90 % în sus. O SINGURĂ sursă: înainte, Sparkline.tsx, HostLoadRing.tsx şi
   HostOverview.tsx îşi defineau fiecare pragurile, cu DOUĂ seturi de hexuri pentru acelaşi semnal
   (gauge-ul CPU verde-smarald #10b981, sparkline-ul de sub el verde-mentă #34d399).

   Culorile nu sunt hexuri, ci tokenii temei (index.css): `--viz-*` pentru grafică (arce, linii,
   arii — ţinta WCAG 1.4.11 e 3:1) şi `--ok/--warn/--danger` pentru TEXT colorat (cifra din centrul
   gauge-ului — ţinta 1.4.3 e 4,5:1). Pe tema închisă cele două seturi coincid; pe cea deschisă
   textul ia nuanţa mai închisă. Valorile sunt `rgb(var(--…))`, deci merg în `style={{ stroke }}`,
   NU în atributele de prezentare SVG (`stroke="…"` nu rezolvă `var()`). */

export type Pressure = 'ok' | 'warn' | 'danger'

export const PRESSURE_WARN = 70
export const PRESSURE_DANGER = 90

export function pressureLevel(pct: number): Pressure {
  return pct >= PRESSURE_DANGER ? 'danger' : pct >= PRESSURE_WARN ? 'warn' : 'ok'
}

/** culoarea de grafic (stroke/fill) pentru un procent */
export function pressureColor(pct: number): string {
  return `rgb(var(--viz-${pressureLevel(pct)}))`
}

/** culoarea de TEXT (AA) pentru un procent — cifra afişată lângă/în grafic */
export function pressureTextColor(pct: number): string {
  return `rgb(var(--${pressureLevel(pct)}))`
}
