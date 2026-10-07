/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    // ── Raze: TREI trepte (+ `full` pentru forme rotunde: buline, pilule, avatare) ─────────
    //   md  6px  — controale: butoane, câmpuri, chip-uri, badge-uri, itemi de meniu
    //   xl  12px — carduri, popover-e, meniuri, panouri
    //   2xl 16px — dialoguri/modale, foi, cardul de login
    // Scara ÎNLOCUIEŞTE pe cea Tailwind (nu o extinde): `rounded`, `rounded-sm`, `rounded-lg`,
    // `rounded-3xl` nu mai generează nimic. Garda (src/design.guard.test.ts) le prinde înainte.
    borderRadius: {
      none: '0',
      md: '6px',
      xl: '12px',
      '2xl': '16px',
      full: '9999px',
    },
    // ── Scara tipografică (design system 3.5.7, docs/design/DESIGN-SYSTEM.md) ───────────────
    // `text-2xs` (11px) e CEA MAI MICĂ mărime permisă pentru text: HIG cere ≥11pt, iar sub 11px
    // CSS etichetele devin ilizibile pe ecrane 1×. `compact` (13px) e treapta dintre xs şi sm,
    // folosită de rândurile dense, proza din modale şi liniile de comandă monospace. Mărimile
    // arbitrare `text-[Npx]` sunt interzise de garda din src/design.guard.test.ts (vitest).
    fontSize: {
      '2xs': ['11px', { lineHeight: '16px' }],
      xs: ['12px', { lineHeight: '16px' }],
      compact: ['13px', { lineHeight: '20px' }],
      sm: ['14px', { lineHeight: '20px' }],
      base: ['16px', { lineHeight: '24px' }],
      lg: ['18px', { lineHeight: '28px' }],
      xl: ['20px', { lineHeight: '28px' }],
      display: ['22px', { lineHeight: '28px' }],   // titlul de pe ecranul de login
      '2xl': ['24px', { lineHeight: '32px' }],
      '3xl': ['30px', { lineHeight: '36px' }],
      hero: ['60px', { lineHeight: '1' }],          // cifra „403" de pe pagina de share revocat
    },
    extend: {
      fontFamily: {
        // același font ca terminalul → identitate de terminal în chrome.
        // Toate `font-mono` din UI (adrese, IP-uri, protocol, timestamp) cad
        // acum pe JetBrains Mono, nu pe Menlo/SFMono-ul de sistem.
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
      colors: {
        // ── Tokeni semantici (variabile CSS în index.css, valori pentru AMBELE teme) ──────────
        // Starea: ok / warn / danger / info / accent. Sunt aceleaşi culori ca .wt-good/.wt-warn/
        // .wt-danger/.wt-info/.wt-accent (clasele acelea citesc acum tot variabilele astea), deci
        // `text-ok` ≡ `wt-good`. Trec AA (4,5:1) pe suprafeţele temei în care sunt definite.
        ok: v('ok'),
        warn: v('warn'),
        danger: v('danger'),
        info: v('info'),
        accent: v('accent'),
        // = .wt-link (indigo AA pe ambele teme); pentru hover-uri: `hover:text-link`
        link: v('link'),
        // culorile de grafic (gauge, sparkline, inel de încărcare): ţintă WCAG 1.4.11 = 3:1
        viz: { ok: v('viz-ok'), warn: v('viz-warn'), danger: v('viz-danger') },
        // suprafeţe: nume semantice peste aceeaşi scară `ink` (tema o redefineşte, iar zonele
        // forţat-întunecate — terminalul — o suprascriu local, deci aliasurile urmează automat)
        surface: {
          sunken: v('ink-950'),
          DEFAULT: v('ink-900'),
          raised: v('ink-800'),
          line: v('ink-700'),
          strong: v('ink-600'),
        },
        // paletele de suprafețe și text sunt variabile CSS ca temele
        // (dark / macos) să fie simple suprascrieri în index.css
        ink: {
          950: v('ink-950'),
          900: v('ink-900'),
          800: v('ink-800'),
          700: v('ink-700'),
          600: v('ink-600'),
        },
        slate: {
          100: v('tx-100'),
          200: v('tx-200'),
          300: v('tx-300'),
          400: v('tx-400'),
          500: v('tx-500'),
          600: v('tx-600'),
        },
        // accent WebTerm: indigo electric — legat de violetul din logo/badge,
        // mai distinctiv decât albastrul de sistem. Numele `sky` rămâne (îl
        // folosesc sute de clase), doar valorile trec pe indigo.
        sky: {
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5', // alb pe el trece WCAG AA (~6.6:1)
          700: '#4338ca',
          800: '#312e81',
          900: '#1e1b4b',
          950: '#171449',
        },
      },
    },
  },
  plugins: [],
}
