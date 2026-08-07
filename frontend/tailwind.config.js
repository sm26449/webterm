/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        // același font ca terminalul → identitate de terminal în chrome.
        // Toate `font-mono` din UI (adrese, IP-uri, protocol, timestamp) cad
        // acum pe JetBrains Mono, nu pe Menlo/SFMono-ul de sistem.
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
      colors: {
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
