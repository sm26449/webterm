/* Contrastul fiecărei variante de temă (3.6.4), verificat STATIC din tokenii din index.css.

   axe (tests/ui_review.mjs) măsoară paginile randate, dar doar pe suprafeţele pe care le deschide;
   aici verificăm perechile pe care design system-ul le promite (docs/design/DESIGN-SYSTEM.md →
   Themes), pe TOATE variantele, la fiecare `vitest run`:
     - textul (tx-100…tx-600) şi culorile semantice de text (link/ok/warn/danger/info/accent)
       ≥ 4,5:1 pe ink-950 / ink-900 / ink-800 şi pe sticla sidebar-ului compusă peste fundal;
     - conturul câmpurilor, inelul de focus şi culorile de grafic ≥ 3:1 (WCAG 1.4.11);
     - alb pe butonul primar (sky-600) ≥ 4,5:1;
     - workspace-ul forţat întunecat: textul lui pe ws-950/900/800 şi pe paleta de comenzi,
       textul cromului pe tab strip / suprafaţa ridicată / fundalul terminalului;
     - editorul de fişiere (`.wt-editor`): textul şi UI-ul lui pe cardul `.glass` şi pe ink-800,
       în AMBELE contexte — din sesiune (.wt-workspace) şi de pe pagina hostului (.wt-canvas),
       unde axe nu vede `color-mix()` (audit 2026-10-17, UI-01);
     - inelul de focus şi conturul de câmp EFECTIVE în zonele forţat-întunecate (.wt-workspace,
       .wt-command, .wt-transfers-widget, .wt-editor) pe tab strip / ws-950 / paleta de comenzi, şi
       înapoi pe canvas-ul deschis al fiecărei variante (audit 2026-10-17, UI-02).
   Raport complet: VITE_CONTRAST_REPORT=1 npx vitest run src/themeContrast.test.ts */
import { describe, expect, it } from 'vitest'
import { FAMILIES, VARIANTS, type ThemeFamily, type ThemeVariant } from './lib/themeModel'

const raw = (import.meta.glob('./index.css', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['./index.css']
const css = raw.replace(/\/\*[\s\S]*?\*\//g, '')

type Tokens = Record<string, string>
/** tokenii din TOATE regulile al căror selector (întreg) trece testul; prima definiţie câştigă */
function tokens(test: (selector: string) => boolean): Tokens {
  const out: Tokens = {}
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!test(m[1].split(';').pop()!.trim().replace(/\s+/g, ' '))) continue
    for (const d of m[2].matchAll(/--([\w-]+):\s*([^;]+);/g)) if (!(d[1] in out)) out[d[1]] = d[2].trim()
  }
  return out
}

type RGB = [number, number, number, number?]
function rgb(v: string): RGB {
  const s = v.trim()
  let m = /^#([0-9a-f]{6})$/i.exec(s)
  if (m) return [0, 2, 4].map((i) => parseInt(m![1].slice(i, i + 2), 16)) as RGB
  m = /^rgba?\(([^)]*)\)$/.exec(s)
  if (m) return m[1].split(/[\s,/]+/).filter(Boolean).map(Number) as RGB
  const p = s.split(/\s+/).map(Number)
  if (p.length === 3 && p.every((x) => Number.isFinite(x))) return p as RGB
  throw new Error(`culoare necunoscută: ${v}`)
}
const over = (fg: RGB, bg: RGB): RGB =>
  fg[3] === undefined ? fg : [0, 1, 2].map((i) => fg[i]! * fg[3]! + bg[i]! * (1 - fg[3]!)) as RGB
const lin = (c: number) => { const x = c / 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4 }
const lum = (c: RGB) => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2])
const ratio = (a: RGB, b: RGB) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05) }
const pageColor = (gradient: string) => rgb([...gradient.matchAll(/#[0-9a-f]{6}/gi)].pop()![0])

const aurora = tokens((s) => s === ':root, :root[data-theme=\'macos\']')
const base = tokens((s) => s === ':root')
const variantTokens = (v: ThemeVariant): Tokens =>
  v === 'macos' ? aurora : { ...aurora, ...tokens((s) => s.split(',')[0].trim() === `:root[data-theme='${v}']`) }
const familyTokens = (f: ThemeFamily): Tokens =>
  f === 'webterm' ? base : { ...base, ...tokens((s) => s === `:root[data-family='${f}']`) }
const ws = tokens((s) => s === '.wt-workspace')

interface Pair { where: string; what: string; r: number; min: number }
const pairs: Pair[] = []
const need = (where: string, what: string, fg: RGB, bg: RGB, min: number) =>
  pairs.push({ where, what, r: ratio(fg, bg), min })

const TEXT = ['tx-100', 'tx-200', 'tx-300', 'tx-400', 'tx-500', 'tx-600', 'link', 'ok', 'warn', 'danger', 'info', 'accent']
const UI = ['field-border', 'focus', 'viz-ok', 'viz-warn', 'viz-danger']
for (const v of Object.keys(VARIANTS) as ThemeVariant[]) {
  const t = variantTokens(v)
  const surfaces: Record<string, RGB> = {
    'ink-950': rgb(t['ink-950']), 'ink-900': rgb(t['ink-900']), 'ink-800': rgb(t['ink-800']),
    'sidebar glass': over(rgb(t['glass-bg']), pageColor(t['app-gradient'])),
  }
  for (const [sn, s] of Object.entries(surfaces)) {
    for (const k of TEXT) need(v, `${k} on ${sn}`, rgb(t[k]), s, 4.5)
    if (sn !== 'sidebar glass') for (const k of UI) need(v, `${k} on ${sn}`, rgb(t[k]), s, 3)
  }
  need(v, 'white on sky-600', [255, 255, 255], rgb(familyTokens(VARIANTS[v].family)['sky-600']), 4.5)
}
for (const f of FAMILIES.map((x) => x.id)) {
  const t = familyTokens(f)
  const where = `workspace/${f}`
  for (const s of ['ws-950', 'ws-900', 'ws-800']) {
    for (const k of ['tx-100', 'tx-200', 'tx-300', 'tx-400', 'tx-500', 'tx-600', 'link']) need(where, `${k} on ${s}`, rgb(ws[k]), rgb(t[s]), 4.5)
  }
  for (const s of ['chrome-bg', 'chrome-elev', 'term-bg']) {
    for (const k of ['chrome-tx', 'chrome-tx-dim']) need(where, `${k} on ${s}`, rgb(t[k]), rgb(t[s]), 4.5)
  }
  need(where, 'tx-500 on command palette', rgb(ws['tx-500']), rgb(t['command-bg']), 4.5)
}

// Editorul de fişiere (`.wt-editor`, FileEditor.tsx) e o zonă forţat-întunecată care se deschide în DOUĂ
// contexte: din sesiune (în `.wt-workspace`, tokeni întunecaţi moşteniţi) şi din pagina hostului —
// tab-ul Files / AI tools — adică sub `.wt-canvas`, unde moşteneşte tokenii variantei DESCHISE.
// Auditul 2026-10-17 (UI-01): `.wt-editor` redeclara doar textul (deschis), nu şi suprafaţa, deci
// cardul `.glass` ieşea alb sub `.wt-canvas` şi textul din antet avea 1,16–1,22:1 pe toate cele
// 5 variante deschise. axe nu prinde cazul (`color-mix()` → „incomplete"), de aceea e verificat aici:
// tokenul EFECTIV = declaraţia zonei (cu `var(--ws-*)` rezolvat din familie), altfel moştenirea.
const editorZone = tokens((s) => s === '.wt-editor')
// Zonele forţat-întunecate îşi iau `--focus` / `--field-border` (+ color-scheme) dintr-o regulă COMUNĂ
// (`.wt-workspace, .wt-command, .wt-transfers-widget, .wt-editor`) şi din una per familie
// (`:root[data-family=…] :is(…)`): audit 2026-10-17, UI-02. Parserul le găseşte după lista de selectori.
const ZONES = ['.wt-workspace', '.wt-command', '.wt-transfers-widget', '.wt-editor']
const selList = (s: string) => s.split(',').map((x) => x.trim())
const zoneShared = tokens((s) => ZONES.every((z) => selList(s).includes(z)))
const zoneFamily = (f: ThemeFamily): Tokens =>
  f === 'webterm' ? {} : tokens((s) => s.startsWith(`:root[data-family='${f}']`) && ZONES.every((z) => s.includes(z)))
// blocul care readuce tokenii variantei pe canvas (dashboard / pagina hostului) — pentru Midnight nu există
const canvasTokens = (v: ThemeVariant): Tokens =>
  tokens((s) => selList(s).includes(`:root[data-theme='${v}'] .wt-workspace .wt-canvas`))
const resolveToken = (name: string, chain: Tokens[]): string => {
  for (const t of chain) {
    if (name in t) return t[name].replace(/var\(--([\w-]+)\)/g, (_, n: string) => resolveToken(n, chain))
  }
  throw new Error(`token lipsă: --${name}`)
}
const editorPairs: Pair[] = []
for (const v of Object.keys(VARIANTS) as ThemeVariant[]) {
  const vt = variantTokens(v)
  const ft = familyTokens(VARIANTS[v].family)
  const editorFamily = zoneFamily(VARIANTS[v].family)
  const contexts: Record<string, Tokens[]> = {
    'host page (canvas)': [editorFamily, editorZone, zoneShared, canvasTokens(v), vt, ft],
    'session (workspace)': [editorFamily, editorZone, zoneShared, ws, vt, ft],
  }
  for (const [ctx, chain] of Object.entries(contexts)) {
    const where = `editor/${v}/${ctx}`
    const eff = (k: string) => rgb(resolveToken(k, chain))
    // `.glass` = color-mix(ink-900 82 %, glass-bg), sticla compusă peste pagină (estimare
    // conservatoare: sub editor e şi scrim-ul negru 60 %, care întunecă şi mai mult)
    const glass = over(rgb(resolveToken('glass-bg', chain)), pageColor(vt['app-gradient']))
    const ink900 = eff('ink-900')
    const card = [0, 1, 2].map((i) => ink900[i]! * 0.82 + glass[i]! * 0.18) as RGB
    const surfaces: Record<string, RGB> = { 'editor card': card, 'ink-800': eff('ink-800') }
    for (const [sn, s] of Object.entries(surfaces)) {
      for (const k of TEXT) editorPairs.push({ where, what: `${k} on ${sn}`, r: ratio(eff(k), s), min: 4.5 })
      for (const k of ['field-border', 'focus']) editorPairs.push({ where, what: `${k} on ${sn}`, r: ratio(eff(k), s), min: 3 })
    }
  }
}

// Inelul de focus şi conturul de câmp în zonele forţat-întunecate (audit 2026-10-17, UI-02): până la
// 3.6.18 zonele redeclarau textul şi suprafeţele, dar `--focus` / `--field-border` rămâneau cele moştenite
// de pe :root — ale variantei DESCHISE — şi pe „Windows 11 · Light" albastrul Fluent dădea 2,92:1 pe tab
// strip (chrome-bg) şi ~2,9:1 pe paleta de comenzi. Perechile de aici erau verificate doar pe ink-* ale
// variantei. Verificăm tokenul EFECTIV: (1) în zonă — chrome-bg / chrome-elev / ws-950 / command-bg;
// (2) înapoi pe canvas-ul variantei, unde Aurora trebuie să-şi ia înapoi indigo-500 (indigo-400 pe alb
// ar da 2,98:1). Garda e `.wt-canvas` scris în lista de selectori a blocului variantei.
const zonePairs: Pair[] = []
for (const v of Object.keys(VARIANTS) as ThemeVariant[]) {
  const f = VARIANTS[v].family
  const vt = variantTokens(v)
  const ft = familyTokens(f)
  const zone = [zoneFamily(f), zoneShared, ws, vt, ft]
  const effZone = (k: string) => rgb(resolveToken(k, zone))
  for (const sn of ['chrome-bg', 'chrome-elev', 'ws-950', 'command-bg']) {
    zonePairs.push({ where: `zone/${v}`, what: `focus on ${sn}`, r: ratio(effZone('focus'), rgb(ft[sn])), min: 3 })
  }
  zonePairs.push({ where: `zone/${v}`, what: 'field-border on ws-800', r: ratio(effZone('field-border'), rgb(ft['ws-800'])), min: 3 })
  // canvas-ul (în .wt-workspace): declaraţiile blocului variantei pe .wt-canvas, altfel moştenirea din zonă
  const canvas = [canvasTokens(v), ...zone]
  const effCanvas = (k: string) => rgb(resolveToken(k, canvas))
  for (const sn of ['ink-950', 'ink-900', 'ink-800']) {
    for (const k of ['focus', 'field-border']) {
      zonePairs.push({ where: `canvas/${v}`, what: `${k} on ${sn}`, r: ratio(effCanvas(k), effCanvas(sn)), min: 3 })
    }
  }
}

// Numele hostului pe tab-ul activ e scris în culoarea hostului (paleta pastel din lib/host.ts) peste
// `color-mix(culoare 18%, --chrome-elev)` (TabBar). Paleta e calibrată pe cromul navy WebTerm, deci
// o familie nouă nu are voie să coboare sub cel mai slab contrast al WebTerm (prins de axe în gate).
const hostSrc = (import.meta.glob('./lib/host.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['./lib/host.ts']
const HOST_PALETTE = [...hostSrc.slice(hostSrc.indexOf('HOST_PALETTE'), hostSrc.indexOf(']', hostSrc.indexOf('HOST_PALETTE')))
  .matchAll(/'(#[0-9a-f]{6})'/gi)].map((m) => rgb(m[1]))
const tabWorst = (f: ThemeFamily) => {
  const elev = rgb(familyTokens(f)['chrome-elev'])
  return Math.min(...HOST_PALETTE.map((c) => ratio(c, [0, 1, 2].map((i) => c[i]! * 0.18 + elev[i]! * 0.82) as RGB)))
}

describe('audit 2026-10-17 — reguli globale din index.css (UI-03 / UI-04)', () => {
  it("UI-03: color-scheme urmează data-mode, zonele întunecate sunt `dark`, canvas-ul deschis `light`; scrollbar-ul din token", () => {
    expect(css).toMatch(/:root\[data-mode='dark'\]\s*\{[^}]*color-scheme:\s*dark/)
    expect(css).toMatch(/:root\[data-mode='light'\]\s*\{[^}]*color-scheme:\s*light/)
    const zoneRule = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].find((m) => ZONES.every((z) => selList(m[1].split(';').pop()!).includes(z)))
    expect(zoneRule?.[2]).toMatch(/color-scheme:\s*dark/)
    expect(zoneRule?.[2]).toMatch(/scrollbar-color:\s*var\(--scrollbar\)/)
    // tokenul stă lângă proprietate: paleta de comenzi şi widgetul Transfers sunt în afara
    // .wt-workspace şi altfel ar lua de pe :root thumb-ul închis al variantei deschise (review MED)
    expect(zoneRule?.[2]).toMatch(/--scrollbar:\s*rgba\(148, 163, 184/)
    expect(css).toMatch(/:root\[data-mode='light'\]\s*\.wt-canvas\s*\{[^}]*color-scheme:\s*light/)
    expect(css).toMatch(/\bhtml\s*\{[^}]*scrollbar-color:\s*var\(--scrollbar\)/)
  })
  it('UI-04: pe pointer grosier controalele de text au ≥ 16 px (max(16px, 1em)), fără checkbox/radio/range şi fără textarea-ul xterm', () => {
    const m = /@media \(pointer: coarse\)\s*\{\s*:is\(([\s\S]*?)\)\s*\{\s*font-size:\s*max\(16px, 1em\);/.exec(css)
    expect(m).not.toBeNull()
    const sel = m![1]
    for (const t of ['checkbox', 'radio', 'range', 'button', 'submit', 'file', 'hidden']) expect(sel).toContain(`:not([type='${t}'])`)
    expect(sel).toMatch(/textarea:not\(\.xterm-helper-textarea\)/)
    expect(sel).toMatch(/\bselect\b/)
  })
})

describe('contrastul variantelor de temă (tokeni din index.css)', () => {
  it('culorile de host pe tab-ul activ: nicio familie sub WebTerm', () => {
    expect(HOST_PALETTE.length).toBeGreaterThanOrEqual(10)
    const ref = tabWorst('webterm')
    const worse = FAMILIES.map((f) => f.id).filter((f) => tabWorst(f) + 1e-9 < ref)
      .map((f) => `${f}: ${tabWorst(f).toFixed(2)} < ${ref.toFixed(2)}`)
    expect(worse).toEqual([])
  })
  if (import.meta.env.VITE_CONTRAST_REPORT) {
    const worst = new Map<string, Pair>()
    for (const p of pairs) {
      const k = `${p.where} ${p.min}`
      if (!worst.has(k) || p.r < worst.get(k)!.r) worst.set(k, p)
    }
    console.log([...worst.values()].map((p) => `${p.where.padEnd(18)} ≥${p.min}:1  ${p.r.toFixed(2)}:1  ${p.what}`).join('\n'))
  }
  it('au fost găsiţi tokenii (parserul vede fiecare variantă şi familie)', () => {
    expect(pairs.length).toBeGreaterThan(600)
    expect(Object.keys(ws)).toContain('tx-500')
  })
  it('text ≥ 4,5:1, UI şi grafice ≥ 3:1, pe toate variantele şi în workspace', () => {
    const bad = pairs.filter((p) => p.r + 1e-9 < p.min).map((p) => `${p.where}: ${p.what} = ${p.r.toFixed(2)}:1 < ${p.min}:1`)
    expect(bad).toEqual([])
  })
  it('zonele forţat-întunecate: focus ≥ 3:1 pe tab strip / ws-950 / paleta de comenzi, şi înapoi pe canvas (UI-02)', () => {
    // regula comună există şi declară ambii tokeni (altfel lanţul ar cădea tăcut pe tokenii variantei)
    expect(Object.keys(zoneShared)).toEqual(expect.arrayContaining(['focus', 'field-border', 'scrollbar']))
    for (const f of ['mac', 'win', 'gnome', 'kde'] as ThemeFamily[]) expect(Object.keys(zoneFamily(f))).toContain('focus')
    expect(zonePairs.length).toBe(Object.keys(VARIANTS).length * (4 + 1 + 3 * 2))
    const bad = zonePairs.filter((p) => p.r + 1e-9 < p.min).map((p) => `${p.where}: ${p.what} = ${p.r.toFixed(2)}:1 < ${p.min}:1`)
    expect(bad).toEqual([])
  })
  it('editorul de fişiere: text ≥ 4,5:1 şi UI ≥ 3:1 pe cardul lui, din sesiune ŞI din pagina hostului (UI-01)', () => {
    expect(Object.keys(editorZone)).toContain('tx-400')
    expect(editorPairs.length).toBe(Object.keys(VARIANTS).length * 2 * 2 * (TEXT.length + 2))
    const bad = editorPairs.filter((p) => p.r + 1e-9 < p.min).map((p) => `${p.where}: ${p.what} = ${p.r.toFixed(2)}:1 < ${p.min}:1`)
    expect(bad).toEqual([])
  })
})
