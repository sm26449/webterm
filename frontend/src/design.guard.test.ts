/* Garda design system-ului (docs/design/DESIGN-SYSTEM.md, secţiunea „Guardrails").
   Rulează cu vitest (deci în CI şi în `npm run lint`) şi pică pe trei regresii:

   1. mărimi de text arbitrare `text-[Npx]` — sub 11px sunt interzise (text ilizibil), iar restul
      au o treaptă în scară (`text-2xs` … `text-3xl`, vezi tailwind.config.js);
   2. raze din afara scării: doar `rounded-md` (controale), `rounded-xl` (carduri), `rounded-2xl`
      (dialoguri), plus `rounded-full` (forme rotunde) şi `rounded-none`; tailwind.config le defineşte
      DOAR pe acestea, deci un `rounded-lg` nou n-ar genera nimic — tăcut;
   3. emoji / glife Unicode folosite ca pictograme în .tsx (text JSX şi string-uri): se randează diferit
      pe fiecare OS şi lipsesc pe unele Android-uri şi în Chromium headless. Pictogramele sunt în
      components/Icons.tsx. Conţinutul (textele traduse din lang/) nu e verificat aici.

   Excepţiile sunt în ALLOW, fiecare cu motiv. Se scanează doar string-urile (literali, template-uri,
   text JSX) — comentariile pot vorbi liber despre ✕ şi `text-[10px]`. */
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const files = import.meta.glob(['./**/*.ts', './**/*.tsx', '!./**/*.test.ts', '!./lang/**'], {
  query: '?raw', import: 'default', eager: true,
}) as Record<string, string>

/** excepţii deliberate: fişier → listă de {ce, de ce} */
const ALLOW: Record<string, { match: string; why: string }[]> = {
  './components/HostOverview.tsx': [
    { match: 'text-[9px]', why: 'miniatura de terminal din cardul de sesiune: o IMAGINE a ecranului (aria-hidden, în interiorul unui buton cu nume propriu), nu text de citit' },
  ],
  './components/CommandPalette.tsx': [
    { match: '↑', why: 'tastă: legenda de tastatură din subsolul paletei (<kbd>↑</kbd>)' },
    { match: '↓', why: 'tastă: legenda de tastatură din subsolul paletei (<kbd>↓</kbd>)' },
    { match: '↵', why: 'tastă: legenda de tastatură din subsolul paletei (<kbd>↵</kbd>)' },
  ],
  './components/KeyboardHelp.tsx': [
    { match: '←', why: 'tastă: combinaţia Alt+Shift+←/→ din lista de scurtături' },
    { match: '→', why: 'tastă: combinaţia Alt+Shift+←/→ din lista de scurtături' },
    { match: '↑', why: 'tastă: combinaţia Alt+↑/↓ din lista de scurtături' },
    { match: '↓', why: 'tastă: combinaţia Alt+↑/↓ din lista de scurtături' },
  ],
  './components/AboutModal.tsx': [
    { match: '©', why: 'conţinut: menţiunea de copyright („© 2026 …")' },
  ],
  './components/LoginPage.tsx': [
    { match: '©', why: 'conţinut: menţiunea de copyright din subsolul ecranului de login' },
  ],
  './components/settings/NotificationsTab.tsx': [
    { match: '→', why: 'notaţie DNS în text („*.domeniu → IP"), nu pictogramă' },
  ],
  './components/ForwardsPanel.tsx': [
    { match: '→', why: 'notaţie de redirecţionare în text („→ host:port · http"), nu pictogramă' },
  ],
  './components/AddHostModal.tsx': [
    { match: '•', why: 'placeholder de parolă („•••••••"), convenţia câmpurilor de secret' },
  ],
}

// glife-pictogramă care NU sunt „Extended_Pictographic" (dingbats, săgeţi-buton, forme geometrice)
const ICON_GLYPHS = '✕✓✗✎☰⌘⌨⏻⛶⇤⇅↻↰⎘⏎⎇❯▶■❚●○◆◧★☆⊘▸▾▲▼⌄⌃⏸↗↳⇄•'
// săgeţi şi liniuţe: tipografie în propoziţii („A → B"), pictograme când stau singure într-un nod
const STANDALONE = '←→↑↓–'
const PICTO = /\p{Extended_Pictographic}/u

type Hit = { file: string; line: number; text: string }

function strings(file: string, src: string): { text: string; jsx: boolean; line: number }[] {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
  const out: { text: string; jsx: boolean; line: number }[] = []
  const visit = (n: ts.Node) => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateHead(n)
        || ts.isTemplateMiddle(n) || ts.isTemplateTail(n) || ts.isJsxText(n)) {
      out.push({ text: n.text, jsx: ts.isJsxText(n), line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1 })
    }
    n.forEachChild(visit)
  }
  visit(sf)
  return out
}

const allowed = (file: string, what: string) => (ALLOW[file] ?? []).some((a) => a.match === what)

function scan() {
  const sizes: Hit[] = [], radii: Hit[] = [], glyphs: Hit[] = []
  for (const [file, src] of Object.entries(files)) {
    for (const s of strings(file, src)) {
      for (const m of s.text.matchAll(/(?<![\w-])text-\[(\d+(?:\.\d+)?)px\]/g)) {
        if (!allowed(file, m[0])) sizes.push({ file, line: s.line, text: m[0] })
      }
      for (const m of s.text.matchAll(/(?<![\w-[])rounded(?:-(?:t|r|b|l|s|e|tl|tr|bl|br|ss|se|es|ee))?(?:-([\w[\].]+))?(?![\w-])/g)) {
        if (!['md', 'xl', '2xl', 'full', 'none'].includes(m[1] ?? '')) radii.push({ file, line: s.line, text: m[0] })
      }
      if (!file.endsWith('.tsx')) continue
      const trimmed = s.text.trim()
      for (const ch of new Set(Array.from(s.text))) {
        const icon = PICTO.test(ch) || ICON_GLYPHS.includes(ch)
          || (STANDALONE.includes(ch) && /^[\s\d←→↑↓–]+$/u.test(trimmed))
        if (icon && !allowed(file, ch)) glyphs.push({ file, line: s.line, text: ch })
      }
    }
  }
  return { sizes, radii, glyphs }
}

const fmt = (h: Hit[]) => h.map((x) => `${x.file}:${x.line}  ${x.text}`).join('\n')

describe('design system: garda de regresie', () => {
  const r = scan()
  // inventar complet (pentru audit): VITE_DESIGN_REPORT=1 npx vitest run src/design.guard.test.ts
  if (import.meta.env.VITE_DESIGN_REPORT) {
    console.log(`DESIGN-REPORT sizes=${r.sizes.length} radii=${r.radii.length} glyphs=${r.glyphs.length}\n`
      + `${fmt(r.sizes)}\n---\n${fmt(r.radii)}\n---\n${fmt(r.glyphs)}`)
  }
  it('fără mărimi de text arbitrare text-[Npx] (minimul e text-2xs = 11px)', () => {
    expect(fmt(r.sizes)).toBe('')
  })
  it('razele sunt din scară: rounded-md · rounded-xl · rounded-2xl (+ full / none)', () => {
    expect(fmt(r.radii)).toBe('')
  })
  it('fără emoji/glife ca pictograme în .tsx (foloseşte components/Icons.tsx)', () => {
    expect(fmt(r.glyphs)).toBe('')
  })
})
