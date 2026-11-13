/* Textul terminalului pentru modul „Selectează text" (3.6.32) — pur, testat în seltext.test.ts.

   xterm.js nu are selecţie pe TOUCH: degetul derulează, apăsarea lungă deschide meniul, deci pe
   telefon nu puteai copia o bucată de output (doar „Selectează tot"). Modul de selecţie arată
   acelaşi text ca text NATIV al browserului (mânerele de selecţie ale sistemului), iar aici îl
   pregătim: rândurile FIZICE devin linii LOGICE.

   De ce linii logice: o comandă lungă, ruptă pe 3 rânduri de ecran, trebuie să se copieze ca O
   linie. Un newline strecurat în mijlocul ei ar face ca, lipită în alt terminal, prima bucată să
   se EXECUTE singură. Un rând continuă în următorul când:
     · următorul e `wrapped` (soft-wrap-ul xterm, sigur), sau
     · rândul ajunge până în ultima celulă (`full`) — sub tmux rândurile continuate sunt repictate
       explicit, fără isWrapped (aceeaşi regulă ca în lib/commands.ts).
   La îndoială UNIM: o unire greşită dă un text fără un newline (vizibil, inofensiv la lipire), o
   rupere greşită dă o comandă pe jumătate executată. Nu tăiem nimic din interiorul liniei
   (indentarea contează în YAML/Python); doar spaţiile de la coada liniei logice. */

export interface SelRow {
  /** textul rândului, NEtăiat la coadă (translateToString(false)) */
  text: string
  /** rândul e continuarea (soft-wrap) celui dinainte */
  wrapped: boolean
  /** rândul ajunge până în ultima celulă a terminalului */
  full: boolean
}

/** Rânduri fizice → linii logice. Liniile goale din interior se păstrează (paragrafe); cele de la
    început şi de la sfârşit (ecranul gol de sub prompt) se taie. */
export function logicalLines(rows: readonly SelRow[]): string[] {
  const out: string[] = []
  let cur: string | null = null
  let prevFull = false
  for (const r of rows) {
    if (cur !== null && (r.wrapped || prevFull)) cur += r.text
    else {
      if (cur !== null) out.push(cur.trimEnd())
      cur = r.text
    }
    prevFull = r.full
  }
  if (cur !== null) out.push(cur.trimEnd())
  let a = 0
  let b = out.length
  while (a < b && out[a] === '') a++
  while (b > a && out[b - 1] === '') b--
  return out.slice(a, b)
}

interface CellLike { getChars(): string; getWidth(): number }
interface LineLike {
  isWrapped: boolean
  translateToString(trimRight?: boolean): string
  getCell(x: number): CellLike | undefined
}
export interface TermLike {
  cols: number
  buffer: { active: { length: number; getLine(y: number): LineLike | undefined } }
}

/** Ultima celulă e ocupată (nu lungimea şirului: un caracter lat ocupă două celule). */
function reachesLastCell(line: LineLike, cols: number): boolean {
  if (!cols) return false
  const last = line.getCell(cols - 1)
  if (!last) return false
  if (last.getChars() !== '') return true
  const prev = cols >= 2 ? line.getCell(cols - 2) : undefined
  return last.getWidth() === 0 && !!prev && prev.getWidth() === 2
}

/** Plafon de rânduri fizice: un scrollback de zeci de mii de rânduri ar îngheţa un telefon. */
export const SELTEXT_MAX_ROWS = 3000

/** Liniile logice din bufferul curent (scrollback + ecran), cele mai recente `maxRows` rânduri. */
export function terminalLines(term: TermLike | null | undefined, maxRows = SELTEXT_MAX_ROWS): string[] {
  if (!term) return []
  const buf = term.buffer.active
  const rows: SelRow[] = []
  for (let i = Math.max(0, buf.length - maxRows); i < buf.length; i++) {
    const line = buf.getLine(i)
    if (!line) continue
    rows.push({
      text: line.translateToString(false),
      // primul rând păstrat nu are de cine să se lipească, chiar dacă era o continuare
      wrapped: rows.length > 0 && line.isWrapped,
      full: reachesLastCell(line, term.cols),
    })
  }
  return logicalLines(rows)
}

/** Ce pleacă în clipboard dintr-o selecţie nativă: fără NBSP (unele browsere îl pun în locul
    spaţiilor din `white-space: pre-wrap`), cu newline-uri normalizate, fără rânduri goale la capete. */
export function cleanSelection(s: string): string {
  return s.replace(/\xa0/g, ' ').replace(/\r\n?/g, '\n').replace(/^\n+|\n+$/g, '')
}
