import type { Terminal } from '@xterm/xterm'

// Detectarea URL-urilor în terminal, făcută NOI (nu doar de addon-ul de click): un URL lung
// se rupe pe mai multe rânduri, iar login-urile tip Claude Code au mouse-tracking pornit —
// clicul e capturat de aplicaţie, nu de link. Un meniu „Linkuri" alimentat de funcţia asta
// ocoleşte ambele: reconstruieşte rândurile rupte şi trăieşte în afara terminalului.

// Acelaşi regex strict ca @xterm/addon-web-links (http/https, se opreşte la spaţiu/ghilimele
// şi la interpuncţie finală), dar GLOBAL — pot fi mai multe URL-uri pe o linie logică. DOAR
// http/https: niciodată `javascript:` sau alte scheme, deci deschiderea e sigură.
const URL_RE = /(https?):[/]{2}[^\s"'!*(){}|\\^<>`]*[^\s"':,.!?{}|\\^~[\]`()<>]/gi

/** URL-urile dintr-un set de linii LOGICE (rândurile rupte deja reunite), unice, în ordinea
 *  apariţiei. Pur — testabil fără xterm. */
export function urlsFromText(lines: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const line of lines) {
    for (const m of line.matchAll(URL_RE)) {
      const u = m[0]
      if (!seen.has(u)) {
        seen.add(u)
        out.push(u)
      }
    }
  }
  return out
}

export type Row = { text: string; wrapped: boolean; full: boolean }

/** Reuneşte rândurile FIZICE în linii logice. Pur — testabil fără xterm.
 *
 *  Un rând continuă linia precedentă în DOUĂ cazuri:
 *   · `wrapped` — terminalul a rupt de la sine la marginea coloanei (soft-wrap, isWrapped);
 *   · precedentul era `full` — aplicaţia (ex. Ink/Claude Code) şi-a făcut SINGURĂ wrap-ul,
 *     emiţând rânduri separate care umplu lăţimea; nu sunt `isWrapped`, dar un rând plin ochi
 *     urmat de alt conţinut e aproape sigur o continuare.
 *  La continuare tăiem spaţiile de la ÎNCEPUTUL rândului următor: un URL n-are spaţii interne,
 *  iar o casetă (login-ul Claude Code) indentează rândurile rupte — fără tăiere, indentarea
 *  ar injecta spaţii în mijlocul URL-ului şi regex-ul s-ar opri acolo (exact bug-ul raportat). */
export function joinRows(rows: Row[]): string[] {
  const out: string[] = []
  let cur = ''
  let prevFull = false
  for (const r of rows) {
    if (cur !== '' && (r.wrapped || prevFull)) {
      cur += r.text.replace(/^\s+/, '')
    } else {
      if (cur) out.push(cur)
      cur = r.text
    }
    prevFull = r.full
  }
  if (cur) out.push(cur)
  return out
}

// cât de aproape de marginea dreaptă trebuie să ajungă un rând ca să-l considerăm „plin"
// (deci rupt): o casetă lasă 1–2 coloane de bordură/padding, deci tolerăm câteva.
const FULL_MARGIN = 3

function readRows(term: Terminal): Row[] {
  const buf = term.buffer.active
  const cols = term.cols
  const rows: Row[] = []
  for (let i = 0; i < buf.length; i++) {
    const line = buf.getLine(i)
    if (!line) continue
    const text = line.translateToString(true)   // taie spaţiile de la coadă
    rows.push({
      text,
      wrapped: line.isWrapped,
      full: text.length >= cols - FULL_MARGIN,
    })
  }
  return rows
}

/** URL-urile din tot bufferul curent al terminalului (viewport + scrollback), reunite peste
 *  rândurile rupte (soft- ŞI hard-wrap), unice, în ordinea apariţiei. Chemat la cerere. */
export function extractUrls(term: Terminal | undefined): string[] {
  if (!term) return []
  return urlsFromText(joinRows(readRows(term)))
}
