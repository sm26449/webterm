import type { Terminal } from '@xterm/xterm'

// Detectarea URL-urilor în terminal, făcută NOI (nu doar de addon-ul de click): un URL lung
// se rupe pe mai multe rânduri, iar login-urile tip Claude Code au mouse-tracking pornit —
// clicul e capturat de aplicație, nu de link. Un meniu „Linkuri" alimentat de funcţia asta
// ocoleşte ambele: reconstruieşte rândurile rupte şi trăieşte în afara terminalului, deci
// merge şi sub mouse-mode, şi pe mobil (un URL rupt e greu de nimerit cu degetul).

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

/** Reuneşte rândurile RUPTE (isWrapped) ale bufferului activ în linii logice. Un rând de
 *  continuare umple toată lăţimea, deci `translateToString(true)` nu-i taie nimic; ultimul
 *  rând al unei linii îşi pierde spaţiile de la coadă, ca să nu spargem un URL cu ele. */
function logicalLines(term: Terminal): string[] {
  const buf = term.buffer.active
  const out: string[] = []
  let cur = ''
  for (let i = 0; i < buf.length; i++) {
    const line = buf.getLine(i)
    if (!line) continue
    const s = line.translateToString(true)
    if (line.isWrapped) cur += s
    else {
      if (cur) out.push(cur)
      cur = s
    }
  }
  if (cur) out.push(cur)
  return out
}

/** URL-urile din tot bufferul curent al terminalului (viewport + scrollback), reunite peste
 *  rândurile rupte, unice, în ordinea apariţiei. Chemat la cerere (deschiderea meniului). */
export function extractUrls(term: Terminal | undefined): string[] {
  if (!term) return []
  return urlsFromText(logicalLines(term))
}
