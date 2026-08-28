// Parser minimal pentru CHANGELOG.md — DOAR ce foloseşte formatul nostru (Keep a Changelog):
// titluri `## [ver] — …`, secţiuni `### …`, itemi `- …` (cu continuări indentate), şi inline
// `**bold**` / `` `code` ``. Nu tragem o librărie de markdown: e o dependenţă mare pentru un
// subset fix, iar randarea ca NODURI (nu HTML) închide orice suprafaţă de injectare chiar dacă
// fişierul ar conţine cândva `<script>`. Blocurile sunt randate de ChangelogModal.
export type Span = { text: string; bold?: boolean; code?: boolean }
export type Block =
  | { kind: 'version'; text: string; current: boolean }
  | { kind: 'section'; text: string }
  | { kind: 'item'; spans: Span[] }
  | { kind: 'para'; spans: Span[] }

// „2.0.10" din `## [2.0.10] — …` sau `## [Unreleased]`
function versionOf(headerText: string): string | null {
  const m = headerText.match(/^\[([^\]]+)\]/)
  return m ? m[1] : null
}

export function parseInline(text: string): Span[] {
  const spans: Span[] = []
  // împarte pe **bold** şi `code`, păstrând delimitatorii ca grupuri
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) spans.push({ text: text.slice(last, m.index) })
    const tok = m[0]
    if (tok.startsWith('**')) spans.push({ text: tok.slice(2, -2), bold: true })
    else spans.push({ text: tok.slice(1, -1), code: true })
    last = m.index + tok.length
  }
  if (last < text.length) spans.push({ text: text.slice(last) })
  return spans.length ? spans : [{ text }]
}

export function parseChangelog(md: string, currentVersion?: string | null): Block[] {
  const blocks: Block[] = []
  const lines = md.replace(/\r\n/g, '\n').split('\n')
  let item: string[] | null = null            // itemul de listă în curs (poate fi pe mai multe rânduri)

  const flushItem = () => {
    if (item) {
      blocks.push({ kind: 'item', spans: parseInline(item.join(' ').trim()) })
      item = null
    }
  }

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '')
    if (/^##\s+/.test(line)) {
      flushItem()
      const text = line.replace(/^##\s+/, '')
      const ver = versionOf(text)
      blocks.push({
        kind: 'version',
        text,
        current: !!currentVersion && ver === currentVersion,
      })
    } else if (/^###\s+/.test(line)) {
      flushItem()
      blocks.push({ kind: 'section', text: line.replace(/^###\s+/, '') })
    } else if (/^\s*-\s+/.test(line)) {
      flushItem()
      item = [line.replace(/^\s*-\s+/, '')]
    } else if (item !== null && /^\s+\S/.test(raw)) {
      item.push(line.trim())                   // continuare indentată a itemului curent
    } else if (line.trim() === '') {
      flushItem()
    } else if (!/^#\s/.test(line)) {           // sare titlul H1 „# Changelog"
      flushItem()
      blocks.push({ kind: 'para', spans: parseInline(line.trim()) })
    }
  }
  flushItem()
  return blocks
}
