// Monaco SLIM (3.5.6, monaco-editor 0.57). Înainte importam `monaco-editor` întreg: toate cele
// ~80 de limbaje + serviciile de limbaj TS/CSS/HTML/JSON cu workerele lor (ts.worker singur avea
// 5,9 MB). Acum aducem DOAR:
//   • API-ul editorului (`monaco-editor/editor/editor.api`, fără limbaje şi fără feature-uri),
//   • feature-urile pe care le foloseşte cineva care editează un config pe un host (mai jos),
//   • tokenizerele Monarch de bază pentru limbajele din lib/editorLang.ts (fiecare e un chunk mic,
//     descărcat abia când deschizi un fişier de tipul ăla),
//   • un singur worker, editor.worker (diff-uri, calcule pe model în afara thread-ului UI).
// Preţul, asumat: nu mai există autocompletare/validare de limbaj (IntelliSense TS, scheme JSON,
// validare CSS). Pentru un editor de config-uri pe server e compromisul corect.
//
// Calea `monaco-editor/esm/vs/...` nu mai merge în 0.57: `exports` mapează `./*` → `./esm/vs/*.js`,
// deci specificatorii sunt relativi la esm/vs şi FĂRĂ extensie.
import * as monaco from 'monaco-editor/editor/editor.api'
import editorWorker from 'monaco-editor/editor/editor.worker?worker'

// ── feature-uri (fiecare = o contribuţie a editorului; ordinea nu contează) ──
// Lăsate DELIBERAT afară: `suggest` (popup-ul de completare pe cuvinte, ~150 KB cu snippet-urile —
// fără servicii de limbaj n-ar propune decât cuvintele deja din fişier), `hover`, `dnd`,
// `codeAction`, `rename`, `format` etc. Editorul de bază (editor.api) rămâne ~2,8 MB minificat
// oricum: widget-ul, modelul, view-ul, quick-input-ul şi diff-ul sunt în nucleu, nu în feature-uri.
import 'monaco-editor/editor/browser/coreCommands'                // mişcarea cursorului, selecţie, tastatură
import 'monaco-editor/features/codicon/register'                 // iconiţele (căutare, folding)
import 'monaco-editor/features/find/register'                    // Ctrl+F / Ctrl+H
import 'monaco-editor/features/folding/register'
import 'monaco-editor/features/bracketMatching/register'
import 'monaco-editor/features/multicursor/register'             // Ctrl+D, Alt+click, Ctrl+Alt+↑/↓
import 'monaco-editor/features/comment/register'                 // Ctrl+/ (comentariul din conf-ul limbajului)
import 'monaco-editor/features/gotoLine/register'                // Ctrl+G
import 'monaco-editor/features/quickCommand/register'            // F1 — paleta de comenzi
import 'monaco-editor/features/contextmenu/register'             // click-dreapta
import 'monaco-editor/features/clipboard/register'               // Copy/Cut/Paste în meniu
import 'monaco-editor/features/linesOperations/register'         // Alt+↑/↓, Ctrl+Shift+K, sortare, trim
import 'monaco-editor/features/indentation/register'
import 'monaco-editor/features/wordOperations/register'          // Ctrl+←/→, Ctrl+Backspace
import 'monaco-editor/features/wordHighlighter/register'          // evidenţiază aparițiile cuvântului
import 'monaco-editor/features/smartSelect/register'             // Shift+Alt+→
import 'monaco-editor/features/cursorUndo/register'
import 'monaco-editor/features/lineSelection/register'
import 'monaco-editor/features/readOnlyMessage/register'         // „nu poţi edita" pe fişierul mare
import 'monaco-editor/features/toggleTabFocusMode/register'      // Ctrl+M: Tab mută focusul (a11y)
import 'monaco-editor/features/iPadShowKeyboard/register'        // tastatura pe iPad

// ── tokenizere Monarch de bază (încărcare leneşă per limbaj, din pachet) ──
import 'monaco-editor/languages/definitions/shell/register'
import 'monaco-editor/languages/definitions/yaml/register'
import 'monaco-editor/languages/definitions/ini/register'
import 'monaco-editor/languages/definitions/dockerfile/register'
import 'monaco-editor/languages/definitions/python/register'
import 'monaco-editor/languages/definitions/javascript/register'
import 'monaco-editor/languages/definitions/typescript/register'
import 'monaco-editor/languages/definitions/sql/register'
import 'monaco-editor/languages/definitions/xml/register'
import 'monaco-editor/languages/definitions/html/register'
import 'monaco-editor/languages/definitions/css/register'
import 'monaco-editor/languages/definitions/markdown/register'
import 'monaco-editor/languages/definitions/go/register'
import 'monaco-editor/languages/definitions/rust/register'
import 'monaco-editor/languages/definitions/php/register'
import 'monaco-editor/languages/definitions/ruby/register'
import 'monaco-editor/languages/definitions/lua/register'
import 'monaco-editor/languages/definitions/perl/register'
import 'monaco-editor/languages/definitions/powershell/register'
import 'monaco-editor/languages/definitions/cpp/register'
import 'monaco-editor/languages/definitions/java/register'
import 'monaco-editor/languages/definitions/hcl/register'

// Workerul, bundle-uit LOCAL de Vite (`?worker`) — fără CDN, fără blob:, acelaşi origin
// (CSP-ul gateway-ului n-are worker-src → cade pe script-src 'self', care îl acoperă).
// Fără serviciile de limbaj, ORICE label primeşte editor.worker.
;(self as unknown as { MonacoEnvironment: monaco.Environment }).MonacoEnvironment = {
  getWorker: () => new editorWorker(),
}

// ── limbaje care NU au tokenizer de bază în Monaco: JSON (avea doar serviciul greu), TOML, nginx ──

const jsonConf: monaco.languages.LanguageConfiguration = {
  comments: { lineComment: '//', blockComment: ['/*', '*/'] },
  brackets: [['{', '}'], ['[', ']']],
  autoClosingPairs: [
    { open: '{', close: '}' }, { open: '[', close: ']' }, { open: '"', close: '"', notIn: ['string'] },
  ],
}
const jsonLang: monaco.languages.IMonarchLanguage = {
  defaultToken: '',          // îngăduitor: JSON5 (chei fără ghilimele) nu se colorează ca eroare
  tokenPostfix: '.json',
  tokenizer: {
    root: [
      { include: '@whitespace' },
      // cheie = şir urmat de „:" (temele vs/vs-dark au culori dedicate string.key.json / value)
      [/"(?:[^"\\]|\\.)*"(?=\s*:)/, 'string.key'],
      [/"(?:[^"\\]|\\.)*"/, 'string.value'],
      [/"(?:[^"\\]|\\.)*$/, 'string.invalid'],
      [/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/, 'number'],
      [/\b(?:true|false|null)\b/, 'keyword'],
      [/[{}[\]]/, '@brackets'],
      [/[,:]/, 'delimiter'],
    ],
    // JSONC (tsconfig, settings.json): comentariile nu sunt erori
    whitespace: [
      [/\s+/, ''],
      [/\/\/.*$/, 'comment'],
      [/\/\*/, 'comment', '@comment'],
    ],
    comment: [
      [/[^/*]+/, 'comment'],
      [/\*\//, 'comment', '@pop'],
      [/[/*]/, 'comment'],
    ],
  },
}

const tomlConf: monaco.languages.LanguageConfiguration = {
  comments: { lineComment: '#' },
  brackets: [['{', '}'], ['[', ']']],
  autoClosingPairs: [
    { open: '{', close: '}' }, { open: '[', close: ']' },
    { open: '"', close: '"', notIn: ['string'] }, { open: "'", close: "'", notIn: ['string'] },
  ],
}
const tomlLang: monaco.languages.IMonarchLanguage = {
  defaultToken: '',
  tokenPostfix: '.toml',
  tokenizer: {
    root: [
      [/#.*$/, 'comment'],
      [/^\s*\[\[?[^\]]*\]\]?/, 'metatag'],                       // [tabel] / [[tablou.de.tabele]]
      [/^(\s*)([\w.\-"']+)(\s*)(=)/, ['', 'key', '', 'delimiter']],
      [/"""/, 'string', '@mlBasic'],
      [/'''/, 'string', '@mlLiteral'],
      [/"/, 'string', '@basic'],
      [/'[^']*'/, 'string'],
      // date/ore RFC 3339 înaintea numerelor (altfel 2024 ar fi luat ca număr)
      [/\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?/, 'number'],
      [/\d{2}:\d{2}:\d{2}(?:\.\d+)?/, 'number'],
      [/[+-]?(?:0x[\da-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?|inf|nan)\b/, 'number'],
      [/\b(?:true|false)\b/, 'keyword'],
      [/[{}[\]]/, '@brackets'],
      [/[,=.]/, 'delimiter'],
    ],
    basic: [
      [/[^"\\]+/, 'string'],
      [/\\./, 'string.escape'],
      [/"/, 'string', '@pop'],
    ],
    mlBasic: [
      [/[^"\\]+/, 'string'],
      [/\\./, 'string.escape'],
      [/"""/, 'string', '@pop'],
      [/"/, 'string'],
    ],
    mlLiteral: [
      [/[^']+/, 'string'],
      [/'''/, 'string', '@pop'],
      [/'/, 'string'],
    ],
  },
}

// nginx: directiva = primul cuvânt al instrucţiunii (keyword), apoi argumentele până la `;` sau `{`.
// Variabilele ($host, ${var}), şirurile, numerele cu unităţi (10m, 30s) şi on/off au culori proprii.
const nginxConf: monaco.languages.LanguageConfiguration = {
  comments: { lineComment: '#' },
  brackets: [['{', '}'], ['(', ')']],
  autoClosingPairs: [
    { open: '{', close: '}' }, { open: '(', close: ')' },
    { open: '"', close: '"', notIn: ['string'] }, { open: "'", close: "'", notIn: ['string'] },
  ],
  surroundingPairs: [{ open: '"', close: '"' }, { open: "'", close: "'" }, { open: '{', close: '}' }],
}
const nginxLang: monaco.languages.IMonarchLanguage = {
  defaultToken: '',
  tokenPostfix: '.nginx',
  tokenizer: {
    root: [
      [/\s+/, ''],
      [/#.*$/, 'comment'],
      [/[{}]/, '@brackets'],
      [/;/, 'delimiter'],
      [/[A-Za-z_][\w.-]*/, { token: 'keyword', next: '@args' }],
    ],
    args: [
      [/\s+/, ''],
      [/#.*$/, 'comment'],
      [/;/, 'delimiter', '@pop'],
      [/\{/, '@brackets', '@pop'],
      [/\}/, '@brackets', '@pop'],
      [/\$\{?\w+\}?/, 'variable'],
      [/"/, 'string', '@dq'],
      [/'/, 'string', '@sq'],
      [/\b(?:on|off)\b/, 'constant'],
      [/~\*?|=|!=|!~\*?|\^~/, 'operator'],
      [/\b\d+(?:\.\d+)?(?:ms|[kKmMgGsShHdDwWyY])?\b/, 'number'],
      [/[()]/, '@brackets'],
      [/[^\s;{}$"'#()]+/, ''],
    ],
    dq: [
      [/[^"\\$]+/, 'string'],
      [/\$\{?\w+\}?/, 'variable'],
      [/\\./, 'string.escape'],
      [/\$/, 'string'],
      [/"/, 'string', '@pop'],
    ],
    sq: [
      [/[^'\\$]+/, 'string'],
      [/\$\{?\w+\}?/, 'variable'],
      [/\\./, 'string.escape'],
      [/\$/, 'string'],
      [/'/, 'string', '@pop'],
    ],
  },
}

for (const [id, conf, lang] of [
  ['json', jsonConf, jsonLang],
  ['toml', tomlConf, tomlLang],
  ['nginx', nginxConf, nginxLang],
] as const) {
  monaco.languages.register({ id })
  monaco.languages.setLanguageConfiguration(id, conf)
  monaco.languages.setMonarchTokensProvider(id, lang)
}
