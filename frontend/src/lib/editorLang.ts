// Detecţia limbajului pentru editorul de fişiere (Monaco slim, 3.5.6). PUR — fără Monaco, fără
// DOM — ca să fie testat în vitest. Editorul aduce DOAR tokenizerele Monarch de bază pentru ce
// editează un sysadmin pe un host (lista de mai jos); orice altceva cade pe `plaintext`, niciodată
// eroare. Id-urile trebuie să fie exact cele înregistrate în components/monacoSetup.ts.

export const EDITOR_LANGS = [
  'shell', 'yaml', 'json', 'ini', 'toml', 'dockerfile', 'nginx', 'python',
  'javascript', 'typescript', 'sql', 'xml', 'html', 'css', 'markdown',
  'go', 'rust', 'php', 'ruby', 'lua', 'perl', 'powershell', 'cpp', 'java', 'hcl',
  'plaintext',
] as const
export type EditorLang = typeof EDITOR_LANGS[number]

// nume EXACTE (basename, lowercase) — fişiere fără extensie sau cu extensie înşelătoare
const NAMES: Record<string, EditorLang> = {
  dockerfile: 'dockerfile', containerfile: 'dockerfile',
  // Makefile n-are tokenizer propriu în Monaco; shell-ul colorează comentariile, variabilele
  // şi şirurile corect — mai util decât text simplu
  makefile: 'shell', gnumakefile: 'shell',
  '.bashrc': 'shell', '.bash_profile': 'shell', '.bash_login': 'shell', '.bash_logout': 'shell',
  '.bash_aliases': 'shell', '.profile': 'shell', '.zshrc': 'shell', '.zshenv': 'shell',
  '.zprofile': 'shell', '.zlogin': 'shell', '.kshrc': 'shell', '.envrc': 'shell',
  bashrc: 'shell', profile: 'shell', 'bash.bashrc': 'shell', 'apkbuild': 'shell', pkgbuild: 'shell',
  '.env': 'ini', '.gitconfig': 'ini', '.editorconfig': 'ini', '.npmrc': 'ini', '.pypirc': 'ini', '.my.cnf': 'ini',
  '.babelrc': 'json', '.eslintrc': 'json', '.prettierrc': 'json', '.jshintrc': 'json',
  'cargo.lock': 'toml', pipfile: 'toml', 'poetry.lock': 'toml',
  gemfile: 'ruby', rakefile: 'ruby', vagrantfile: 'ruby', podfile: 'ruby', brewfile: 'ruby',
  'nginx.conf': 'nginx',
}

// extensie (fără punct, lowercase) → limbaj
const EXTS: Record<string, EditorLang> = {
  sh: 'shell', bash: 'shell', zsh: 'shell', ksh: 'shell', ash: 'shell', dash: 'shell', bats: 'shell',
  command: 'shell',
  yaml: 'yaml', yml: 'yaml',
  json: 'json', jsonc: 'json', json5: 'json', webmanifest: 'json', geojson: 'json', jsonl: 'json',
  ndjson: 'json',
  // ini acoperă tot ce e „cheie=valoare + [secţiune] + # comentariu": unităţi systemd, .conf/.cfg
  // generice, .env, .desktop, my.cnf, php.ini, .properties ale Java
  ini: 'ini', conf: 'ini', cfg: 'ini', cnf: 'ini', properties: 'ini', prop: 'ini', env: 'ini',
  desktop: 'ini', service: 'ini', socket: 'ini', timer: 'ini', mount: 'ini', automount: 'ini',
  target: 'ini', path: 'ini', slice: 'ini', scope: 'ini', swap: 'ini', network: 'ini',
  netdev: 'ini', link: 'ini', container: 'ini', volume: 'ini', pod: 'ini', repo: 'ini',
  toml: 'toml',
  dockerfile: 'dockerfile', containerfile: 'dockerfile',
  nginx: 'nginx', nginxconf: 'nginx',
  py: 'python', pyw: 'python', pyi: 'python',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', mts: 'typescript', cts: 'typescript', tsx: 'typescript',
  sql: 'sql',
  xml: 'xml', svg: 'xml', xsl: 'xml', xslt: 'xml', xsd: 'xml', plist: 'xml', xaml: 'xml',
  csproj: 'xml', pom: 'xml', wsdl: 'xml', rss: 'xml', atom: 'xml',
  html: 'html', htm: 'html', xhtml: 'html',
  css: 'css', scss: 'css', less: 'css',
  md: 'markdown', markdown: 'markdown', mdown: 'markdown', mkd: 'markdown',
  go: 'go',
  rs: 'rust',
  php: 'php', phtml: 'php',
  rb: 'ruby', rake: 'ruby', gemspec: 'ruby', ru: 'ruby',
  lua: 'lua',
  pl: 'perl', pm: 'perl',
  ps1: 'powershell', psm1: 'powershell', psd1: 'powershell',
  c: 'cpp', h: 'cpp', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp', hxx: 'cpp',
  ino: 'cpp',
  java: 'java',
  hcl: 'hcl', tf: 'hcl', tfvars: 'hcl', nomad: 'hcl',
  txt: 'plaintext', log: 'plaintext',
}

// interpretorul din shebang → limbaj (`#!/usr/bin/env python3`, `#!/bin/bash -e`)
const SHEBANG: [RegExp, EditorLang][] = [
  [/^(ba|z|k|da|a|mk)?sh$/, 'shell'],
  [/^python[\d.]*$/, 'python'],
  [/^(node|nodejs|deno|bun)$/, 'javascript'],
  [/^perl[\d.]*$/, 'perl'],
  [/^ruby[\d.]*$/, 'ruby'],
  [/^php[\d.]*$/, 'php'],
  [/^lua[\d.]*$/, 'lua'],
  [/^pwsh$/, 'powershell'],
]

function shebangLang(firstLine: string): EditorLang | null {
  if (!firstLine.startsWith('#!')) return null
  const words = firstLine.slice(2).trim().split(/\s+/)
  let prog = words[0]?.split('/').pop() ?? ''
  // `#!/usr/bin/env -S python3 -u` → sărim peste env, opţiunile lui şi VAR=valoare
  if (prog === 'env') prog = words.slice(1).find((w) => !w.startsWith('-') && !w.includes('=')) ?? ''
  for (const [re, lang] of SHEBANG) if (re.test(prog)) return lang
  return null
}

/** Limbajul Monaco pentru un fişier: nume exact → config nginx după cale → extensie → shebang /
    antet XML → plaintext. `path` poate fi calea completă sau doar numele (basename). */
export function detectLanguage(path: string, firstLine = ''): EditorLang {
  const lower = path.toLowerCase()
  const name = lower.split('/').pop() ?? lower
  if (NAMES[name]) return NAMES[name]
  // Dockerfile.prod, Dockerfile-dev, Containerfile.alpine
  if (/^(docker|container)file[.-]/.test(name)) return 'dockerfile'
  // .env.local, .env.production
  if (name.startsWith('.env.')) return 'ini'
  // tot ce e sub /etc/nginx/ (sites-available/default n-are extensie) şi orice *nginx*.conf
  if (/(^|\/)nginx\//.test(lower) && !/\.(json|ya?ml|html?|js|lua|pem|crt|key)$/.test(name)) {
    // mime.types, fastcgi_params, sites-*/*, conf.d/*.conf, snippets/*.conf — toate sintaxă nginx
    return 'nginx'
  }
  if (name.includes('nginx') && name.endsWith('.conf')) return 'nginx'
  const dot = name.lastIndexOf('.')
  // .bashrc etc. au fost prinse sus; un nume „.ceva" fără alt punct nu are extensie
  const ext = dot > 0 ? name.slice(dot + 1) : ''
  if (ext && EXTS[ext]) return EXTS[ext]
  const sb = shebangLang(firstLine)
  if (sb) return sb
  if (/^\s*<\?xml\b/.test(firstLine)) return 'xml'
  return 'plaintext'
}
