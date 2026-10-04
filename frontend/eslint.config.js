// ESLint pentru frontend. A lipsit mult timp, iar codul conține deja 17 pragme
// `eslint-disable react-hooks/exhaustive-deps` — adică autorii ȘTIAU unde sunt locurile
// riscante, dar nimic nu le verifica: pragmele suprimau un linter care nu rula.
//
// Regula care contează aici e `react-hooks/*`. Aplicația ține terminale xterm vii în
// closure-uri, cu listeneri, timere și WebSocket-uri — exact terenul stale closures. Un
// incident real din istorie (hook mutat după un return timpuriu → crash post-login,
// React #310) ar fi fost prins de `rules-of-hooks`, nu de `tsc`.
//
// Stilul NU e verificat: nu vrem un al doilea limbaj de reguli peste „scrie ca împrejurimile"
// din CONTRIBUTING. Doar bug-uri reale — la fel ca `ruff --select F` pe Python.
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import tseslint from 'typescript-eslint'

// Accesibilitate statică (auditul 2026-10-04, §8.6): `jsx-a11y/recommended` în întregime.
// Regulile care aveau 0 încălcări la introducere sunt ERORI — ele păzesc ce e deja curat
// (alt-text, aria-*, role-*, label-has-associated-control, anchor-is-valid, tabindex-no-positive…).
// Cele de mai jos aveau încălcări în componente pe care nu le putem repara dintr-un singur
// commit; rămân AVERTISMENTE (CI rulează `eslint .` fără --max-warnings, deci nu blochează)
// până la curăţarea lor, apoi se scot din listă şi devin erori. Numărul = încălcări la 2026-10-04.
const A11Y_WARN_FOR_NOW = [
  'jsx-a11y/click-events-have-key-events',            // 45 — div/span cu onClick fără onKeyDown
  'jsx-a11y/no-static-element-interactions',          // 35 — acelaşi tipar, fără role
  'jsx-a11y/no-noninteractive-element-interactions',  // 14 — li/tr/p cu handler-e
  'jsx-a11y/no-noninteractive-tabindex',              //  4 — App.tsx, FilePanel, HostLoadRing, Sidebar
]
// `no-autofocus` e OPRITĂ, nu doar coborâtă la warn: toate cele ~22 de utilizări sunt în dialoguri
// modale cu focus-trap (ConfirmModal, prompt, formulare), unde mutarea focusului în dialog la
// deschidere e exact ce cere APG „dialog (modal)"; regula ţinteşte autofocus-ul pe pagini întregi.
const A11Y_OFF = ['jsx-a11y/no-autofocus']
const a11yRules = Object.fromEntries(
  Object.entries(jsxA11y.flatConfigs.recommended.rules).map(([id, v]) => {
    if (A11Y_OFF.includes(id)) return [id, 'off']
    if (!A11Y_WARN_FOR_NOW.includes(id)) return [id, v]            // 'error' (sau 'off') ca în recommended
    return [id, Array.isArray(v) ? ['warn', ...v.slice(1)] : 'warn'] // păstrăm opţiunile regulii
  }),
)

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'eslint.config.js'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: { 'react-hooks': reactHooks, 'jsx-a11y': jsxA11y },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...a11yRules,

      // `any` e folosit deliberat la marginile netipate (addon-uri xterm, API-uri de
      // browser în curs de standardizare). Îl semnalăm ca avertisment, nu ca eroare.
      '@typescript-eslint/no-explicit-any': 'warn',
      // variabile nefolosite: eroare, DAR prefixul `_` e evadarea convenită
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
      // `catch {}` gol e un tipar intenționat aici (best-effort: clipboard, focus, dispose)
      'no-empty': ['error', { allowEmptyCatch: true }],
      // Într-un emulator de terminal, `\x1b` în regex e materia primă, nu o greşeală:
      // orice curăţare de secvenţe ANSI îl conţine.
      'no-control-regex': 'off',
    },
  },
)
