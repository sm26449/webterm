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
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'eslint.config.js'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,

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
