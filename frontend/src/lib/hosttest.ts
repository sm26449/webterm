/* „Test connection" din Add host / Edit host (POST /api/hosts/test). Serverul întoarce etape cu
   CODURI, fără proză: aici le transformăm în rândurile afişate (icon + etichetă + text tradus).
   Pur (fără React), ca să fie testabil în vitest. Codurile de eşec sunt cele de la conectarea
   reală (`err.ssh.authFailed`, `err.ssh.noBanner`…) plus cele ale testului (`err.hosttest.*`). */

export type StageId = 'tcp' | 'banner' | 'hostkey' | 'auth'

export type TestStage = {
  id: StageId
  ok: boolean
  ms?: number
  code?: string
  vars?: Record<string, string | number>
  detail?: string
  warn?: boolean
  skipped?: boolean
}

export type TestResult = {
  ok: boolean
  stages: TestStage[]
  hostkey?: { type: string; fingerprint_sha256: string; key?: string }
}

export type StageView = {
  id: StageId
  state: 'ok' | 'fail' | 'warn' | 'skip'
  icon: string          // glif vizual (aria-hidden); cititorul de ecran primeşte starea ca text (sr-only)
  label: string
  text: string
}

type T = (k: string, v?: Record<string, string | number>) => string

/** Rândurile de afişat, în ordinea etapelor. `telnet` schimbă eticheta bannerului. */
export function stageViews(r: TestResult, t: T, telnet: boolean): StageView[] {
  return r.stages.map((st) => {
    const label = st.id === 'banner'
      ? (telnet ? t('hosttest.stage.telnet') : t('hosttest.stage.ssh'))
      : t(`hosttest.stage.${st.id}`)
    if (st.ok) {
      let text = ''
      if (st.id === 'tcp' && typeof st.ms === 'number') text = t('hosttest.ms', { ms: st.ms })
      else if (st.id === 'banner') {
        text = telnet
          ? (st.detail === 'prompt' ? t('hosttest.telnetPrompt') : t('hosttest.telnetData'))
          : (st.detail ?? '')
      } else if (st.id === 'hostkey') text = r.hostkey?.fingerprint_sha256 ?? ''
      return { id: st.id, state: 'ok', icon: '✓', label, text }
    }
    const state = st.skipped ? 'skip' : st.warn ? 'warn' : 'fail'
    return { id: st.id, state, icon: state === 'skip' ? '–' : state === 'warn' ? '!' : '✗', label,
             text: codeText(st.code, st.vars, t) }
  })
}

/** Textul tradus al unui cod (`err.<code>`); fallback generic dacă lipseşte din catalog. */
export function codeText(code: string | undefined, vars: Record<string, string | number> | undefined, t: T): string {
  if (code) {
    const s = t(`err.${code}`, vars)
    if (s !== `err.${code}`) return s
  }
  return t('err.hosttest.failed')
}

/** Rezumatul anunţat (aria-live) după test: reuşit / avertisment / etapa care a picat. */
export function summaryText(r: TestResult, t: T, telnet: boolean): string {
  const failed = r.stages.find((s) => !s.ok && !s.warn && !s.skipped)
  if (failed) {
    const v = stageViews({ ...r, stages: [failed] }, t, telnet)[0]
    return t('hosttest.failedAt', { stage: v.label, reason: v.text })
  }
  if (r.stages.some((s) => s.warn)) return t('hosttest.okWarn')
  if (r.stages.some((s) => s.skipped)) return t('hosttest.okNoAuth')
  return t('hosttest.ok')
}

/** Câmpul de formular de care ţine o etapă picată — focusul merge acolo, nu pe „Nume". */
export function failingField(r: TestResult): 'hostname' | 'port' | 'username' | 'secret' | 'via' | null {
  const failed = r.stages.find((s) => !s.ok && !s.warn && !s.skipped)
  if (!failed) return null
  if (failed.code === 'sshjump.unreachable') return 'hostname'
  if (failed.id === 'tcp') return failed.code === 'hosttest.dns' ? 'hostname' : 'port'
  if (failed.id === 'banner') return 'port'
  if (failed.id === 'auth') return failed.code === 'ssh.authFailed' ? 'secret' : null
  return null
}

/** Amprenta conexiunii testate: orice schimbare a unui câmp de conexiune o invalidează. */
export function connSignature(f: Record<string, string | number | boolean | null | undefined>): string {
  return JSON.stringify(Object.keys(f).sort().map((k) => [k, f[k] ?? null]))
}
