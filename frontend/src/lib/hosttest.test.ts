import { describe, expect, it } from 'vitest'
import { codeText, connSignature, failingField, stageViews, summaryText, TestResult } from './hosttest'

// `t` minimal: catalogul de test + interpolare {var}; cheie lipsă → cheia însăşi (ca i18n.tsx)
const CAT: Record<string, string> = {
  'hosttest.stage.tcp': 'TCP', 'hosttest.stage.ssh': 'SSH', 'hosttest.stage.telnet': 'Telnet',
  'hosttest.stage.hostkey': 'host key', 'hosttest.stage.auth': 'authentication',
  'hosttest.ms': '{ms} ms', 'hosttest.telnetPrompt': 'login prompt', 'hosttest.telnetData': 'answered',
  'hosttest.ok': 'Connection verified', 'hosttest.okWarn': 'Reachable, with a warning',
  'hosttest.okNoAuth': 'Reachable; authentication not tested', 'hosttest.failedAt': '{stage} failed: {reason}',
  'err.ssh.authFailed': 'The target rejected the credentials', 'err.hosttest.refused': 'Connection refused',
  'err.hosttest.failed': 'The test failed', 'err.hosttest.hostKeyMismatch': 'differs {old_fp} → {new_fp}',
  'err.hosttest.telnetSilent': 'No banner yet', 'err.hosttest.authSkipped': 'not tested',
}
const t = (k: string, v?: Record<string, string | number>) =>
  (CAT[k] ?? k).replace(/\{(\w+)\}/g, (_m, n) => String(v?.[n] ?? `{${n}}`))

const okSsh: TestResult = {
  ok: true,
  stages: [
    { id: 'tcp', ok: true, ms: 23 }, { id: 'banner', ok: true, ms: 4, detail: 'SSH-2.0-OpenSSH_9.6' },
    { id: 'hostkey', ok: true, ms: 11 }, { id: 'auth', ok: true, ms: 40 },
  ],
  hostkey: { type: 'ssh-ed25519', fingerprint_sha256: 'SHA256:abc' },
}

describe('stageViews', () => {
  it('reuşită SSH: ✓ TCP 23 ms · ✓ SSH versiunea · ✓ host key amprenta · ✓ authentication', () => {
    const v = stageViews(okSsh, t, false)
    expect(v.map((s) => s.state)).toEqual(['ok', 'ok', 'ok', 'ok'])
    expect(v.map((s) => s.icon).join('')).toBe('✓✓✓✓')
    expect(v[0]).toMatchObject({ label: 'TCP', text: '23 ms' })
    expect(v[1]).toMatchObject({ label: 'SSH', text: 'SSH-2.0-OpenSSH_9.6' })
    expect(v[2]).toMatchObject({ label: 'host key', text: 'SHA256:abc' })
  })
  it('eşec la auth: textul tradus al codului de la conectarea reală', () => {
    const r: TestResult = { ok: false, stages: [...okSsh.stages.slice(0, 3), { id: 'auth', ok: false, code: 'ssh.authFailed' }] }
    const v = stageViews(r, t, false)
    expect(v[3]).toMatchObject({ state: 'fail', icon: '✗', text: 'The target rejected the credentials' })
    expect(summaryText(r, t, false)).toBe('authentication failed: The target rejected the credentials')
  })
  it('telnet: eticheta Telnet, promptul detectat, tăcerea e avertisment', () => {
    const r: TestResult = { ok: true, stages: [{ id: 'tcp', ok: true, ms: 2 }, { id: 'banner', ok: true, detail: 'prompt' }] }
    expect(stageViews(r, t, true)[1]).toMatchObject({ label: 'Telnet', text: 'login prompt' })
    const w: TestResult = { ok: true, stages: [{ id: 'tcp', ok: true }, { id: 'banner', ok: false, warn: true, code: 'hosttest.telnetSilent' }] }
    expect(stageViews(w, t, true)[1]).toMatchObject({ state: 'warn', icon: '!' })
    expect(summaryText(w, t, true)).toBe('Reachable, with a warning')
  })
  it('auth sărit (fără credenţial) → skip, rezumat fără „verificat"', () => {
    const r: TestResult = { ok: true, stages: [...okSsh.stages.slice(0, 3), { id: 'auth', ok: false, skipped: true, code: 'hosttest.authSkipped' }] }
    expect(stageViews(r, t, false)[3].state).toBe('skip')
    expect(summaryText(r, t, false)).toBe('Reachable; authentication not tested')
  })
})

describe('codeText', () => {
  it('interpolează vars; cod necunoscut → mesaj generic', () => {
    expect(codeText('hosttest.hostKeyMismatch', { old_fp: 'A', new_fp: 'B' }, t)).toBe('differs A → B')
    expect(codeText('nope.unknown', undefined, t)).toBe('The test failed')
    expect(codeText(undefined, undefined, t)).toBe('The test failed')
  })
})

describe('failingField', () => {
  it('trimite focusul la câmpul vinovat', () => {
    const at = (id: 'tcp' | 'banner' | 'auth', code: string): TestResult => ({ ok: false, stages: [{ id, ok: false, code }] })
    expect(failingField(at('tcp', 'hosttest.refused'))).toBe('port')
    expect(failingField(at('tcp', 'hosttest.dns'))).toBe('hostname')
    expect(failingField(at('tcp', 'sshjump.unreachable'))).toBe('hostname')
    expect(failingField(at('banner', 'ssh.noBanner'))).toBe('port')
    expect(failingField(at('auth', 'ssh.authFailed'))).toBe('secret')
    expect(failingField(okSsh)).toBeNull()
  })
})

describe('connSignature', () => {
  it('stabilă la ordinea cheilor, diferită la orice valoare schimbată', () => {
    expect(connSignature({ a: 1, b: 'x' })).toBe(connSignature({ b: 'x', a: 1 }))
    expect(connSignature({ a: 1, b: 'x' })).not.toBe(connSignature({ a: 1, b: 'y' }))
  })
})
