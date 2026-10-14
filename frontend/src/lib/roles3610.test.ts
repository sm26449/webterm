import { describe, expect, it, vi } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import { ApiError } from './api'
import { crownDialog, isCrownError, withCrownConfirm } from './crown'
import { capabilities, EXPIRY_CHOICES, expiresIn, expiryFrom, lastSignIn, tokenCap } from './usersAdmin'

/* 3.6.10 („roles, part 2"): logica pură din spatele UI-ului — ultima autentificare, legăturile
   temporare, explain access, confirmarea crown-jewel, plafonul tokenurilor. */

const NOW = Date.UTC(2026, 9, 14, 12, 0, 0)     // ms
const S = NOW / 1000

describe('lastSignIn', () => {
  it('fără câmp (fără users.manage) → hidden', () => {
    expect(lastSignIn({ created: 1 })).toEqual({ state: 'hidden' })
  })
  it('cu ştampilă → at + metoda', () => {
    expect(lastSignIn({ created: 1, last_login: 5, last_login_method: 'passkey', last_login_tracked_since: 2 }))
      .toEqual({ state: 'at', at: 5, method: 'passkey' })
  })
  it('cont mai vechi decât înregistrarea, fără ştampilă → untracked, NU never', () => {
    expect(lastSignIn({ created: 1, last_login: null, last_login_tracked_since: 10 }))
      .toEqual({ state: 'untracked', since: 10 })
  })
  it('cont creat după, fără ştampilă → never', () => {
    expect(lastSignIn({ created: 20, last_login: null, last_login_tracked_since: 10 })).toEqual({ state: 'never' })
  })
})

describe('expiryFrom', () => {
  it('permanent → null; preseturile → acum + durata', () => {
    expect(expiryFrom('permanent', '', NOW)).toBeNull()
    expect(expiryFrom('4h', '', NOW)).toBe(S + 4 * 3600)
    expect(expiryFrom('1d', '', NOW)).toBe(S + 86400)
    expect(expiryFrom('7d', '', NOW)).toBe(S + 7 * 86400)
  })
  it('custom: data locală validă', () => {
    const d = new Date(NOW + 3 * 86400 * 1000)
    const pad = (n: number) => String(n).padStart(2, '0')
    const local = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
    expect(expiryFrom('custom', local, NOW)).toBe(Math.round(d.getTime() / 1000))
  })
  it('custom: lipsă, în trecut, prea departe, gunoi → invalid', () => {
    expect(expiryFrom('custom', '', NOW)).toBe('invalid')
    expect(expiryFrom('custom', '2020-01-01T00:00', NOW)).toBe('invalid')
    expect(expiryFrom('custom', '2030-01-01T00:00', NOW)).toBe('invalid')
    expect(expiryFrom('custom', 'nope', NOW)).toBe('invalid')
  })
  it('alegerile, în ordine', () => {
    expect(EXPIRY_CHOICES).toEqual(['permanent', '4h', '1d', '7d', 'custom'])
  })
})

describe('expiresIn', () => {
  it('minute (rotunjit în sus), ore şi zile (în jos), expirat → null', () => {
    expect(expiresIn(S + 30, NOW)).toEqual({ n: 1, unit: 'm' })
    expect(expiresIn(S + 59 * 60 + 1, NOW)).toEqual({ n: 60, unit: 'm' })
    expect(expiresIn(S + 3 * 3600 + 59 * 60, NOW)).toEqual({ n: 3, unit: 'h' })
    expect(expiresIn(S + 47 * 3600, NOW)).toEqual({ n: 47, unit: 'h' })
    expect(expiresIn(S + 7 * 86400, NOW)).toEqual({ n: 7, unit: 'd' })
    expect(expiresIn(S - 1, NOW)).toBeNull()
    expect(expiresIn(S, NOW)).toBeNull()
  })
})

describe('capabilities (explain)', () => {
  it('Operator: terminal, fişiere (scriere, nu şi citire separat), comenzi…', () => {
    const c = capabilities(['host.view', 'session.open', 'files.read', 'files.write', 'run', 'session.watch'])
    expect(c).toEqual(['terminal', 'filesWrite', 'run', 'watch'])
  })
  it('doar citire fişiere', () => {
    expect(capabilities(['host.view', 'files.read'])).toEqual(['filesRead'])
  })
  it('doar host.view → view; nimic → []', () => {
    expect(capabilities(['host.view'])).toEqual(['view'])
    expect(capabilities([])).toEqual([])
  })
  it('fiecare cheie are text în ambele limbi', () => {
    for (const k of ['terminal', 'filesWrite', 'filesRead', 'run', 'docker', 'watch', 'recordings', 'admin', 'view']) {
      expect(en.strings['explain.can.' + k], k).toBeTruthy()
      expect(ro.strings['explain.can.' + k], k).toBeTruthy()
    }
  })
})

describe('withCrownConfirm', () => {
  const crown = () => new ApiError(409, 'gives a shell…', 'authz.crownJewel', { hosts: 'gw01', n: 1 })
  it('fără 409: un singur apel, fără întrebare', async () => {
    const send = vi.fn().mockResolvedValue('ok')
    const ask = vi.fn()
    expect(await withCrownConfirm(send, ask)).toBe('ok')
    expect(send).toHaveBeenCalledTimes(1)
    expect(ask).not.toHaveBeenCalled()
  })
  it('409 crown → întreabă; DA → retrimite cu confirm_crown_jewel', async () => {
    const send = vi.fn().mockRejectedValueOnce(crown()).mockResolvedValueOnce('done')
    const ask = vi.fn().mockResolvedValue(true)
    expect(await withCrownConfirm(send, ask)).toBe('done')
    expect(send.mock.calls).toEqual([[{}], [{ confirm_crown_jewel: true }]])
  })
  it('NU → null, fără a doua cerere', async () => {
    const send = vi.fn().mockRejectedValueOnce(crown())
    expect(await withCrownConfirm(send, vi.fn().mockResolvedValue(false))).toBeNull()
    expect(send).toHaveBeenCalledTimes(1)
  })
  it('altă eroare: aruncată mai departe, fără întrebare', async () => {
    const e = new ApiError(403, 'no', 'authz.denied')
    const ask = vi.fn()
    await expect(withCrownConfirm(vi.fn().mockRejectedValue(e), ask)).rejects.toBe(e)
    expect(ask).not.toHaveBeenCalled()
    expect(isCrownError(e)).toBe(false)
  })
  it('dialogul: hosturile la acordare, hostul + numărul la mutare; danger', () => {
    const t = (k: string, v?: Record<string, string | number>) => k + JSON.stringify(v ?? {})
    const g = crownDialog(crown(), t)
    expect(g.message).toContain('gw01')
    expect(g.danger).toBe(true)
    const m = crownDialog(new ApiError(409, 'x', 'authz.crownJewelMove', { host: 'gw01', n: 3 }), t)
    expect(m.message).toContain('crown.confirmMove')
    expect(m.message).toContain('3')
  })
})

describe('tokenCap', () => {
  it('token vechi (fără role_id) → null', () => {
    expect(tokenCap({ role: '', role_id: null })).toBeNull()
  })
  it('rol predefinit / custom cu scope', () => {
    expect(tokenCap({ role: 'viewer', role_id: 4, role_name: 'Viewer', scope_kind: 'folder', scope_value: 'prod' }))
      .toEqual({ role: 'viewer', role_name: 'Viewer', scope_kind: 'folder', scope_value: 'prod' })
    expect(tokenCap({ role: '', role_id: 9, role_name: 'Runner' })?.role_name).toBe('Runner')
  })
})
