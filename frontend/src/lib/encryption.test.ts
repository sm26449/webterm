/* 3.8: logica panoului Owner „Encryption at rest" şi a acţiunii „Erase permanently". */
import { describe, expect, it, vi } from 'vitest'
import { ApiError, withFreshFactor } from './api'
import {
  canErase, conflictWord, destState, destTone, eraseWord, isEncryptionOwner, migrationPercent,
  protectionView, recompactionPercent, recoveryWord, typedMatches, utcDate,
  type EraseDestination, type QuarantineItem,
} from './encryption'
import type { MyPerms } from './perms'

const perms = (o: Partial<MyPerms>): MyPerms => ({
  global: [], all_hosts: [], hosts: {}, bindings: [], owner: false, epoch: 1, has_admins: true, ...o,
})
const OWNER = perms({ owner: true, global: ['backups.manage'] })
const SID = '0123456789abcdef0123456789abcdef'
const rec = (o: object = {}) => ({ sid: SID, kinds: { out: 'ok' }, encrypted: true, tombstoned: false, ...o })

describe('cine vede acţiunile (cosmetic; serverul decide)', () => {
  it('doar Owner cu backups.manage; nimic cât permisiunile nu s-au încărcat', () => {
    expect(isEncryptionOwner(null)).toBe(false)
    expect(isEncryptionOwner(perms({ global: ['backups.manage'] }))).toBe(false)
    expect(isEncryptionOwner(perms({ owner: true }))).toBe(false)
    expect(isEncryptionOwner(OWNER)).toBe(true)
  })
  it('Erase permanently: sesiune închisă, înregistrare criptată, încă neştearsă', () => {
    expect(canErase(OWNER, rec(), false, SID)).toBe(true)
    expect(canErase(OWNER, rec(), true, SID)).toBe(false)
    expect(canErase(OWNER, rec({ encrypted: false }), false, SID)).toBe(false)
    expect(canErase(OWNER, rec({ tombstoned: true }), false, SID)).toBe(false)
    expect(canErase(OWNER, null, false, SID)).toBe(false)
    expect(canErase(OWNER, rec({ sid: 'ffffffff-other' }), false, SID)).toBe(false)
    expect(canErase(perms({ global: ['backups.manage'] }), rec(), false, SID)).toBe(false)
  })
})

describe('starea afişată', () => {
  it('protecţia volumului', () => {
    expect(protectionView({ mode: '', source: null })).toEqual({ tone: 'neutral', key: 'enc.protection.unknown' })
    expect(protectionView({ mode: 'legacy', source: null }).key).toBe('enc.protection.legacy')
    expect(protectionView({ mode: 'reduced', source: 'volume' }).tone).toBe('warn')
    expect(protectionView({ mode: 'protected', source: 'env' }).key).toBe('enc.protection.env')
    expect(protectionView({ mode: 'protected', source: 'file' })).toEqual({ tone: 'ok', key: 'enc.protection.protected' })
  })
  it('procentele migrării şi recompactării (nimic de făcut = 100)', () => {
    expect(migrationPercent({ done: 0, total: 0 })).toBe(100)
    expect(migrationPercent({ done: 1, total: 3 })).toBe(33)
    expect(migrationPercent(null)).toBe(100)
    expect(recompactionPercent({ done: 3, left: 1 })).toBe(75)
    expect(recompactionPercent({ done: 0, left: 0 })).toBe(100)
  })
  it('starea unei destinaţii, de la cea mai gravă', () => {
    const d = (o: Partial<EraseDestination>): EraseDestination => ({
      id: 'sftp:u@h:22/x', configured: true, required: false, attested_n: 3, attested_time: 1, state: 'ok',
      since: null, error: '', behind: false, rolled_back: false, ahead: null, retirable: false, ...o,
    })
    expect(destState(d({}))).toBe('attested')
    expect(destState(d({ behind: true }))).toBe('behind')
    expect(destState(d({ state: 'missing', behind: true }))).toBe('missing')
    expect(destState(d({ state: 'failing', error: 'timeout' }))).toBe('failing')
    expect(destState(d({ ahead: 9 }))).toBe('ahead')
    expect(destState(d({ rolled_back: true, ahead: 9 }))).toBe('rolledBack')
    expect(destState(d({ configured: false, attested_n: 0, behind: true }))).toBe('none')
    expect(destState(d({ configured: false, required: true, attested_n: 0, behind: false }))).toBe('none')
    expect(destState(d({ attested_n: 0, behind: true }))).toBe('behind')
    expect(destTone('rolledBack')).toBe('danger')
    expect(destTone('attested')).toBe('ok')
  })
})

describe('confirmările tastate (aceleaşi ca pe server)', () => {
  it('ştergere / discard: primele 8 caractere', () => {
    expect(eraseWord(SID)).toBe('01234567')
    expect(typedMatches('  01234567 ', eraseWord(SID))).toBe(true)
    expect(typedMatches('0123456', eraseWord(SID))).toBe(false)
  })
  it('recuperare: data backup-ului (UTC) sau „<sid8> <diagnostic>"', () => {
    const item = (o: Partial<QuarantineItem>): QuarantineItem => ({
      sid: SID, kinds: ['out'], status: 'quarantined', reason: 'continuity', since: 1, recoverable: true,
      recovery: 'continuity', ...o,
    })
    const q = { continuity: { state: 'unproven', since: 86400 * 365, n: 3 } }
    expect(utcDate(86400 * 365)).toBe('1971-01-01')
    expect(recoveryWord(item({}), q)).toBe('1971-01-01')
    expect(recoveryWord(item({ recovery: 'journal', confirm_word: 'rollback' }), q)).toBe('01234567 rollback')
    expect(typedMatches('01234567   rollback', '01234567 rollback')).toBe(true)
    expect(recoveryWord(item({ recoverable: false }), q)).toBeNull()
    expect(recoveryWord(item({}), { continuity: null })).toBeNull()
  })
  it('conflict: „<n> <primele 16 ale MAC-ului>"', () => {
    expect(conflictWord({ n: 7, mac: 'ABCDEF0123456789'.repeat(4) })).toBe('7 abcdef0123456789')
  })
})

describe('withFreshFactor: factorul REAL proaspăt în corpul cererii', () => {
  const refusal = (code: string) => new ApiError(403, 'factor', code)
  it('fără refuz: o singură cerere, fără ceremonie', async () => {
    const send = vi.fn().mockResolvedValue('ok')
    const credential = vi.fn()
    expect(await withFreshFactor(5, send, { credential })).toBe('ok')
    expect(send).toHaveBeenCalledTimes(1)
    expect(credential).not.toHaveBeenCalled()
  })
  it('stepup.passkey → ceremonia pentru hostul cerut, apoi o reîncercare cu grantul în corp', async () => {
    const send = vi.fn().mockRejectedValueOnce(refusal('stepup.passkey')).mockResolvedValueOnce('done')
    const credential = vi.fn().mockResolvedValue({ stepup_grant: 'g1' })
    expect(await withFreshFactor(0, send, { credential })).toBe('done')
    expect(credential).toHaveBeenCalledWith(0, 'stepup.passkey')
    expect(send).toHaveBeenLastCalledWith({ stepup_grant: 'g1' })
  })
  it('ceremonie anulată → null, fără a doua cerere', async () => {
    const send = vi.fn().mockRejectedValue(refusal('stepup.totp'))
    expect(await withFreshFactor(3, send, { credential: async () => null })).toBeNull()
    expect(send).toHaveBeenCalledTimes(1)
  })
  it('SSO (direct sau abia la reîncercare) → redirect la IdP pentru hostul cerut, null', async () => {
    const redirect = vi.fn()
    expect(await withFreshFactor(4, vi.fn().mockRejectedValue(refusal('host.needs2faSso')), { redirect })).toBeNull()
    expect(redirect).toHaveBeenCalledWith(4)
    const send = vi.fn().mockRejectedValueOnce(refusal('stepup.passkey')).mockRejectedValueOnce(refusal('host.needs2faSso'))
    expect(await withFreshFactor(0, send, { credential: async () => ({}), redirect })).toBeNull()
    expect(redirect).toHaveBeenLastCalledWith(0)
  })
  it('orice altă eroare trece mai departe (inclusiv un factor greşit la reîncercare)', async () => {
    await expect(withFreshFactor(1, vi.fn().mockRejectedValue(new ApiError(409, 'live', 'session.live')),
      { credential: vi.fn() })).rejects.toMatchObject({ code: 'session.live' })
    const send = vi.fn().mockRejectedValueOnce(refusal('stepup.totp')).mockRejectedValueOnce(refusal('stepup.totp'))
    await expect(withFreshFactor(1, send, { credential: async () => ({ stepup_totp: '000000' }) }))
      .rejects.toMatchObject({ code: 'stepup.totp' })
  })
  it('fără ceremonie înregistrată: refuzul serverului rămâne eroarea', async () => {
    await expect(withFreshFactor(1, vi.fn().mockRejectedValue(refusal('stepup.passkey'))))
      .rejects.toMatchObject({ code: 'stepup.passkey' })
  })
})
