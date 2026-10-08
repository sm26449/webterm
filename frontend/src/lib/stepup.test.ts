import { describe, expect, it } from 'vitest'
import { lockTextKeys, stepupPrompt } from './stepup'

describe('stepupPrompt', () => {
  it('codul refuzului câştigă asupra metodei contului', () => {
    expect(stepupPrompt('stepup.needsFactor', 'passkey', true)).toBe('needsFactor')
    expect(stepupPrompt('stepup.totp', 'passkey', true)).toBe('totp')
    // re-auth pe o ţintă fără 2FA (deploy de cheie): parola, chiar dacă contul n-are factor
    expect(stepupPrompt('stepup.password', 'none', false)).toBe('password')
    expect(stepupPrompt('host.needs2faSso', 'none', false)).toBe('sso')
  })
  it('fără cod: decide din metoda contului', () => {
    expect(stepupPrompt(undefined, 'passkey', true)).toBe('passkey')
    expect(stepupPrompt('', 'totp', true)).toBe('totp')          // TOTP pe deploy cu WebAuthn
    expect(stepupPrompt(undefined, 'sso', false)).toBe('sso')
    expect(stepupPrompt(undefined, 'none', true)).toBe('needsFactor')
  })
  it('parola singură nu mai e propusă unui cont fără factor', () => {
    expect(stepupPrompt(undefined, 'none', false)).not.toBe('password')
  })
  it('gateway vechi (fără stepup_method): comportamentul de dinainte', () => {
    expect(stepupPrompt(undefined, undefined, true)).toBe('passkey')
    expect(stepupPrompt(undefined, null, false)).toBe('password')
  })
})

describe('lockTextKeys', () => {
  it('plafonul de 60 min are text propriu; restul rămân pe idle-lock', () => {
    expect(lockTextKeys('stepup_max').desc).toBe('session.lockedDescMax')
    expect(lockTextKeys('idle').title).toBe('session.lockedTitle')
    expect(lockTextKeys(undefined).desc).toBe('session.lockedDesc')
  })
})
