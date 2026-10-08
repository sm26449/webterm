import { describe, expect, it } from 'vitest'
import { lockTextKeys, stepupPrompt, unlockLabelKey } from './stepup'
import en from '../lang/en'
import ro from '../lang/ro'

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

describe('unlockLabelKey (3.5.15: eticheta butonului de deblocare)', () => {
  it('spune ce se va cere, nu mereu „passkey"', () => {
    expect(unlockLabelKey(stepupPrompt(null, 'passkey', true))).toBe('session.unlockWithPasskey')
    expect(unlockLabelKey(stepupPrompt(null, 'totp', true))).toBe('session.unlockWithTotp')
    expect(unlockLabelKey(stepupPrompt(null, 'sso', true))).toBe('session.unlockWithSso')
    expect(unlockLabelKey(stepupPrompt(null, 'none', true))).toBe('session.unlockNeedsFactor')
    // passkey fără WebAuthn (IP gol) → nu promitem un passkey
    expect(unlockLabelKey(stepupPrompt(null, 'passkey', false))).toBe('session.unlock')
  })
  it('codul ultimului refuz câştigă asupra metodei contului', () => {
    expect(unlockLabelKey(stepupPrompt('stepup.totp', 'passkey', true))).toBe('session.unlockWithTotp')
    expect(unlockLabelKey(stepupPrompt('host.needs2faSso', 'passkey', true))).toBe('session.unlockWithSso')
  })
  it('fiecare etichetă există în EN şi RO', () => {
    for (const k of ['passkey', 'totp', 'sso', 'needsFactor', 'password'] as const) {
      const key = unlockLabelKey(k)
      expect(en.strings[key], key).toBeTruthy()
      expect(ro.strings[key], key).toBeTruthy()
    }
  })
})
