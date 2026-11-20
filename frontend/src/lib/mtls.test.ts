import { describe, expect, it } from 'vitest'
import { mtlsDaysLeft, mtlsExpiringSoon, mtlsState } from './mtls'

describe('agent mTLS state (3.7.0)', () => {
  const now = 1_900_000_000
  it('names the three states', () => {
    expect(mtlsState(null)).toBe('none')
    expect(mtlsState({ required: false, last: null, not_after: null, issued: false })).toBe('none')
    expect(mtlsState({ required: false, last: null, not_after: now + 1, issued: true })).toBe('issued')
    expect(mtlsState({ required: true, last: now, not_after: now + 1, issued: true })).toBe('required')
  })
  it('counts days left and flags a certificate that did not renew', () => {
    const m = { required: true, last: now, not_after: now + 40 * 86400, issued: true }
    expect(mtlsDaysLeft(m, now)).toBe(40)
    expect(mtlsExpiringSoon(m, now)).toBe(false)
    expect(mtlsExpiringSoon({ ...m, not_after: now + 10 * 86400 }, now)).toBe(true)
    expect(mtlsDaysLeft(null, now)).toBeNull()
  })
})
