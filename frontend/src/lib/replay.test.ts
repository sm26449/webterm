import { describe, expect, it } from 'vitest'
import { expiryKey, parseCast, REPLAY_DEFAULT_EXPIRY, REPLAY_EXPIRY_HOURS, replayHeaders, replayTokenFromHash } from './replay'
import en from '../lang/en'
import ro from '../lang/ro'

describe('replayTokenFromHash', () => {
  const tok = 'Ab_-0123456789abcdefghijklmnopqrstuvwxyzABC'
  it('reads the token from the fragment route', () => {
    expect(replayTokenFromHash(`#/replay/${tok}`)).toBe(tok)
  })
  it('rejects other routes, short tokens and extra path segments', () => {
    expect(replayTokenFromHash(`#/shared/${tok}`)).toBeNull()
    expect(replayTokenFromHash('#/replay/abc')).toBeNull()
    expect(replayTokenFromHash(`#/replay/${tok}/x`)).toBeNull()
    expect(replayTokenFromHash(`#/replay/${tok}?a=1`)).toBeNull()
    expect(replayTokenFromHash('')).toBeNull()
  })
})

describe('replay API helpers', () => {
  it('sends the token in a header, not in the URL', () => {
    expect(replayHeaders('t0k')).toEqual({ 'X-Replay-Token': 't0k' })
  })
  it('offers exactly 1 h / 24 h / 7 days, default 24 h', () => {
    expect([...REPLAY_EXPIRY_HOURS]).toEqual([1, 24, 168])
    expect(REPLAY_DEFAULT_EXPIRY).toBe(24)
  })
  it.each([...REPLAY_EXPIRY_HOURS])('expiry %i h has a label in en and ro', (h) => {
    expect(en.strings[expiryKey(h)]).toBeTruthy()
    expect(ro.strings[expiryKey(h)]).toBeTruthy()
  })
})

describe('parseCast', () => {
  it('skips the header and corrupt lines, keeps events in order', () => {
    const text = [
      JSON.stringify({ version: 2, width: 80, height: 24 }),
      JSON.stringify([0.1, 'o', 'a']),
      'not json',
      JSON.stringify([0.2, 'r', '100x30']),
      JSON.stringify(['x', 'o', 'bad time']),
      JSON.stringify([0.3, 'o', 'b']),
      '',
    ].join('\n')
    expect(parseCast(text)).toEqual([[0.1, 'o', 'a'], [0.2, 'r', '100x30'], [0.3, 'o', 'b']])
  })
  it('returns nothing for an empty recording', () => {
    expect(parseCast('')).toEqual([])
  })
})
