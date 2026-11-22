import { describe, expect, it } from 'vitest'
import type { Session } from './api'
import { noticeKey, parseDays, pendingIdleNotices } from './idleSessions'

const base: Session = {
  id: 'a', host_id: 1, title: 't', note: '', state: 'live', created: 0, closed_at: null, exit_status: null,
  close_reason: null, rows: 24, cols: 80, connected_clients: 0, out_offset: 0, created_by_id: 7,
}

describe('idle session notices', () => {
  const notified = { ...base, idle_notice: { at: 1000.4, days: 7 } }

  it('keys a notice by session and time', () => {
    expect(noticeKey(notified)).toBe('a@1000')
    expect(noticeKey(base)).toBeNull()
  })

  it('toasts only my own live, not-kept sessions, once', () => {
    expect(pendingIdleNotices([notified], 7, new Set())).toHaveLength(1)
    expect(pendingIdleNotices([notified], 8, new Set())).toHaveLength(0)
    expect(pendingIdleNotices([notified], null, new Set())).toHaveLength(0)
    expect(pendingIdleNotices([{ ...notified, keep_open: true }], 7, new Set())).toHaveLength(0)
    expect(pendingIdleNotices([{ ...notified, state: 'closed' }], 7, new Set())).toHaveLength(0)
    expect(pendingIdleNotices([notified], 7, new Set(['a@1000']))).toHaveLength(0)
    expect(pendingIdleNotices([base], 7, new Set())).toHaveLength(0)
  })

  it('parses day counts inside the bounds only', () => {
    expect(parseDays('7', 1, 90)).toBe(7)
    expect(parseDays(' 30 ', 1, 30)).toBe(30)
    expect(parseDays('0', 1, 90)).toBeNull()
    expect(parseDays('91', 1, 90)).toBeNull()
    expect(parseDays('2.5', 1, 90)).toBeNull()
    expect(parseDays('', 1, 90)).toBeNull()
  })
})
