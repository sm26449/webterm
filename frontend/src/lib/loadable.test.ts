import { describe, expect, it } from 'vitest'
import { canSave, isStale, loadFor, reloadLoad, settleLoad, startLoad, type Load } from './loadable'

type S = { id: string; host_id: number }
const A = [{ id: 'a1', host_id: 1 }]
const B = [{ id: 'b1', host_id: 2 }]

describe('loadable — date legate de identitate (U01)', () => {
  it('A → B: până soseşte răspunsul lui B nu se văd sesiunile lui A', () => {
    let s: Load<S[]> = settleLoad(startLoad<S[]>('1'), '1', { ok: true, data: A })
    // randarea dintre schimbarea hostului şi efectul care resetează
    expect(loadFor(s, '2')).toEqual({ status: 'loading', key: '2' })
    expect(loadFor(s, '2').data).toBeUndefined()
    s = startLoad('2')
    expect(s.data).toBeUndefined()
  })

  it('un răspuns întârziat pentru hostul vechi e ignorat', () => {
    const s = startLoad<S[]>('2')
    expect(settleLoad(s, '1', { ok: true, data: A })).toBe(s)
    expect(settleLoad(s, '1', { ok: false, error: 'x' })).toBe(s)
    expect(settleLoad(s, '2', { ok: true, data: B })).toEqual({ status: 'ok', key: '2', data: B })
  })

  it('eşecul la prima încărcare e eroare FĂRĂ date (nu o listă goală)', () => {
    const s = settleLoad(startLoad<S[]>('2'), '2', { ok: false, error: 'HTTP 502' })
    expect(s).toEqual({ status: 'error', key: '2', error: 'HTTP 502', data: undefined })
    expect(isStale(s)).toBe(false)
  })

  it('un refresh picat păstrează ultima listă bună a ACELEIAŞI chei, marcată veche', () => {
    const ok = settleLoad(startLoad<S[]>('2'), '2', { ok: true, data: B })
    const err = settleLoad(reloadLoad(ok), '2', { ok: false, error: 'timeout' })
    expect(err.status).toBe('error')
    expect(err.data).toEqual(B)
    expect(isStale(err)).toBe(true)
    // Reîncearcă: înapoi la ok, nu mai e veche
    const again = settleLoad(reloadLoad(err), '2', { ok: true, data: [] })
    expect(again).toEqual({ status: 'ok', key: '2', data: [] })
    expect(isStale(again)).toBe(false)
  })
})

describe('canSave — formularele din Setări (U04)', () => {
  it('se salvează doar peste valori încărcate', () => {
    expect(canSave({ status: 'ok' })).toBe(true)
    expect(canSave({ status: 'loading' })).toBe(false)
    expect(canSave({ status: 'error', error: 'HTTP 500' })).toBe(false)
  })
})
