import { describe, expect, it } from 'vitest'
import { upsertToast } from './notify'

type T = { id: string; key?: string; message: string }

describe('upsertToast (un paste = un toast, actualizat pe loc — 3.6.16)', () => {
  it('fără cheie: se adaugă la final', () => {
    const l: T[] = [{ id: '1', message: 'a' }]
    expect(upsertToast(l, { id: '2', message: 'b' }).map((x) => x.id)).toEqual(['1', '2'])
  })
  it('aceeaşi cheie: înlocuit în acelaşi loc, cu id nou (temporizatorul vechi nu-l mai închide)', () => {
    const l: T[] = [{ id: '1', key: 'p', message: 'Uploading…' }, { id: '2', message: 'other' }]
    const n = upsertToast(l, { id: '3', key: 'p', message: 'Saved' })
    expect(n.map((x) => [x.id, x.message])).toEqual([['3', 'Saved'], ['2', 'other']])
    expect(l[0].message).toBe('Uploading…')     // lista veche neatinsă (imuabil)
  })
  it('cheie nouă: se adaugă', () => {
    const l: T[] = [{ id: '1', key: 'p1', message: 'a' }]
    expect(upsertToast(l, { id: '2', key: 'p2', message: 'b' })).toHaveLength(2)
  })
})
