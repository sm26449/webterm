import { afterEach, describe, expect, it } from 'vitest'
import { acceptDrop, beginDrag, endDrag, ownDragKind } from './dragState'

// review independent 3.6.12 (L3): tipurile application/x-wt-pane / x-wt-session pot fi puse pe un
// drag de ORICE pagină (sau alt tab WebTerm), cu un sid ales de ea — acceptăm doar drag-ul nostru.
describe('dragState', () => {
  afterEach(() => endDrag())

  it('fără drag pornit în pagină: orice payload e refuzat', () => {
    expect(ownDragKind()).toBeNull()
    expect(acceptDrop('pane', 'abc')).toBeNull()
    expect(acceptDrop('tab', 'abc')).toBeNull()
  })

  it('drag-ul nostru: payload-ul tras e acceptat', () => {
    beginDrag('tab', 's1')
    expect(ownDragKind()).toBe('tab')
    expect(acceptDrop('tab', 's1')).toBe('s1')
  })

  it('alt tip sau alt sid decât cel tras → refuzat', () => {
    beginDrag('pane', 's1')
    expect(acceptDrop('tab', 's1')).toBeNull()
    expect(acceptDrop('pane', 's2')).toBeNull()
    expect(acceptDrop('pane', '')).toBeNull()
  })

  it('după dragend nu mai acceptă nimic', () => {
    beginDrag('pane', 's1')
    endDrag()
    expect(acceptDrop('pane', 's1')).toBeNull()
  })
})
