import { afterEach, describe, expect, it, vi } from 'vitest'
import { acceptDrop, beginDrag, DRAG_MAX_MS, endDrag, ownDragKind } from './dragState'

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

  // re-review 3.6.12 (INFO): un drag fără onDragEnd (sursa demontată) nu rămâne valabil
  it('un drop / dragend oriunde în fereastră închide drag-ul', () => {
    const win = new EventTarget()
    vi.stubGlobal('window', win)
    try {
      beginDrag('pane', 's1')
      win.dispatchEvent(new Event('drop'))
      expect(acceptDrop('pane', 's1')).toBeNull()
      beginDrag('tab', 's2')
      win.dispatchEvent(new Event('dragend'))
      expect(ownDragKind()).toBeNull()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('un drag uitat expiră după DRAG_MAX_MS', () => {
    vi.useFakeTimers()
    try {
      beginDrag('pane', 's1')
      vi.advanceTimersByTime(DRAG_MAX_MS - 1)
      expect(acceptDrop('pane', 's1')).toBe('s1')
      vi.advanceTimersByTime(1)
      expect(acceptDrop('pane', 's1')).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })
})
