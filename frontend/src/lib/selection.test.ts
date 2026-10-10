import { describe, expect, it } from 'vitest'
import {
  EMPTY_SELECTION, Selection, allState, isListKeyTarget, previewNames, prune, rangeTo, toggleAll, toggleKey, visibleSelected,
} from './selection'

const order = ['a', 'b', 'c', 'd', 'e']
const keys = (s: Selection) => [...s.keys].sort()

describe('toggle (Ctrl/Cmd+click, Space, bifa)', () => {
  it('adaugă, apoi scoate; rândul atins devine ancoră', () => {
    let s = toggleKey(EMPTY_SELECTION, 'b')
    expect(keys(s)).toEqual(['b'])
    expect(s.anchor).toBe('b')
    s = toggleKey(s, 'd')
    expect(keys(s)).toEqual(['b', 'd'])
    s = toggleKey(s, 'b')
    expect(keys(s)).toEqual(['d'])
    expect(s.anchor).toBe('b')
  })
  it('nu mută starea veche (imuabil — React compară referinţe)', () => {
    const s0 = toggleKey(EMPTY_SELECTION, 'a')
    toggleKey(s0, 'b')
    expect(keys(s0)).toEqual(['a'])
  })
})

describe('interval (Shift+click / Shift+săgeţi)', () => {
  it('de la ancoră la rândul ţintă, în ambele sensuri', () => {
    const s = toggleKey(EMPTY_SELECTION, 'b')
    expect(keys(rangeTo(s, order, 'd'))).toEqual(['b', 'c', 'd'])
    const up = toggleKey(EMPTY_SELECTION, 'd')
    expect(keys(rangeTo(up, order, 'a'))).toEqual(['a', 'b', 'c', 'd'])
  })
  it('ancora rămâne fixă: al doilea Shift+click recalculează de la ea (nu cumulează)', () => {
    let s = toggleKey(EMPTY_SELECTION, 'b')
    s = rangeTo(s, order, 'e')
    s = rangeTo(s, order, 'c')
    expect(keys(s)).toEqual(['b', 'c'])
    expect(s.anchor).toBe('b')
  })
  it('Ctrl+Shift adaugă intervalul la selecţia existentă', () => {
    let s = toggleKey(EMPTY_SELECTION, 'a')
    s = toggleKey(s, 'd')
    s = rangeTo(s, order, 'e', true)
    expect(keys(s)).toEqual(['a', 'd', 'e'])
  })
  it('fără ancoră (sau ancora ascunsă de filtru) = doar rândul ţintă', () => {
    expect(keys(rangeTo(EMPTY_SELECTION, order, 'c'))).toEqual(['c'])
    const hidden: Selection = { keys: new Set(['zz']), anchor: 'zz' }
    expect(keys(rangeTo(hidden, order, 'c'))).toEqual(['c'])
  })
  it('intervalul urmează ORDINEA VIZIBILĂ (după filtru/sortare), nu ordinea alfabetică', () => {
    const filtered = ['e', 'c', 'a']           // sortare inversă, b/d ascunse de filtru
    const s = toggleKey(EMPTY_SELECTION, 'e')
    expect(keys(rangeTo(s, filtered, 'a'))).toEqual(['a', 'c', 'e'])
  })
  it('ţintă inexistentă în ordine → selecţia neschimbată', () => {
    const s = toggleKey(EMPTY_SELECTION, 'a')
    expect(rangeTo(s, order, 'nope')).toBe(s)
  })
})

describe('Selectează tot (respectă filtrul)', () => {
  it('selectează doar ce se vede; a doua apăsare deselectează exact acele rânduri', () => {
    const visible = ['b', 'd']
    let s = toggleKey(EMPTY_SELECTION, 'a')             // „a" e ascuns acum de filtru
    s = toggleAll(s, visible)
    expect(keys(s)).toEqual(['a', 'b', 'd'])
    expect(allState(s, visible)).toBe('all')
    s = toggleAll(s, visible)
    expect(keys(s)).toEqual(['a'])                      // ascunsul nu e atins
    expect(allState(s, visible)).toBe('none')
  })
  it('stare tri-state: none / some / all', () => {
    const s = toggleKey(EMPTY_SELECTION, 'a')
    expect(allState(s, order)).toBe('some')
    expect(allState(EMPTY_SELECTION, order)).toBe('none')
    expect(allState(toggleAll(EMPTY_SELECTION, order), order)).toBe('all')
  })
  it('listă vizibilă goală: nimic de selectat', () => {
    expect(keys(toggleAll(EMPTY_SELECTION, []))).toEqual([])
  })
  it('acţiunile în bloc primesc DOAR rândurile selectate şi vizibile, în ordinea afişată', () => {
    const s: Selection = { keys: new Set(['e', 'a', 'hidden']), anchor: null }
    expect(visibleSelected(s, ['e', 'c', 'a'])).toEqual(['e', 'a'])
  })
})

describe('re-listare + previzualizare', () => {
  it('prune scoate cheile dispărute şi ancora lor; fără schimbări = acelaşi obiect', () => {
    const s: Selection = { keys: new Set(['a', 'b']), anchor: 'b' }
    const p = prune(s, ['a', 'c'])
    expect(keys(p)).toEqual(['a'])
    expect(p.anchor).toBeNull()
    expect(prune(s, order)).toBe(s)
  })
  it('previewNames: primele n + câte mai sunt', () => {
    expect(previewNames(['a', 'b', 'c'], 5)).toEqual({ shown: ['a', 'b', 'c'], more: 0 })
    expect(previewNames(['a', 'b', 'c', 'd', 'e', 'f', 'g'], 5)).toEqual({ shown: ['a', 'b', 'c', 'd', 'e'], more: 2 })
  })
})

describe('isListKeyTarget (U09)', () => {
  it('tastele de navigare se aplică doar de pe containerul listei, nu de pe un descendent focalizat', () => {
    const list = { id: 'list' }
    const deleteBtn = { id: 'delete' }
    const checkbox = { id: 'checkbox' }
    expect(isListKeyTarget(list, list)).toBe(true)
    // Enter pe „Şterge" / Space pe bifă: le tratează controlul, nu lista (nu deschide view[sel])
    expect(isListKeyTarget(deleteBtn, list)).toBe(false)
    expect(isListKeyTarget(checkbox, list)).toBe(false)
  })
})
