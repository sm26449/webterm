import { describe, expect, it } from 'vitest'
import {
  applyPaneMove, dividers, dividerStyle, effectiveLayout, entryPane, equalSizes, findSameSet, fitGroup,
  gridSpec, isDistinct, LAYOUTS, layoutsFor, movePaneBy, nextDefaultName, normalizeSizes, nudge,
  pointerToCum, positionKeys, reorderPositions, setBoundary, SIZE_MAX, SIZE_MIN, sizeVars, type SplitLayout,
} from './splitLayout'

const ALL = Object.keys(LAYOUTS) as SplitLayout[]
const sum = (a: number[]) => a.reduce((x, y) => x + y, 0)

describe('forme', () => {
  it('fiecare formă are atâtea zone câte panouri şi atâtea dimensiuni câte cer grupurile', () => {
    for (const l of ALL) {
      expect(gridSpec(l).areas).toHaveLength(LAYOUTS[l].panes)
      expect(equalSizes(l)).toHaveLength(sum(LAYOUTS[l].groups))
      expect(positionKeys(l)).toHaveLength(LAYOUTS[l].panes)
    }
  })
  it('formele pentru n panouri; 3 panouri au trei variante', () => {
    expect(layoutsFor(2)).toEqual(['cols2'])
    expect(layoutsFor(3)).toEqual(['cols3', 'main-left', 'main-top'])
    expect(layoutsFor(4)).toEqual(['grid'])
  })
  it('forma efectivă: cerută dacă se potriveşte, altfel implicitul pe număr', () => {
    expect(effectiveLayout('cols3', 3)).toBe('cols3')
    expect(effectiveLayout('grid', 3)).toBe('main-left')
    expect(effectiveLayout('bogus', 2)).toBe('cols2')
    expect(effectiveLayout(undefined, 4)).toBe('grid')
  })
  it('zona fiecărui panou apare în template (fără celulă goală)', () => {
    for (const l of ALL) {
      const { template, areas } = gridSpec(l)
      const cells = template.replace(/"/g, '').split(/\s+/).filter(Boolean)
      expect(new Set(cells)).toEqual(new Set(areas))
    }
  })
})

describe('dimensiuni', () => {
  it('normalizeSizes: intrare invalidă → egale', () => {
    expect(normalizeSizes('cols2', null)).toEqual([0.5, 0.5])
    expect(normalizeSizes('cols2', [0.5])).toEqual([0.5, 0.5])
    expect(normalizeSizes('cols2', [0.7, 0.7])).toEqual([0.5, 0.5])           // suma 1.4
    expect(normalizeSizes('cols2', [Number.NaN, 0.5])).toEqual([0.5, 0.5])
    expect(normalizeSizes('grid', [0.6, 0.4, 0.3, 0.7])).toEqual([0.6, 0.4, 0.3, 0.7])
  })
  it('fitGroup: clamp + renormalizare, fiecare în [MIN, MAX], suma 1', () => {
    for (const g of [[0.05, 0.95], [0.05, 0.05, 0.9], [0.95, 0.03, 0.02].map((x) => x)]) {
      const f = fitGroup(g)
      expect(Math.abs(sum(f) - 1)).toBeLessThan(1e-3)
      for (const x of f) { expect(x).toBeGreaterThanOrEqual(SIZE_MIN - 1e-3); expect(x).toBeLessThanOrEqual(SIZE_MAX + 1e-3) }
    }
  })
  it('sizeVars: fracţii în fr + sume cumulate per grup', () => {
    const v = sizeVars('main-left', [0.6, 0.4, 0.3, 0.7])
    expect(v['--wt-s0']).toBe('0.6fr')
    expect(v['--wt-k0']).toBe('0.6')
    expect(v['--wt-k1']).toBe('1')
    expect(v['--wt-k2']).toBe('0.3')      // grupul al doilea începe de la 0
  })
})

describe('dividere', () => {
  it('cols3 are două dividere, main-left unul vertical + unul orizontal doar pe stivă', () => {
    expect(dividers('cols3').map((d) => [d.a, d.b])).toEqual([[0, 1], [1, 2]])
    const ml = dividers('main-left')
    expect(ml[0].orientation).toBe('vertical')
    expect(ml[1]).toMatchObject({ orientation: 'horizontal', a: 2, b: 3, crossFrom: 0 })
    const st = dividerStyle(ml[1])
    expect(st.left).toContain('var(--wt-k0)')       // începe după coloana mare
    expect(st.top).toContain('var(--wt-k2)')
  })
  it('setBoundary: mută doar perechea, suma ei se păstrează, fiecare ≥ MIN', () => {
    const d = dividers('cols3')[1]
    const s = setBoundary('cols3', [0.3, 0.3, 0.4], d, 0.95)
    expect(s[0]).toBe(0.3)
    expect(s[1] + s[2]).toBeCloseTo(0.7, 4)
    expect(s[2]).toBeCloseTo(SIZE_MIN, 4)
    const s2 = setBoundary('cols3', [0.3, 0.3, 0.4], d, -5)
    expect(s2[1]).toBeCloseTo(SIZE_MIN, 4)
    expect(setBoundary('cols3', [0.3, 0.3, 0.4], d, Number.NaN)).toEqual([0.3, 0.3, 0.4])
  })
  it('nudge: săgeţi ±2%, Home/End la capete', () => {
    const d = dividers('cols2')[0]
    expect(nudge('cols2', [0.5, 0.5], d, 'inc')).toEqual([0.52, 0.48])
    expect(nudge('cols2', [0.5, 0.5], d, 'dec')).toEqual([0.48, 0.52])
    expect(nudge('cols2', [0.5, 0.5], d, 'min')).toEqual([SIZE_MIN, SIZE_MAX])
    expect(nudge('cols2', [0.5, 0.5], d, 'max')).toEqual([SIZE_MAX, SIZE_MIN])
    // al doilea grup (rândurile grilei) — indexul cumulat porneşte de la începutul grupului
    const h = dividers('grid')[1]
    expect(nudge('grid', [0.5, 0.5, 0.5, 0.5], h, 'inc')).toEqual([0.5, 0.5, 0.52, 0.48])
  })
  it('pointerToCum scade golurile dintre piste', () => {
    const d = dividers('cols2')[0]
    // container 0..1006, un gol de 6 px: centrul golului la 503 → graniţa exact la jumătate
    expect(pointerToCum(d, 0, 1006, 503)).toBeCloseTo(0.5, 4)
  })
})

describe('mutări de panouri', () => {
  const P = ['a', 'b', 'c']
  it('swap', () => {
    expect(applyPaneMove(P, { kind: 'swap', from: 'a', to: 'c' })).toEqual(['c', 'b', 'a'])
    expect(applyPaneMove(P, { kind: 'swap', from: 'a', to: 'a' })).toBeNull()
    expect(applyPaneMove(P, { kind: 'swap', from: 'a', to: 'z' })).toBeNull()
  })
  it('replace cu o sesiune din afară → o înlocuieşte', () => {
    expect(applyPaneMove(P, { kind: 'replace', target: 'b', with: 'z' })).toEqual(['a', 'z', 'c'])
  })
  it('replace cu o sesiune care e DEJA panou → schimb, niciodată duplicat', () => {
    const out = applyPaneMove(P, { kind: 'replace', target: 'a', with: 'c' })
    expect(out).toEqual(['c', 'b', 'a'])
    expect(isDistinct(out!)).toBe(true)
    expect(applyPaneMove(P, { kind: 'replace', target: 'a', with: 'a' })).toBeNull()
  })
  it('o listă deja duplicată nu e „reparată" tăcut — mutarea e refuzată', () => {
    expect(applyPaneMove(['a', 'a', 'b'], { kind: 'swap', from: 'a', to: 'b' })).toBeNull()
  })
  it('movePaneBy: circular', () => {
    expect(movePaneBy(P, 'c', 1)).toEqual(['c', 'b', 'a'])
    expect(movePaneBy(P, 'a', -1)).toEqual(['c', 'b', 'a'])
    expect(movePaneBy(P, 'z', 1)).toBeNull()
  })
})

describe('intrare, nume, refolosire, ordine', () => {
  it('entryPane: ultimul focalizat dacă e încă panou, altfel primul', () => {
    expect(entryPane(['a', 'b'], 'b')).toBe('b')
    expect(entryPane(['a', 'b'], 'gone')).toBe('a')
    expect(entryPane([], null)).toBeNull()
  })
  it('nextDefaultName: primul număr liber, nu length+1', () => {
    const fmt = (n: number) => `Split ${n}`
    expect(nextDefaultName([], fmt)).toBe('Split 1')
    expect(nextDefaultName(['Split 1', 'Split 3'], fmt)).toBe('Split 2')
    expect(nextDefaultName(['Split 1', 'Split 2'], fmt)).toBe('Split 3')
  })
  it('findSameSet: aceleaşi sesiuni în orice ordine; nu unul cu panouri ascunse', () => {
    const v = [{ id: 1, panes: ['a', 'b'] }, { id: 2, panes: ['b', 'c'], hidden: 1 }]
    expect(findSameSet(v, ['b', 'a'])?.id).toBe(1)
    expect(findSameSet(v, ['c', 'b'])).toBeUndefined()
  })
  it('reorderPositions: trimite doar poziţiile schimbate (rândurile vechi au toate 0)', () => {
    const views = [{ id: 7, position: 0 }, { id: 8, position: 0 }, { id: 9, position: 0 }]
    const r = reorderPositions(views, 2, 0)
    expect(r.order.map((v) => v.id)).toEqual([9, 7, 8])
    expect(r.changed).toEqual([{ id: 7, position: 1 }, { id: 8, position: 2 }])
    expect(reorderPositions(views, 1, 1).changed).toEqual([])
  })
})
