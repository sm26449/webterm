import { describe, expect, it } from 'vitest'
import { byText } from './sortText'

describe('byText', () => {
  it('ignores case and accents, sorts numbers naturally', () => {
    expect(['web-10', 'Zeta', 'alpha', 'web-2', 'Ştefan', 'beta'].sort(byText))
      .toEqual(['alpha', 'beta', 'Ştefan', 'web-2', 'web-10', 'Zeta'])
  })
  it('is a total order: equal-looking strings keep a stable, deterministic order', () => {
    expect(['B', 'b', 'B'].sort(byText)).toEqual(['B', 'B', 'b'])
  })
})
