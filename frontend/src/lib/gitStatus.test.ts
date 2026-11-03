import { describe, expect, it } from 'vitest'
import { parseGitStatus } from './gitStatus'
const t = (s: string) => s

describe('Git porcelain -z', () => {
  it('keeps paths literal, including unicode, quotes, arrows, tabs and newlines', () => {
    const path = 'sub/ă space -> "quoted"\n\tfile.txt'
    const r = parseGitStatus('## main...origin/main [ahead 2, behind 3]\0 M ' + path + '\0', t)
    expect(r.repo).toEqual({ branch: 'main', ahead: 2, behind: 3, detached: false })
    expect(r.files).toEqual([{ path, index: ' ', work: 'M', untracked: false }])
  })
  it('uses rename destination and consumes the source record', () => {
    const r = parseGitStatus('## main\0R  new -> name.txt\0old\nname.txt\0?? next.txt\0', t)
    expect(r.files.map((f) => f.path)).toEqual(['new -> name.txt', 'next.txt'])
    expect(r.files[1].untracked).toBe(true)
  })
  it('handles an unborn branch and detached HEAD', () => {
    expect(parseGitStatus('## No commits yet on main\0', t).repo.branch).toBe('main')
    expect(parseGitStatus('## HEAD (no branch)\0', t).repo.detached).toBe(true)
  })
})
