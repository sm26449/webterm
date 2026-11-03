export interface GitFile { path: string; index: string; work: string; untracked: boolean }
export interface RepoInfo { branch: string; ahead: number; behind: number; detached: boolean }

/** Porcelain v1 -z: literal UTF-8 paths; a rename has destination then source. */
export function parseGitStatus(out: string, t: (key: string) => string): { repo: RepoInfo; files: GitFile[] } {
  const repo: RepoInfo = { branch: '?', ahead: 0, behind: 0, detached: false }
  const files: GitFile[] = []
  const records = out.split('\0')
  for (let i = 0; i < records.length; i++) {
    const line = records[i]
    if (!line) continue
    if (line.startsWith('## ')) {
      const info = line.slice(3)
      if (info.startsWith('HEAD (no branch)')) { repo.detached = true; repo.branch = t('git.detachedHead'); continue }
      const initial = info.match(/^(?:No commits yet|Initial commit) on (.+)$/)
      if (initial) { repo.branch = initial[1]; continue }
      repo.branch = info.split('...')[0].split(' ')[0]
      const ahead = info.match(/ahead (\d+)/), behind = info.match(/behind (\d+)/)
      if (ahead) repo.ahead = +ahead[1]
      if (behind) repo.behind = +behind[1]
      continue
    }
    const index = line[0], work = line[1], path = line.slice(3)
    if (line.length < 4 || line[2] !== ' ') continue
    files.push({ path, index, work, untracked: index === '?' && work === '?' })
    if (index === 'R' || index === 'C' || work === 'R' || work === 'C') i++
  }
  return { repo, files }
}
