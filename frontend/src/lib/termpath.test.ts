import { describe, expect, it } from 'vitest'
import { baseName, looksLikePath, resolveTermPath } from './termpath'

describe('looksLikePath', () => {
  it('acceptă căi absolute, home şi relative pe un singur rând', () => {
    expect(looksLikePath('/etc/passwd')).toBe(true)
    expect(looksLikePath('  ~/notes.md  ')).toBe(true)   // trim înainte de verdict
    expect(looksLikePath('~')).toBe(true)
    expect(looksLikePath('./src/main.ts')).toBe(true)
  })
  it('respinge ce nu arată a cale sau nu e pe un rând', () => {
    expect(looksLikePath('')).toBe(false)
    expect(looksLikePath('   ')).toBe(false)             // doar spaţii
    expect(looksLikePath('rulează ./build apoi')).toBe(false)  // nu începe a cale
    expect(looksLikePath('/etc/passwd\n/etc/group')).toBe(false)  // două rânduri
    expect(looksLikePath('npm run build')).toBe(false)
    expect(looksLikePath('/' + 'a'.repeat(5000))).toBe(false)     // peste plafon
  })
})

describe('resolveTermPath', () => {
  it('lasă căile absolute neschimbate (doar fără „/” la coadă)', () => {
    expect(resolveTermPath('/var/log', '/home/u')).toBe('/var/log')
    expect(resolveTermPath('/var/log/', '/home/u')).toBe('/var/log')
    expect(resolveTermPath('/', '/home/u')).toBe('/')
  })
  it('nu atinge `~` (agentul îl expandează)', () => {
    expect(resolveTermPath('~', '/home/u')).toBe('~')
    expect(resolveTermPath('~/x/y', '/home/u')).toBe('~/x/y')
  })
  it('leagă căile relative de base', () => {
    expect(resolveTermPath('./src/a.ts', '/home/u/proj')).toBe('/home/u/proj/src/a.ts')
    expect(resolveTermPath('a.ts', '/home/u/proj/')).toBe('/home/u/proj/a.ts')
  })
})

describe('baseName', () => {
  it('întoarce ultimul segment', () => {
    expect(baseName('/a/b/c.txt')).toBe('c.txt')
    expect(baseName('/a/b/')).toBe('b')
    expect(baseName('file.txt')).toBe('file.txt')
    expect(baseName('~/notes.md')).toBe('notes.md')
  })
})
