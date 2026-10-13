import { describe, expect, it } from 'vitest'
import { ApiError, apiErrorFrom, errText, scalarVars } from './api'
import { clearDenied, errIsWriteDenied, isDenied, isSafeToType, isWriteDenied, markDenied, setfaclCommand, typeCommandInto, typeCommandOutcome } from './rootmove'
import { insertPathInto, registerInsertTarget, typeIntoOutcome } from './transfers'
import { isDefinitiveError } from './uploads'

const tr = (k: string, v?: Record<string, string | number>) => {
  const cat: Record<string, string> = {
    'err.files.writeDeniedMode': 'The agent runs as {user} and cannot write in {dir} (mode {mode}).',
    'err.files.failedReason': 'The file operation failed on the host: {reason}',
  }
  let s = cat[k] ?? k
  for (const [a, b] of Object.entries(v ?? {})) s = s.split('{' + a + '}').join(String(b))
  return s
}

describe('error bodies → ApiError with vars (3.6.9)', () => {
  it('reads code, detail and scalar vars from the JSON body', () => {
    const e = apiErrorFrom(400, JSON.stringify({ detail: '/srv/bin/lists/x: Permission denied', code: 'files.writeDeniedMode',
      vars: { user: 'webterm', dir: '/srv/bin/lists', mode: '755' } }), null)
    expect(e.code).toBe('files.writeDeniedMode')
    expect(errText(e, tr)).toBe('The agent runs as webterm and cannot write in /srv/bin/lists (mode 755).')
  })
  it('prefers the header code; a non-JSON body keeps the status as detail', () => {
    const e = apiErrorFrom(502, '<html>bad gateway</html>', 'host.offline')
    expect(e.code).toBe('host.offline')
    expect(e.message).toBe('502')
  })
  it('scalarVars drops structures, odd keys and over-long strings', () => {
    const v = scalarVars({ ok: 'x', n: 3, obj: { a: 1 }, arr: [1], 'bad key': 'y', __proto__x: 'z', long: 'a'.repeat(900), inf: Infinity })
    expect(v).toEqual({ ok: 'x', n: 3, long: 'a'.repeat(500) })
    expect(scalarVars(null)).toEqual({})
    expect(scalarVars([1, 2])).toEqual({})
  })
  it('caller vars override server vars; {reason} is filled', () => {
    const e = new ApiError(400, 'x', 'files.failedReason', { reason: 'Input/output error' })
    expect(errText(e, tr)).toBe('The file operation failed on the host: Input/output error')
  })
})

describe('definitive upload errors are not retried', () => {
  it('permission/read-only/no-space/missing/internal are definitive', () => {
    for (const c of ['files.writeDenied', 'files.writeDeniedMode', 'files.readOnlyAt', 'files.noSpaceAt', 'files.dirMissing', 'files.agentInternal'])
      expect(isDefinitiveError(new ApiError(400, 'x', c))).toBe(true)
  })
  it('timeouts, unknown failures and server errors are retried', () => {
    expect(isDefinitiveError(new ApiError(400, 'x', 'files.timeout'))).toBe(false)
    expect(isDefinitiveError(new ApiError(400, 'x', 'files.failedReason'))).toBe(false)
    expect(isDefinitiveError(new ApiError(502, 'x', 'files.writeDenied'))).toBe(false)
    expect(isDefinitiveError(new Error('400'))).toBe(false)
  })
})

describe('write-denied detection + learned folders', () => {
  it('recognises the denial codes', () => {
    expect(isWriteDenied('files.writeDeniedMode')).toBe(true)
    expect(isWriteDenied('files.permissionDenied')).toBe(true)
    expect(isWriteDenied('files.readOnlyAt')).toBe(false)
    expect(isWriteDenied(undefined)).toBe(false)
    expect(errIsWriteDenied(new ApiError(400, 'x', 'files.writeDenied'))).toBe(true)
  })
  it('remembers a denied folder per host until cleared', () => {
    markDenied(1, '/srv/bin/lists')
    expect(isDenied(1, '/srv/bin/lists')).toBe(true)
    expect(isDenied(2, '/srv/bin/lists')).toBe(false)
    clearDenied(1, '/srv/bin/lists')
    expect(isDenied(1, '/srv/bin/lists')).toBe(false)
  })
})

describe('setfacl command (copy only)', () => {
  it('quotes the folder and names the agent user', () => {
    expect(setfaclCommand('webterm', '/srv/bin/lists')).toBe('sudo setfacl -m u:webterm:rwx -- /srv/bin/lists')
    expect(setfaclCommand('webterm', "/srv/it's $(x)")).toBe(`sudo setfacl -m u:webterm:rwx -- '/srv/it'\\''s $(x)'`)
  })
  it('refuses a user name that is not a POSIX user name, a relative or control-char folder', () => {
    expect(setfaclCommand('web term', '/srv')).toBeNull()
    expect(setfaclCommand('$(id)', '/srv')).toBeNull()
    expect(setfaclCommand('', '/srv')).toBeNull()
    expect(setfaclCommand('webterm', 'srv')).toBeNull()
    expect(setfaclCommand('webterm', '/srv\nx')).toBeNull()
  })
})

describe('typing the move-as-root command (bracketed paste, prompts only)', () => {
  const cmd = "sudo sh -c 'u=$1 d=$2; shift 2' webterm-move webterm /srv/bin/lists /home/webterm/.webterm/inbox/x 4 " + 'a'.repeat(64) + " '/srv/bin/lists/a b'"
  const target = (typed: string[], bracketed: boolean | (() => boolean), ok = true) => ({
    send: (t: string) => { typed.push(t); return ok },
    bracketedPaste: typeof bracketed === 'function' ? bracketed : () => bracketed,
  })
  it('at a prompt that asked for bracketed paste: the command, wrapped in ESC[200~ … ESC[201~, no newline', () => {
    const typed: string[] = []
    registerInsertTarget('sid1', target(typed, true))
    expect(typeCommandInto('sid1', cmd)).toBe(true)
    expect(typed).toEqual(['\x1b[200~' + cmd + '\x1b[201~'])
    expect(typed[0]).not.toMatch(/[\r\n]/)
    registerInsertTarget('sid1', null)
  })
  it('bracketed paste OFF (mc, less, htop, a raw-mode program) → nothing typed, outcome notPrompt', () => {
    const typed: string[] = []
    registerInsertTarget('raw', target(typed, false))
    expect(typeCommandOutcome('raw', cmd)).toBe('notPrompt')
    expect(typeCommandInto('raw', cmd)).toBe(false)
    expect(insertPathInto('raw', '/home/webterm/x.png')).toBe(false)
    expect(typed).toEqual([])
    registerInsertTarget('raw', null)
  })
  it('foreground unknown (the mode cannot be read) → nothing typed', () => {
    const typed: string[] = []
    registerInsertTarget('unk', target(typed, () => { throw new Error('disposed') }))
    expect(typeIntoOutcome('unk', cmd)).toBe('notPrompt')
    expect(typed).toEqual([])
    registerInsertTarget('unk', null)
  })
  it('the path insert follows the same rule: wrapped at a prompt', () => {
    const typed: string[] = []
    registerInsertTarget('p', target(typed, true))
    expect(insertPathInto('p', "/home/webterm/it's.png")).toBe(true)
    expect(typed).toEqual(["\x1b[200~'/home/webterm/it'\\''s.png' \x1b[201~"])
    registerInsertTarget('p', null)
  })
  it('refuses control characters, ESC (bracketed-paste breakout), bidi and separators', () => {
    for (const bad of [cmd + '\r', cmd + '\n', cmd + '\x1b[201~', 'a\u202eb', 'a\u2028b', 'a\x00b', 'a\x9bb', ''])
      expect(isSafeToType(bad)).toBe(false)
    const typed: string[] = []
    registerInsertTarget('sid2', target(typed, true))
    expect(typeCommandOutcome('sid2', cmd + '\x1b[201~; id')).toBe('unsafe')
    expect(typeCommandInto('sid2', cmd + '\n')).toBe(false)
    expect(typed).toEqual([])
    // a path: shellQuote already strips control bytes, so the only ESCs typed are the brackets
    expect(insertPathInto('sid2', '/tmp/a\x1b[201~b')).toBe(true)
    expect(typed).toEqual(["\x1b[200~'/tmp/a[201~b' \x1b[201~"])
    registerInsertTarget('sid2', null)
  })
  it('a read-only / closed terminal types nothing (the target says no) → false', () => {
    registerInsertTarget('ro', target([], true, false))
    expect(typeCommandOutcome('ro', cmd)).toBe('refused')
    expect(typeCommandInto('ro', cmd)).toBe(false)
    registerInsertTarget('ro', null)
    expect(typeCommandOutcome('gone', cmd)).toBe('noTarget')
    expect(typeCommandInto(undefined, cmd)).toBe(false)
  })
})
