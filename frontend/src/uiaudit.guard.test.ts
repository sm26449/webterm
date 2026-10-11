/* Garda auditului UI extern (3.6.1). Regresiile pe care tsc/eslint nu le văd şi pe care e2e-ul de
   cale fericită nu le atinge: o eroare de încărcare înghiţită (`.catch(() => {})` → listă goală /
   valori implicite afişate ca setări), contrastul CTA-ului de rulare pe flotă, tokenul --viz-warn.
   Citeşte sursele ca text (fără jsdom) — logica propriu-zisă e testată în lib/*.test.ts. */
import { describe, expect, it } from 'vitest'

const src = import.meta.glob(['./components/**/*.tsx', './components/settings/ui.ts', './index.css', './App.tsx'], {
  query: '?raw', import: 'default', eager: true,
}) as Record<string, string>
const file = (p: string) => {
  const s = src[p]
  if (s === undefined) throw new Error(`lipseşte ${p}`)
  return s
}

// Fişierele în care un fetch de LISTĂ sau de FORMULAR picat era înghiţit. Aici nu mai are voie
// niciun `.catch(() => {})` — eşecul are starea lui (ErrorState + Reîncearcă / NotLoaded).
const NO_SWALLOW = [
  './components/HostOverview.tsx',
  './components/ServicesPanel.tsx',
  './components/SnippetsMenu.tsx',
  './components/HostsCsv.tsx',
  './components/settings/SignInTab.tsx',
  './components/settings/NotificationsTab.tsx',
  './components/settings/AppearanceTab.tsx',
  './components/settings/InfrastructureTab.tsx',
  './components/settings/UsersTab.tsx',
  './components/settings/PreferencesTab.tsx',
  // 3.6.3: aplicaţiile de pe dashboard, versiunea din Status
  './components/Dashboard.tsx',
  './components/StatusModal.tsx',
]

describe('audit UI 3.6.1 — eroare ≠ gol', () => {
  it.each(NO_SWALLOW)('%s nu înghite erori de încărcare', (p) => {
    expect(file(p)).not.toMatch(/\.catch\(\(\)\s*=>\s*\{\s*\}\)/)
    expect(file(p)).not.toMatch(/\.catch\(\(\)\s*=>\s*\[\]/)
  })

  it('SignInTab: avertismentul de blocare nu e sărit când lista de hosturi nu se încarcă (fail-safe)', () => {
    expect(file('./components/settings/SignInTab.tsx')).toMatch(/hosts === null \|\| hosts\.some\(\(h\) => h\.require_2fa\)/)
  })

  it('formularele de securitate se salvează doar peste valori încărcate (guardrail, chei de deploy, watermark, SMTP)', () => {
    const infra = file('./components/settings/InfrastructureTab.tsx')
    expect(infra).toMatch(/saveGuard = async \(\) => \{\s*if \(!canSave\(guardState\)\) return/)
    expect(infra).toMatch(/saveDkPolicy = async \(next: DeployKeyPolicy\) => \{\s*if \(!canSave\(dkState\)\) return/)
    expect(file('./components/settings/AppearanceTab.tsx')).toMatch(/if \(!canSave\(wmState\)\) return/)
    expect(file('./components/settings/NotificationsTab.tsx')).toMatch(/if \(!canSave\(smtpState\)\) throw/)
  })
})

describe('audit UI 3.6.1 — contrast şi siguranţă', () => {
  it('U06: CTA-ul „Rulează pe N hosturi" e Button primary, nu amber-500 + text ink-950 (1,88:1)', () => {
    const f = file('./components/FleetRunModal.tsx')
    expect(f).not.toContain('bg-amber-500 px-4 py-1.5 text-sm font-semibold text-ink-950')
    expect(f).toMatch(/<Button variant="primary" type="button" loading=\{checking\}/)
  })

  it('U07: comenzile salvate nu folosesc hover:text-white (1,14:1 pe Aurora)', () => {
    expect(file('./components/FleetRunModal.tsx')).not.toContain('hover:text-white')
  })

  it('U02/U05: „Rulează" trece prin garda de re-intrare; închiderea cu comenzi în curs cere confirmare', () => {
    const f = file('./components/FleetRunModal.tsx')
    expect(f).toContain('exclusive(runFlag, dispatch, setChecking)')
    expect(f).toContain("t('fleet.closeRunningMsg')")
    expect(f).not.toMatch(/useFocusTrap\(dialogRef, props\.onClose\)/)
  })

  it('U08: --viz-warn Aurora = #b45309 în :root ŞI în suprascrierea .wt-canvas; Midnight neschimbat', () => {
    const css = file('./index.css')
    const warn = [...css.matchAll(/--viz-warn:\s*([\d ]+);/g)].map((m) => m[1].trim())
    expect(warn.filter((v) => v === '180 83 9')).toHaveLength(2)
    expect(warn).not.toContain('217 119 6')
    expect(warn.filter((v) => v === '251 191 36').length).toBeGreaterThanOrEqual(2)
  })

  it('U14: riscul linkului scriptibil e text vizibil; expirarea nu mai e ascunsă sub `sm`', () => {
    const f = file('./components/SessionView.tsx')
    expect(f).toContain("t('session.writableRisk')")
    expect(f).not.toContain('hidden shrink-0 text-2xs text-slate-500 sm:inline')
  })

  it('U12: walkthrough-ul nu mai are 7 butoane-punct; cardul are înălţime maximă şi scroll propriu', () => {
    const f = file('./components/Walkthrough.tsx')
    expect(f).not.toMatch(/onClick=\{\(\) => go\(i\)\}/)
    expect(f).toContain('max-h-[calc(100dvh-2rem)]')
  })

  it('U10: paleta foloseşte tiparul combobox + listbox cu aria-activedescendant', () => {
    const f = file('./components/CommandPalette.tsx')
    expect(f).toContain('role="combobox"')
    expect(f).toContain('aria-activedescendant=')
    expect(f).toContain('role="listbox"')
  })
})

describe('finisaje UI 3.6.3', () => {
  it('ştergerea unei sesiuni nu mai înghite eşecul; HostOverview readuce rândul şi arată eroarea', () => {
    const app = file('./App.tsx')
    expect(app).not.toMatch(/api\(`\/api\/sessions\/\$\{sid\}`, \{ method: 'DELETE' \}\)\.catch/)
    const ho = file('./components/HostOverview.tsx')
    expect(ho).toContain('await props.onDeleteSession(sid)')
    expect(ho).toContain('data-testid="session-delete-error"')
  })

  it('Status: eşecul verificării de versiune e afişat cu Reîncearcă, nu tăcere', () => {
    const f = file('./components/StatusModal.tsx')
    expect(f).toContain("t('status.versionLoadFailed')")
    expect(f).toContain('onClick={loadVer}')
  })

  it('U19: după înrolare — „Deschide primul terminal" (agent online) / „Conectează-te acum" (SSH)', () => {
    const f = file('./components/AddHostModal.tsx')
    expect(f).toContain("t('addhost.openFirstTerminal')")
    expect(f).toContain("t('addhost.connectNow')")
    expect(file('./components/Sidebar.tsx')).toMatch(/onOpenSession=\{\(h\) => \{ setShowAdd\(false\)/)
  })

  it('U20: „+N sesiuni — caută cu…" e înlocuit de o acţiune reală cu aria-expanded', () => {
    const f = file('./components/Dashboard.tsx')
    expect(f).not.toContain('dashboard.moreActiveSessions')
    expect(f).toContain("t('dashboard.viewAllSessions', { count: active.length })")
    expect(f).toContain('aria-expanded={showAllActive}')
  })

  it('U23: „More" din sesiune e disclosure — aria-expanded/aria-controls, fără role=menuitem', () => {
    const f = file('./components/SessionView.tsx')
    expect(f).toContain('aria-expanded={moreOpen} aria-controls={moreId}')
    const more = f.slice(f.indexOf('function MoreItem('), f.indexOf('function MoreItem(') + 1200)
    expect(more).not.toContain('role="menuitem"')
  })

  it('U25: pe pointer grosier, serviciile au „Actions" + foaie; pe desktop rămân pictogramele', () => {
    const f = file('./components/ServicesPanel.tsx')
    expect(f).toContain("useMediaQuery('(pointer: coarse)')")
    expect(f).toContain('function ServiceActionsSheet(')
    // confirmarea nu se mută în foaie: tot act() o cere, pentru stop/restart
    expect(f).toMatch(/onAction=\{\(a\) => \{[\s\S]*?act\(unit, a\)/)
  })

  it('U22: câmpurile partajate şi căutarea din sidebar sunt text-base sub sm (fără zoom iOS)', () => {
    expect(file('./components/settings/ui.ts')).toContain('text-base sm:text-sm')
    expect(file('./components/Sidebar.tsx')).toContain('pl-8 pr-7 text-base sm:text-sm')
    const login = file('./components/LoginPage.tsx')
    for (const id of ['login-email', 'login-password']) expect(login).toContain(`htmlFor="${id}"`)
  })

  it('U24: IconButton are starea `active`, iar ToolButton n-o mai suprascrie prin className', () => {
    expect(file('./components/ui/IconButton.tsx')).toContain('active = false')
    expect(file('./components/SessionView.tsx')).not.toContain("'wt-accent bg-ink-700'")
  })
})
