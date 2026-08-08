import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { errText, isSessionLive, api, ApiError, getBootVersion, Host, SearchHit, Session } from '../lib/api'
import { useI18n } from '../lib/i18n'
import InstallCommand from './InstallCommand'
import { hostColor, reachState } from '../lib/host'
import { allSchemes, hostSchemeRaw, setHostScheme } from '../lib/termtheme'
import { ActivityIcon, CloseIcon, FilesIcon, FolderMoveIcon, GearIcon, KeyIcon, LogoMark, MoreIcon, NoteIcon, PlusIcon, PowerIcon, RefreshIcon, SearchIcon, ServerIcon, TerminalPromptIcon } from './Icons'
import { fmt } from '../lib/shortcuts'

// modale rar folosite → chunk-uri separate, în afara bundle-ului inițial
const AddHostModal = lazy(() => import('./AddHostModal'))
const SettingsModal = lazy(() => import('./SettingsModal'))
const FleetRunModal = lazy(() => import('./FleetRunModal'))
const StatusModal = lazy(() => import('./StatusModal'))
const AboutModal = lazy(() => import('./AboutModal'))

// Motivele de blocare care se rezolvă REINSTALÂND agentul (cheia publică încorporată nu se
// potriveşte), faţă de restul, unde sfatul e „uită-te în jurnalul hostului". Codurile vin de la
// agent (`update_unsigned`) şi de la gateway (`signature_missing`); decizia se ia pe ele, nu pe
// textul mesajului, care se traduce şi mută condiţia sub picioare.
const SIGNATURE_BLOCKS = new Set(['signature_missing', 'update_unsigned'])

// Motivul blocării, tradus dacă îl cunoaştem, altfel afişat ca atare. Un cod nou trebuie să
// fie VIZIBIL, nu ascuns în spatele unei traduceri lipsă.
function blockReason(t: (k: string) => string, code: string): string {
  const key = 'sidebar.blockReason.' + code
  const label = t(key)
  return label === key ? code : label
}

const stateDot: Record<Session['state'], string> = {
  creating: 'bg-amber-400',
  live: 'bg-emerald-400 dot-live',
  closed: 'bg-slate-600',
  lost: 'bg-rose-500',
}

export default function Sidebar(props: {
  hosts: Host[]
  sessions: Session[]
  selectedHost: number | null
  open: boolean
  addHostSignal: number
  settingsSignal: number
  statusSignal: number
  onClose: () => void
  onSelectHost: (id: number) => void
  onSelect: (sid: string, search?: string) => void
  onNewSession: (host: Host) => void
  onFiles: (host: Host) => void
  onSerial: (host: Host) => void
  onDiagnostic: (host: Host) => void
  onOpenPalette: () => void
  onChanged: () => void
  onLogout: () => void
  onAccountChanged: () => void
  email: string | null
  webauthnAvailable: boolean
  backupReady?: boolean
  signingMissing?: boolean
  signingLocked?: boolean
}) {
  const { t } = useI18n()
  const [showAdd, setShowAdd] = useState(false)
  const [editHost, setEditHost] = useState<Host | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [showFleetRun, setShowFleetRun] = useState(false)
  const [showStatus, setShowStatus] = useState(false)
  const [showAbout, setShowAbout] = useState(false)
  const [provisioning, setProvisioning] = useState<string | null>(null)
  const [reinstallCmd, setReinstallCmd] = useState<{ cmd: string; dedicated?: string } | null>(null)
  const [query, setQuery] = useState('')
  const [historyHits, setHistoryHits] = useState<SearchHit[] | null>(null)
  const [newVersion, setNewVersion] = useState<string | null>(null)

  // „există versiune nouă?" — răspunsul e cache-uit server-side (1h), deci un apel
  // la montare ajunge; dacă verificarea e oprită din Setări, câmpul lipsește și
  // bara rămâne exact cum era.
  useEffect(() => {
    api<{ update_available?: boolean; latest?: string }>('/api/version')
      .then((v) => setNewVersion(v.update_available ? v.latest ?? null : null))
      .catch(() => {})
  }, [])

  // deschide modalul „adaugă host" când empty state-ul cere (semnal din App)
  const onCloseRef = useRef(props.onClose)
  onCloseRef.current = props.onClose
  useEffect(() => {
    if (props.addHostSignal > 0) {
      setShowAdd(true)
      // Prin ref, nu direct: `props` se schimbă la fiecare randare, deci ca dependenţă
      // efectul s-ar re-executa mereu şi ar redeschide modalul. Cu ref apelăm mereu
      // ultimul `onClose`, iar efectul rămâne legat doar de semnal — cum era intenţia.
      onCloseRef.current()
    }
  }, [props.addHostSignal])
  // aceleași semnale pentru setări/status — folosite de acțiunile din ⌘K
  useEffect(() => {
    if (props.settingsSignal > 0) setShowSettings(true)
  }, [props.settingsSignal])
  useEffect(() => {
    if (props.statusSignal > 0) setShowStatus(true)
  }, [props.statusSignal])

  // scurtătura globală „/": focusează inputul de căutare din copia VIZIBILĂ a
  // sidebarului (sunt două: desktop + drawer mobil; cea ascunsă nu e focusabilă)
  useEffect(() => {
    const onFocusSearch = () => {
      const inputs = document.querySelectorAll<HTMLInputElement>('input[data-wt-search]')
      for (const el of inputs) {
        if (el.offsetParent !== null) { el.focus(); return }
      }
    }
    window.addEventListener('wt-focus-search', onFocusSearch)
    return () => window.removeEventListener('wt-focus-search', onFocusSearch)
  }, [])

  // căutare în istoric (server-side), debounced
  useEffect(() => {
    const q = query.trim()
    if (q.length < 2) {
      setHistoryHits(null)
      return
    }
    const t = setTimeout(() => {
      api<{ sessions: SearchHit[] }>(`/api/search?q=${encodeURIComponent(q)}`)
        .then((r) => setHistoryHits(r.sessions))
        .catch(() => setHistoryHits([]))
    }, 350)
    return () => clearTimeout(t)
  }, [query])

  async function reinstall(host: Host) {
    const r = await api<{ install_command: string; install_command_dedicated?: string }>(`/api/hosts/${host.id}/enroll`, {
      method: 'POST',
    })
    setReinstallCmd({ cmd: r.install_command, dedicated: r.install_command_dedicated })
  }

  async function deleteHost(host: Host) {
    const agent = !host.connection_type || host.connection_type === 'agent'
    const q = agent
      ? t('sidebar.confirmRemoveAgent', { name: host.name })
      : t('sidebar.confirmDeleteHost', { name: host.name })
    if (!confirm(q)) return
    try {
      await api(`/api/hosts/${host.id}`, { method: 'DELETE' })
      props.onChanged()
    } catch (e) {
      alert(errText(e, t) || t('sidebar.error'))
    }
  }

  async function uninstallHost(host: Host) {
    if (!confirm(t('sidebar.confirmUninstall', { name: host.name }))) return
    try {
      const r = await api<{ uninstalled: boolean; warnings: string[] }>(
        `/api/hosts/${host.id}/uninstall`, { method: 'POST' })
      if (r.warnings?.length) alert(t('sidebar.uninstalledWithWarnings') + r.warnings.join(', '))
      props.onChanged()
    } catch (e) {
      const m = errText(e, t) || t('sidebar.error')
      // Agent offline / care nu răspunde → oferim scoaterea DOAR din WebTerm (fişierele rămân
      // pe server). Semnalul e STATUSUL 409, nu textul erorii: aici se citea mesajul cu
      // /offline|did not answer|not responding/, ceea ce mergea doar cât timp API-ul răspunde
      // în engleză. În ziua în care se localizează, un host offline devenea imposibil de scos
      // din UI — exact ruda defectului „frază tradusă, comparaţia nu".
      const canForce = e instanceof ApiError && e.status === 409
      if (canForce && confirm(`${m}\n\n${t('sidebar.confirmRemoveOnly')}`)) {
        try {
          await api(`/api/hosts/${host.id}/uninstall?force=1`, { method: 'POST' })
          props.onChanged()
        } catch (e2) { alert(errText(e2, t) || t('sidebar.error')) }
      } else if (!canForce) {
        alert(m)
      }
    }
  }

  async function updateAgent(host: Host) {
    if (!confirm(t('sidebar.confirmUpdateAgent', { name: host.name }))) return
    try {
      await api(`/api/hosts/${host.id}/update`, { method: 'POST' })
      props.onChanged()
    } catch (e) {
      alert(errText(e, t) || t('sidebar.error'))
    }
  }

  async function moveToFolder(host: Host) {
    const folder = prompt(t('sidebar.promptFolder'), host.folder ?? '')
    if (folder === null) return
    await api(`/api/hosts/${host.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: host.name, note: host.note, folder: folder.trim() }),
    }).catch((e) => alert(errText(e, t) || t('sidebar.error')))
    props.onChanged()
  }

  // redenumește un grup întreg = mută toate host-urile din folder în noul nume
  async function renameGroup(folder: string) {
    const next = prompt(t('sidebar.promptRenameGroup', { folder }), folder)
    if (next === null) return
    const name = next.trim()
    if (name === folder) return
    const inGroup = props.hosts.filter((h) => (h.folder || '') === folder)
    await Promise.all(inGroup.map((h) => api(`/api/hosts/${h.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: h.name, note: h.note, folder: name }),
    }).catch(() => {})))
    props.onChanged()
  }

  async function toggle2fa(host: Host) {
    await api(`/api/hosts/${host.id}/require-2fa`, {
      method: 'POST',
      body: JSON.stringify({ enabled: !host.require_2fa }),
    }).catch((e) => alert(errText(e, t) || t('sidebar.error')))
    props.onChanged()
  }

  async function provision(host: Host) {
    if (!confirm(t('sidebar.confirmProvision', { name: host.name }))) return
    setProvisioning(host.name)
    try {
      const r = await api<{ credentials_deleted: boolean }>(`/api/hosts/${host.id}/provision`, { method: 'POST' })
      // Cheile `sidebar.provisionOk` / `sidebar.provisionCredsRemoved` existau în ambele
      // limbi şi nu le folosea nimeni: mesajul era scris de mână, în engleză, lângă un frate
      // (`provisionFailed`) care trecea corect prin `t()`.
      alert(t('sidebar.provisionOk', { name: host.name }) +
        (r.credentials_deleted ? t('sidebar.provisionCredsRemoved') : ''))
      props.onChanged()
    } catch (e) {
      alert(t('sidebar.provisionFailed') + (errText(e, t) || t('sidebar.error')))
    } finally {
      setProvisioning(null)
    }
  }

  const [collapsedFolders, setCollapsedFolders] = useState<Record<string, boolean>>({})
  const [groupFilter, setGroupFilter] = useState<string | null>(null)

  // grupurile existente (foldere) pentru filtrare rapidă
  const groups = [...new Set(props.hosts.map((h) => h.folder || '').filter(Boolean))].sort()

  const q = query.trim().toLowerCase()
  const hostMatches = (h: Host) =>
    (!groupFilter || (h.folder || '') === groupFilter) &&
    (!q || h.name.toLowerCase().includes(q) || (h.hostname ?? '').toLowerCase().includes(q))

  // Sidebar = navigare: card de host → deschide pagina hostului. Sesiunile
  // (active + închise, istoric, atașare) trăiesc în pagina hostului, nu aici.
  const renderHost = (host: Host) => {
    const liveCount = props.sessions.filter(
      (s) => s.host_id === host.id && isSessionLive(s, props.hosts)).length
    const selected = props.selectedHost === host.id
    const canConnect = host.connection_type !== 'agent' || host.online
    const color = hostColor(host)
    const reach = reachState(host)
    return (
      <div key={host.id} className="px-2 py-0.5">
        <div
          onClick={() => props.onSelectHost(host.id)}
          style={selected ? { boxShadow: `inset 2px 0 0 ${color}` } : undefined}
          className={`group flex cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 ${
            selected ? 'bg-ink-800 ring-1 ring-ink-700' : 'hover:bg-ink-800/60'
          }`}
        >
          <div className="relative shrink-0">
            <div className="grid h-8 w-8 place-items-center rounded-lg" style={{ background: `${color}22`, color }}>
              <ServerIcon />
            </div>
            <span
              className={`absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full ring-2 ring-ink-900 ${
                reach === 'online' ? 'bg-emerald-400' : reach === 'ondemand' ? 'bg-sky-500' : 'bg-slate-500'
              }`}
              title={reach === 'online' ? 'online' : reach === 'ondemand' ? t('dashboard.onDemandConnect') : 'offline'}
            />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-sm font-medium">{host.name}</span>
              {liveCount > 0 && (
                <span className="shrink-0 rounded-full bg-emerald-500/15 px-1.5 text-[10px] font-semibold wt-good"
                  title={t('sidebar.liveSessions', { count: liveCount })}>
                  {liveCount}
                </span>
              )}
            </div>
            {host.hostname && (
              <div className="truncate font-mono text-xs text-slate-500">
                {(host.ssh_username || host.agent_user) ?? ''}@{host.hostname}
                {host.connection_type && host.connection_type !== 'agent' && (
                  <span className="font-semibold text-slate-400"> · {host.connection_type.toUpperCase()}</span>
                )}
              </div>
            )}
            {host.conflict && (
              <div className="truncate text-xs wt-danger"
                title={t('sidebar.conflictTitle')}>
                ⚠ {t('sidebar.conflictBody')}
              </div>
            )}
          </div>
          {host.online && host.update_blocked && (
            /* update BLOCAT ≠ update disponibil: fără distincţia asta, cardul arăta „↑ vNN"
               la infinit şi omul apăsa degeaba. Roşu + motiv + remediu în tooltip. */
            /* Motivul e un COD stabil (`update_unsigned`, `signature_missing`…), nu o frază:
               alegeam sfatul cu un regex englezesc peste text de server — exact clasa care a
               rupt deja dezinstalarea. Codul necunoscut se afişează ca atare, ca să nu ascundem
               un motiv nou în spatele unei traduceri lipsă. */
            <span
              title={t('sidebar.updateBlockedTitle', {
                // `t()` nu întoarce niciodată gol: la cheie lipsă întoarce CHEIA. Deci `||` era
                // cod mort, iar un cod nou de la agent (`core.py` scrie şi „necunoscut", sau ce
                // frază trimite el) apărea în tooltip ca `sidebar.blockReason.necunoscut` —
                // exact inversul a ce promitea comentariul de aici. Comparăm cu cheia.
                reason: blockReason(t, host.update_blocked),
              }) + (SIGNATURE_BLOCKS.has(host.update_blocked)
                ? t('sidebar.updateBlockedHint')
                : t('sidebar.updateBlockedLog'))}
              className="wt-danger shrink-0 cursor-help rounded-md bg-rose-900/60 px-1.5 py-0.5 text-xs text-rose-300"
            >
              {t('sidebar.updateBlockedBadge')}
            </span>
          )}
          {host.online && host.update_pending && !host.update_blocked && (
            <button
              onClick={(e) => { e.stopPropagation(); updateAgent(host) }}
              /* `?? '?'`: amândouă sunt `number | null`, iar template-ul de dinainte le
                 transforma tăcut în cuvântul „null" în tooltip. */
              title={t('sidebar.updateAgentTitle',
                { from: host.agent_version ?? '?', to: host.agent_latest ?? '?' })}
              className="shrink-0 rounded-md bg-amber-900/60 px-1.5 py-0.5 text-xs text-amber-300 hover:bg-amber-800/60"
            >
              ↑ v{host.agent_latest}
            </button>
          )}
          <button
            disabled={!canConnect}
            onClick={(e) => { e.stopPropagation(); props.onNewSession(host) }}
            // `aria-label` bate `title`, deci un cititor de ecran auzea „New session, dimmed"
            // şi nu afla NICIODATĂ de ce e dezactivat. Motivul intră în însuşi numele accesibil.
            title={host.connection_type !== 'agent' ? t('sidebar.connect')
                   : host.online ? t('sidebar.newSession') : t('sidebar.hostOffline')}
            aria-label={host.online || host.connection_type !== 'agent'
                        ? t('host.newSession')
                        : `${t('host.newSession')} — ${t('sidebar.hostOffline')}`}
            className="flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-slate-300 opacity-0 ring-1 ring-ink-700 transition hover:bg-sky-600 hover:text-white hover:ring-transparent focus-visible:opacity-100 group-hover:opacity-100 disabled:cursor-not-allowed disabled:opacity-0"
          >
            <PlusIcon /> {t('sidebar.new')}
          </button>
          <span onClick={(e) => e.stopPropagation()}>
            <HostMenu
              online={host.online}
              require2fa={!!host.require_2fa}
              connectionType={host.connection_type}
              hostId={host.id}
              onFiles={() => props.onFiles(host)}
              onSerial={() => props.onSerial(host)}
              onDiagnostic={() => props.onDiagnostic(host)}
              onFolder={() => moveToFolder(host)}
              onEdit={() => setEditHost(host)}
              onReinstall={() => reinstall(host)}
              onProvision={() => provision(host)}
              onToggle2fa={() => toggle2fa(host)}
              onUninstall={() => uninstallHost(host)}
              onDelete={() => deleteHost(host)}
            />
          </span>
        </div>
      </div>
    )
  }

  // versiunea vine din headerul X-Webterm-Version al primului răspuns (fără apel dedicat);
  // hosturile online le avem deja în props — sidebarul le primeşte oricum pentru listă
  const version = getBootVersion()
  const hostsOnline = props.hosts.filter((h) => h.online).length

  const body = (
    <div className="wt-sidebar flex h-full w-72 flex-col border-r border-ink-800 bg-ink-900">
      {/* overflow-hidden + min-w-0: garantează că butoanele de header NU ies din
          lățimea sidebar-ului peste conținutul principal (altfel un buton acoperă
          „Acasă" din TabBar pe desktop) */}
      <div className="flex items-center justify-between gap-1 overflow-hidden border-b border-ink-800 px-4 py-3">
        <button
          onClick={() => setShowAbout(true)}
          title={t('nav.about')}
          aria-label={t('nav.about')}
          className="flex min-w-0 items-center gap-2 truncate rounded-md font-semibold tracking-tight hover:text-sky-300"
        >
          <LogoMark /> WebTerm
        </button>
        {/* `wt-touch` (44px, activ doar sub `pointer: coarse`) pe navigaţia PRINCIPALĂ.
            Auditul mobil raportează ţintele mici ca `ux`, nu ca `bug`, deci nu blochează
            imaginea — dar astea patru sunt butoanele atinse de zeci de ori pe zi, şi erau
            32×24. Restul listei rămâne raportat şi nereparat în bloc: pe iconiţele dintr-un
            rând dens de fişiere, 44px ar rupe layout-ul — acolo compromisul e deliberat. */}
        <div className="flex shrink-0 items-center gap-0.5">
          <button
            title={t('nav.addHost')} aria-label={t('nav.addHost')}
            onClick={() => setShowAdd(true)}
            className="wt-touch inline-flex items-center justify-center rounded-md px-2 py-1 text-sm text-slate-400 hover:bg-ink-800 hover:text-slate-200"
          >
            <PlusIcon />
          </button>
          <button
            title={t('nav.fleetRun')}
            aria-label={t('nav.fleetRunAria')}
            onClick={() => setShowFleetRun(true)}
            className="wt-touch inline-flex items-center justify-center rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-ink-800"
          >
            <TerminalPromptIcon />
          </button>
          <button
            title={t('nav.status')}
            aria-label={t('nav.status')}
            onClick={() => setShowStatus(true)}
            className="wt-touch inline-flex items-center justify-center rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-ink-800"
          >
            <ActivityIcon />
          </button>
          <button
            title={props.signingLocked
              ? t('sidebar.settingsSigningLocked')
              : props.signingMissing ? t('sidebar.settingsSigningMissing')
                : props.backupReady ? t('sidebar.settingsBackupReady') : t('sidebar.settingsPasskeys')}
            onClick={() => setShowSettings(true)}
            aria-label={t('settings.title')}
            className="wt-touch relative inline-flex items-center justify-center rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-ink-800"
          >
            <GearIcon />
            {(props.backupReady || props.signingMissing || props.signingLocked) && (
              <span aria-label={props.signingLocked ? 'signing key locked — agents cannot update'
                : props.signingMissing ? 'signing key missing' : 'backup gata'}
                className={`absolute right-1 top-1 h-2 w-2 rounded-full ring-2 ring-ink-900 ${
                  props.signingLocked ? 'bg-rose-500' : props.signingMissing ? 'bg-amber-400' : 'bg-sky-400'}`} />
            )}
          </button>
          <button
            title={t('sidebar.signOut')}
            onClick={props.onLogout}
            className="rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-ink-800"
          >
            <PowerIcon />
          </button>
        </div>
      </div>

      <div className="relative px-3 py-2">
        <span className="pointer-events-none absolute left-5 top-1/2 -translate-y-1/2 text-slate-400">
          <SearchIcon />
        </span>
        <input
          data-wt-search
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label={t('sidebar.searchAria')}
          placeholder={t('sidebar.searchPlaceholder')}
          className="w-full rounded-lg bg-ink-800 py-1.5 pl-8 pr-7 text-sm placeholder-slate-600 ring-1 ring-ink-700 focus:ring-sky-600"
        />
        {query ? (
          <button
            onClick={() => setQuery('')}
            className="absolute right-5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
          >
            ✕
          </button>
        ) : (
          /* badge-ul de scurtătură: doar unde EXISTĂ tastatură */
          <button
            onClick={props.onOpenPalette}
            title={t('sidebar.paletteTitle', { key: fmt('Mod+K') })}
            aria-label={t('sidebar.openPalette')}
            className="absolute right-4 top-1/2 hidden -translate-y-1/2 rounded bg-white/5 px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-white/10 hover:text-slate-200 [@media(hover:hover)]:block"
          >
            {fmt('Mod+K')}
          </button>
        )}
      </div>

      {groups.length > 0 && (
        <div className="flex flex-wrap gap-1.5 px-3 pb-2">
          <GroupChip label={t('sidebar.allGroups')} active={groupFilter === null} onClick={() => setGroupFilter(null)} />
          {groups.map((g) => (
            <GroupChip key={g} label={g} active={groupFilter === g} onClick={() => setGroupFilter(groupFilter === g ? null : g)} />
          ))}
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        {props.hosts.length === 0 && (
          <div className="p-4 text-sm text-slate-500">
            {t('sidebar.noHostsYet')}
          </div>
        )}
        {(() => {
          const visible = props.hosts.filter(hostMatches)
          // grupurile cu nume întâi (alfabetic), hosturile fără folder la FINAL —
          // altfel plutesc deasupra grupurilor etichetate și par un bug de randare
          const folders = [...new Set(visible.map((h) => h.folder || ''))].sort((a, b) =>
            a === '' ? 1 : b === '' ? -1 : a.localeCompare(b))
          const hasNamed = folders.some((f) => f !== '')
          return folders.map((folder) => {
            const inFolder = visible.filter((h) => (h.folder || '') === folder)
            const collapsed = collapsedFolders[folder]
            // arată un antet și pentru hosturile fără folder, DAR doar când există
            // și grupuri cu nume (pe o listă complet plată n-are rost o etichetă)
            const showHeader = folder !== '' || hasNamed
            return (
              <div key={folder || '__root__'}>
                {showHeader && (
                  <div className="group/folder flex items-center gap-1 px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-slate-500">
                    <button
                      onClick={() => setCollapsedFolders({ ...collapsedFolders, [folder]: !collapsed })}
                      className="flex min-w-0 flex-1 items-center gap-1.5 text-left hover:text-slate-300"
                    >
                      <span className="text-[10px]">{collapsed ? '▸' : '▾'}</span>
                      <span className="opacity-70"><FolderMoveIcon /></span>
                      <span className={`truncate ${folder ? '' : 'italic text-slate-400'}`}>{folder || t('sidebar.noFolder')}</span>
                    </button>
                    {folder && (
                      <button
                        onClick={() => renameGroup(folder)}
                        title={t('sidebar.renameGroupAria', { folder })}
                        aria-label={t('sidebar.renameGroupAria', { folder })}
                        className="shrink-0 rounded p-0.5 opacity-0 hover:text-slate-200 focus-visible:opacity-100 group-hover/folder:opacity-100"
                      >
                        <NoteIcon />
                      </button>
                    )}
                    <span className="shrink-0 text-slate-400">{inFolder.length}</span>
                  </div>
                )}
                {!collapsed && inFolder.map(renderHost)}
              </div>
            )
          })
        })()}

        {historyHits !== null && (
          <div className="border-t border-ink-800 pb-2">
            <div className="px-4 pb-1 pt-3 text-xs font-medium uppercase tracking-wide text-slate-400">
              In session history
            </div>
            {historyHits.length === 0 && (
              <div className="px-4 py-1 text-xs text-slate-400">{t('sidebar.noResults')}</div>
            )}
            {historyHits.map((h) => (
              <button
                key={h.id}
                onClick={() => props.onSelect(h.id, query.trim())}
                className="block w-full px-4 py-1.5 text-left hover:bg-ink-800"
              >
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${stateDot[h.state]}`} />
                  <span className="truncate text-sm">{h.title || t('sidebar.untitled')}</span>
                  {h.matches > 0 && (
                    <span className="ml-auto shrink-0 text-[10px] text-slate-400">
                      {t('sidebar.matchCount', { count: h.matches })}
                    </span>
                  )}
                </div>
                {h.snippet && (
                  <div className="truncate pl-4 font-mono text-xs text-slate-500">…{h.snippet}…</div>
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Bară de stare: versiunea care rulează + câţi agenţi răspund din câţi există.
          Două informaţii pe care le verifici des şi pentru care intrai până acum în
          două locuri diferite (Despre / panoul de Status). `shrink-0` ca lista de
          hosturi să se comprime, nu bara. */}
      <button
        onClick={() => setShowStatus(true)}
        title={t('nav.statusBarTitle', { online: hostsOnline, total: props.hosts.length })
          + (newVersion ? ' · ' + t('status.updateAvailable', { version: newVersion }) : '')}
        className="flex shrink-0 items-center gap-2 border-t border-ink-800 px-3 py-1.5 text-left text-[11px] text-slate-500 hover:bg-ink-800/60"
      >
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${
          props.hosts.length === 0 ? 'bg-slate-600'
            : hostsOnline === props.hosts.length ? 'bg-emerald-500'
              : hostsOnline === 0 ? 'bg-rose-500' : 'bg-amber-500'}`} />
        <span className="tabular-nums">
          {hostsOnline}/{props.hosts.length} {t('nav.statusBarHosts')}
        </span>
        {newVersion && (
          <span className="wt-warn ml-auto shrink-0 rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-300 ring-1 ring-amber-500/25">
            {newVersion}
          </span>
        )}
        <span className={`font-mono text-slate-400 ${newVersion ? '' : 'ml-auto'}`}>v{version || '—'}</span>
      </button>
    </div>
  )

  return (
    <>
      {/* desktop */}
      <div className="hidden md:block">{body}</div>
      {/* mobile drawer */}
      {props.open && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/70" onClick={props.onClose} />
          {/* wt-drawer: fundal OPAC pe mobil. Sticla translucidă (--glass-bg) lăsa
              dashboard-ul să se vadă prin drawer — exact „suprapunerea" raportată */}
          <div className="wt-drawer absolute inset-y-0 left-0 shadow-2xl">{body}</div>
        </div>
      )}
      {/* modalele se randează o singură dată, nu în fiecare copie a sidebarului;
         lazy → sub Suspense (fallback null: apar oricum doar la deschidere) */}
      <Suspense fallback={null}>
        {showAdd && (
          <AddHostModal
            onClose={() => {
              setShowAdd(false)
              props.onChanged()
            }}
          />
        )}
        {editHost && (
          <AddHostModal
            host={editHost}
            onSaved={props.onChanged}
            onClose={() => setEditHost(null)}
          />
        )}
        {showSettings && (
          <SettingsModal
            email={props.email}
            webauthnAvailable={props.webauthnAvailable}
            initialCat={props.signingMissing ? 'securitate' : props.backupReady ? 'backup' : undefined}
            onAccountChanged={props.onAccountChanged}
            onClose={() => setShowSettings(false)}
          />
        )}
        {showStatus && <StatusModal onClose={() => setShowStatus(false)} />}
        {showAbout && <AboutModal onClose={() => setShowAbout(false)} />}
        {showFleetRun && <FleetRunModal hosts={props.hosts} onClose={() => setShowFleetRun(false)} />}
      </Suspense>
      {reinstallCmd && (
        <CommandModal cmd={reinstallCmd.cmd} cmdDedicated={reinstallCmd.dedicated}
                      onClose={() => setReinstallCmd(null)} />
      )}
      {provisioning && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4">
          <div className="glass flex max-w-sm flex-col items-center gap-3 rounded-2xl p-6 text-center">
            <span className="h-8 w-8 animate-spin rounded-full border-2 border-ink-600 border-t-sky-500" />
            <div className="font-medium">Instalez agentul pe „{provisioning}"</div>
            <div className="text-sm text-slate-500">
              {t('sidebar.provisioning')}
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function GroupChip(props: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={props.onClick}
      aria-pressed={props.active}
      className={`rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 transition ${
        props.active
          ? 'bg-sky-600 text-white ring-sky-600'
          : 'bg-ink-800 text-slate-400 ring-ink-700 hover:text-slate-200'
      }`}
    >
      {props.label}
    </button>
  )
}

function HostMenu(props: {
  online: boolean
  require2fa: boolean
  connectionType?: string
  hostId: number
  onFiles: () => void
  onSerial: () => void
  onDiagnostic: () => void
  onFolder: () => void
  onEdit: () => void
  onReinstall: () => void
  onProvision: () => void
  onToggle2fa: () => void
  onUninstall: () => void
  onDelete: () => void
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [schemeOpen, setSchemeOpen] = useState(false)
  // Escape închide meniul. Fără el, singura ieșire era un click pe overlay-ul
  // `fixed inset-0`, care acoperă tot ecranul: cine navighează de la tastatură rămânea
  // cu meniul deschis ȘI cu restul UI-ului blocat sub overlay.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      e.stopPropagation()
      if (schemeOpen) setSchemeOpen(false)
      else setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, schemeOpen])
  const item = 'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm hover:bg-ink-800'
  return (
    <div className="relative shrink-0">
      <button
        title={t('sidebar.hostActions')} aria-label={t('sidebar.hostActions')} aria-haspopup="menu" aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="wt-touch grid place-items-center rounded-md p-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200"
      >
        <MoreIcon />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div role="menu" className="absolute right-0 z-40 mt-1 w-48 rounded-xl border border-ink-700 bg-ink-900 p-1 shadow-2xl">
            {props.online && (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onFiles() }}>
                <FilesIcon /> {t('sidebar.files')}
              </button>
            )}
            {props.online && (!props.connectionType || props.connectionType === 'agent') && (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onSerial() }}>
                <span className="grid h-4 w-4 place-items-center text-[13px]">🔌</span> {t('sidebar.serialConsole')}
              </button>
            )}
            {(!props.connectionType || props.connectionType === 'agent') && (
              // și când e OFFLINE: exact atunci vrei să vezi DE CE (jurnal de conexiune)
              <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onDiagnostic() }}>
                <span className="grid h-4 w-4 place-items-center text-[13px]">🩺</span> Diagnostic
              </button>
            )}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onEdit() }}>
              <span className="grid h-4 w-4 place-items-center text-[13px]">✎</span> {t('sidebar.editHost')}
            </button>
            <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onFolder() }}>
              <FolderMoveIcon /> {t('sidebar.moveToGroup')}
            </button>
            {props.connectionType === 'ssh' ? (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onProvision() }}>
                <RefreshIcon /> {t('sidebar.installAgentSsh')}
              </button>
            ) : (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onReinstall() }}>
                <RefreshIcon /> {t('sidebar.reinstallAgent')}
              </button>
            )}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={() => { setOpen(false); props.onToggle2fa() }}>
              <KeyIcon /> {props.require2fa ? t('sidebar.require2faOn') : t('sidebar.require2faOff')}
            </button>
            {/* schemă de culori proprie hostului: „producția e roșiatică" —
                un semnal vizual imposibil de ratat când ai 5 host-uri deschise */}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={() => setSchemeOpen((v) => !v)}>
              <span className="inline-block w-4" aria-hidden="true">◧</span> {t('sidebar.hostColours')}
            </button>
            {schemeOpen && (
              <div className="mb-1 ml-6 mr-1 space-y-0.5">
                <button
                  role="menuitem"
                  onClick={() => { setHostScheme(props.hostId, null); setOpen(false) }}
                  className={`${item} py-1 text-xs ${!hostSchemeRaw(props.hostId) ? 'text-sky-400' : 'text-slate-400'}`}
                >
                  same as the global scheme
                </button>
                {allSchemes().map((s) => (
                  <button
                    key={s.id}
                    role="menuitem"
                    onClick={() => { setHostScheme(props.hostId, s.id); setOpen(false) }}
                    className={`${item} py-1 text-xs ${hostSchemeRaw(props.hostId) === s.id ? 'text-sky-400' : 'text-slate-400'}`}
                  >
                    <span className="flex gap-0.5" aria-hidden="true">
                      {[s.theme.red, s.theme.green, s.theme.blue].map((c, i) => (
                        <span key={i} className="h-2.5 w-1 rounded-sm" style={{ background: c }} />
                      ))}
                    </span>
                    {s.name}
                  </button>
                ))}
              </div>
            )}
            <div className="my-1 h-px bg-ink-800" />
            {(!props.connectionType || props.connectionType === 'agent') && (
              <button role="menuitem" className={`${item} wt-danger hover:underline`}
                title={t('sidebar.uninstallTitle')}
                onClick={() => { setOpen(false); props.onUninstall() }}>
                <CloseIcon size={16} /> {t('sidebar.uninstallAgent')}
              </button>
            )}
            <button role="menuitem" className={`${item} wt-danger hover:underline`}
              title={(!props.connectionType || props.connectionType === 'agent')
                ? t('sidebar.removeOnlyTitle') : undefined}
              onClick={() => { setOpen(false); props.onDelete() }}>
              <CloseIcon size={16} /> {(!props.connectionType || props.connectionType === 'agent') ? t('sidebar.removeFromWebTerm') : t('sidebar.deleteHost')}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export function CommandModal(props: { cmd: string; cmdDedicated?: string; onClose: () => void }) {
  const { t } = useI18n()
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="glass w-full max-w-xl rounded-2xl p-6">
        <h2 className="font-semibold">{t('sidebar.installAgentTitle')}</h2>
        <p className="mt-1 text-sm text-slate-500">
          {t('sidebar.reinstallHint')}
        </p>
        <InstallCommand command={props.cmd} commandDedicated={props.cmdDedicated} />
        <div className="mt-4 text-right">
          <button onClick={props.onClose} className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-ink-800">
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
