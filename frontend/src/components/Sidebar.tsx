import { Fragment, lazy, Suspense, useEffect, useRef, useState, PointerEvent as ReactPointerEvent } from 'react'
import { lsGet } from '../lib/storage'
import { errText, isSessionLive, api, ApiError, getBootVersion, Host, SearchHit, Session, timeAgo, withStepup } from '../lib/api'
import { notify, notifyError } from '../lib/notify'
import { fmtTs } from '../lib/tz'
import type { SettingsTarget } from '../lib/settingsIndex'
import { useI18n } from '../lib/i18n'
import { useConfirm } from '../lib/confirm'
import { useFocusTrap } from '../lib/useFocusTrap'
import InstallCommand from './InstallCommand'
import { hostColor, reachState } from '../lib/host'
import { canWake } from '../lib/hostOffline'
import { wakeHost as wakeShared } from '../lib/wake'
import { allSchemes, hostSchemeRaw, setHostScheme } from '../lib/termtheme'
import { AlertsBell } from './AlertsPanel'
import { ActivityIcon, ArrowUpIcon, BanIcon, BellIcon, BellOffIcon, ChevronIcon, CloseIcon, CollapseIcon, DownloadIcon, FilesIcon, FolderMoveIcon, GearIcon, KeyIcon, LinkIcon, LogoMark, MoreIcon, NoteIcon, PaletteIcon, PencilIcon, PlugIcon, PlusIcon, PowerIcon, RefreshIcon, SearchIcon, ServerIcon, ShieldSmallIcon, StethoscopeIcon, SubItemIcon, TerminalPromptIcon, WarningIcon } from './Icons'
import { fmt } from '../lib/shortcuts'
import { setHostMuted, updatesSignal, useUpdatesPref } from '../lib/updatesPref'
import { Badge, Button, IconButton } from './ui'

// modale rar folosite → chunk-uri separate, în afara bundle-ului inițial
const AddHostModal = lazy(() => import('./AddHostModal'))
const ExportHostsModal = lazy(() => import('./HostsCsv').then((m) => ({ default: m.ExportHostsModal })))
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
  /** tab-ul cerut odată cu semnalul (cardul Securitate de pe Dashboard); gol = alegerea obişnuită */
  settingsCat?: SettingsTarget
  statusSignal: number
  onClose: () => void
  collapsed: boolean
  onToggleCollapse: () => void
  onSelectHost: (id: number) => void
  onSelect: (sid: string, search?: string) => void
  onNewSession: (host: Host) => void
  onFiles: (host: Host) => void
  onSerial: (host: Host) => void
  onDiagnostic: (host: Host) => void
  onUpgrade: (host: Host) => void
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
  // confirm()/prompt()/alert() native → dialoguri proprii + toast-uri (vezi lib/confirm.tsx: de ce)
  const { confirm, promptText } = useConfirm()
  const fail = (e: unknown) => notifyError(t('sidebar.actionFailed'), errText(e, t) || t('sidebar.error'))
  const [showAdd, setShowAdd] = useState(false)
  const [editHost, setEditHost] = useState<Host | null>(null)
  const [jumpVia, setJumpVia] = useState<Host | null>(null)   // agentul-gazdă pentru care adăugăm o ţintă SSH-jump
  // dialogul de export CSV; `folder` = preselecţia (antetul unui folder), undefined = nimic bifat
  const [exportCsv, setExportCsv] = useState<{ folder?: string } | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [settingsCat, setSettingsCat] = useState<SettingsTarget | undefined>(undefined)
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
    if (props.settingsSignal > 0) { setSettingsCat(props.settingsCat); setShowSettings(true) }
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

  // căutare în istoric (server-side), debounced. Numărul de secvenţă + AbortController: un
  // răspuns LENT la „pro" nu are voie să suprascrie rezultatele deja afişate pentru „prod" —
  // debounce-ul anulează doar timer-ul, nu şi cererea deja plecată (audit F-05).
  const searchSeq = useRef(0)
  useEffect(() => {
    const q = query.trim()
    if (q.length < 2) {
      searchSeq.current++
      setHistoryHits(null)
      return
    }
    const ctl = new AbortController()
    const t = setTimeout(() => {
      const seq = ++searchSeq.current
      api<{ sessions: SearchHit[] }>(`/api/search?q=${encodeURIComponent(q)}`, { signal: ctl.signal })
        .then((r) => { if (seq === searchSeq.current) setHistoryHits(r.sessions) })
        .catch(() => { if (seq === searchSeq.current && !ctl.signal.aborted) setHistoryHits([]) })
    }, 350)
    return () => { clearTimeout(t); ctl.abort() }
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
    if (!(await confirm({
      title: agent ? t('sidebar.removeFromWebTerm') : t('sidebar.deleteHost'),
      message: q, danger: true, confirmLabel: agent ? t('sidebar.dlgRemove') : t('sidebar.dlgDelete'),
    }))) return
    try {
      await api(`/api/hosts/${host.id}`, { method: 'DELETE' })
      props.onChanged()
    } catch (e) {
      fail(e)
    }
  }

  async function uninstallHost(host: Host) {
    if (!(await confirm({
      title: t('sidebar.uninstallAgent'), message: t('sidebar.confirmUninstall', { name: host.name }),
      danger: true, confirmLabel: t('sidebar.dlgUninstall'),
    }))) return
    try {
      const r = await api<{ uninstalled: boolean; warnings: string[] }>(
        `/api/hosts/${host.id}/uninstall`, { method: 'POST' })
      if (r.warnings?.length) notify(t('sidebar.uninstalledOk'), t('sidebar.uninstalledWithWarnings') + r.warnings.join(', '), 'warn')
      props.onChanged()
    } catch (e) {
      const m = errText(e, t) || t('sidebar.error')
      // Agent offline / care nu răspunde → oferim scoaterea DOAR din WebTerm (fişierele rămân
      // pe server). Semnalul e STATUSUL 409, nu textul erorii: aici se citea mesajul cu
      // /offline|did not answer|not responding/, ceea ce mergea doar cât timp API-ul răspunde
      // în engleză. În ziua în care se localizează, un host offline devenea imposibil de scos
      // din UI — exact ruda defectului „frază tradusă, comparaţia nu".
      const canForce = e instanceof ApiError && e.status === 409
      if (canForce && (await confirm({
        title: t('sidebar.removeFromWebTerm'), message: `${m}\n\n${t('sidebar.confirmRemoveOnly')}`,
        danger: true, confirmLabel: t('sidebar.dlgRemove'),
      }))) {
        try {
          await api(`/api/hosts/${host.id}/uninstall?force=1`, { method: 'POST' })
          props.onChanged()
        } catch (e2) { fail(e2) }
      } else if (!canForce) {
        notifyError(t('sidebar.actionFailed'), m)
      }
    }
  }

  async function updateAgent(host: Host) {
    if (!(await confirm({
      title: t('sidebar.updateAgentDlgTitle'), message: t('sidebar.confirmUpdateAgent', { name: host.name }),
      confirmLabel: t('sidebar.dlgUpdate'),
    }))) return
    try {
      await api(`/api/hosts/${host.id}/update`, { method: 'POST' })
      props.onChanged()
    } catch (e) {
      fail(e)
    }
  }

  async function moveToFolder(host: Host) {
    const folder = await promptText({
      title: t('sidebar.moveToGroup'), message: t('sidebar.promptFolder'),
      label: t('sidebar.folderLabel'), defaultValue: host.folder ?? '',
    })
    if (folder === null) return
    await api(`/api/hosts/${host.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: host.name, note: host.note, folder: folder.trim() }),
    }).catch(fail)
    props.onChanged()
  }

  // Notă pe host, la îndemână când e down: „de ce l-am oprit" se uită în două săptămâni —
  // aici rămâne scris exact în locul în care te uiţi când îl cauţi. Acelaşi PATCH ca la
  // mutarea în folder (nota e câmp obişnuit de host, doar că acum e vizibilă în sidebar).
  // Wake-on-LAN: gateway-ul cere unui agent vecin să trimită magic packet-ul. Feedback pe toast.
  const [waking, setWaking] = useState<number | null>(null)
  const [updFor, setUpdFor] = useState<Host | null>(null)   // hostul cu modalul de update-uri deschis
  const updPref = useUpdatesPref()
  // helperul e comun cu overlay-ul „host offline" din sesiune (lib/wake): acelaşi endpoint şi toast
  async function wakeHost(host: Host) {
    setWaking(host.id)
    try { await wakeShared(host, t) } finally { setWaking(null) }
  }

  // Opreşte/porneşte alertele de host-offline pe acest host. Util pentru o maşină oprită
  // intenţionat (nu vrei un email la fiecare sweep). La re-activare gateway-ul curăţă şi
  // dedup-ul, deci un host încă jos re-declanşează o alertă (vrei să ştii). Pe hosturi 2FA,
  // OPRIREA alertelor cere step-up (slăbeşte monitorizarea) — de aici withStepup.
  async function muteHost(host: Host, muted: boolean) {
    await withStepup(host.id, () => api(`/api/hosts/${host.id}`, {
      method: 'PATCH', body: JSON.stringify({ alerts_muted: muted }),
    })).catch(fail)
    props.onChanged()
  }

  async function editNote(host: Host) {
    const note = await promptText({
      title: t('sidebar.noteDlgTitle', { name: host.name }), message: t('sidebar.promptNote', { name: host.name }),
      label: t('sidebar.noteLabel'), defaultValue: host.note ?? '',
    })
    if (note === null) return
    await api(`/api/hosts/${host.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: host.name, note: note.trim(), folder: host.folder ?? '' }),
    }).catch(fail)
    props.onChanged()
  }

  // redenumește un grup întreg = mută toate host-urile din folder în noul nume
  async function renameGroup(folder: string) {
    const next = await promptText({
      title: t('sidebar.renameGroupDlgTitle'), message: t('sidebar.promptRenameGroup', { folder }),
      label: t('sidebar.groupNameLabel'), defaultValue: folder,
    })
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
    const r = await api<{ ok: boolean; warning?: string }>(`/api/hosts/${host.id}/require-2fa`, {
      method: 'POST',
      body: JSON.stringify({ enabled: !host.require_2fa }),
    }).catch(fail)
    props.onChanged()
    // 3.5.13: activarea nu e blocată, dar fără passkey/TOTP contul nu va mai putea deschide
    // hostul — spunem acum (nu la primul Conectare) şi oferim drumul la Setări → 2FA
    if (r && r.warning === 'stepup.needsFactor') {
      if (await confirm({
        title: t('stepup.needsFactorTitle'), message: t('host.require2faNoFactor', { name: host.name }),
        confirmLabel: t('stepup.openSignin'),
      })) {
        setSettingsCat({ cat: 'autentificare', section: 'totp' })
        setShowSettings(true)
      }
    }
  }

  async function provision(host: Host) {
    if (!(await confirm({
      title: t('sidebar.installAgentSsh'), message: t('sidebar.confirmProvision', { name: host.name }),
      confirmLabel: t('sidebar.dlgInstall'),
    }))) return
    setProvisioning(host.name)
    try {
      const r = await api<{ credentials_deleted: boolean }>(`/api/hosts/${host.id}/provision`, { method: 'POST' })
      // Rezultatul e un toast (nu alert): omul vede oricum hostul trecând online în listă.
      notify(t('sidebar.provisionDoneTitle', { name: host.name }),
        t('sidebar.provisionDoneBody') + (r.credentials_deleted ? ' ' + t('sidebar.provisionCredsRemoved').trim() : ''), 'info')
      props.onChanged()
    } catch (e) {
      notifyError(t('sidebar.provisionFailed').replace(/:\s*$/, ''), errText(e, t) || t('sidebar.error'))
    } finally {
      setProvisioning(null)
    }
  }

  const [collapsedFolders, setCollapsedFolders] = useState<Record<string, boolean>>({})
  const [groupFilter, setGroupFilter] = useState<string | null>(null)

  // grupurile existente (foldere) pentru filtrare rapidă
  const groups = [...new Set(props.hosts.map((h) => h.folder || '').filter(Boolean))].sort()
  // etichetele deja folosite → sugestii în Add-host (evită fragmentarea taxonomiei: web/webserver)
  const allTags = [...new Set(props.hosts.flatMap((h) => h.tags || []))].sort()

  // Ţintele SSH-jump/telnet-prin-agent se salvează cu `via_host_id` = agentul prin care se
  // tunelează. În sidebar le cuibărim SUB acel agent (nu în lista plată de foldere), ca să
  // se vadă dintr-o privire „de cine atârnă". `isNested` le exclude din bucla de foldere.
  // ...dar doar dacă părintele chiar există în listă: un rând cu `via_host_id` către un host
  // şters (DB-uri de dinainte de curăţarea în cascadă din delete_host) ar dispărea altfel din
  // sidebar pentru totdeauna — nici în folder, nici sub un părinte — şi n-ar mai putea fi şters.
  const parentIds = new Set(props.hosts.map((h) => h.id))
  const isNested = (h: Host) => h.via_host_id != null && parentIds.has(h.via_host_id)
  // ţintele EFEMERE („conectează o dată", fără salvare) nu apar nicăieri în sidebar — nici în
  // arbore, nici cuibărite sub agent; trăiesc doar cât sesiunea, apoi reaper-ul le şterge.
  const childrenOf = (id: number) => props.hosts.filter((h) => h.via_host_id === id && !h.ephemeral)

  const q = query.trim().toLowerCase()
  // potrivirea pe text (nume/hostname/tag) — folosită și pentru ţintele cuibărite, care
  // atârnă de părinte, nu de un folder, deci NU trec prin filtrul de grup
  const textMatches = (h: Host) =>
    !q || h.name.toLowerCase().includes(q) || (h.hostname ?? '').toLowerCase().includes(q)
      || (h.tags || []).some((tag) => tag.toLowerCase().includes(q))
  // o ţintă cuibărită care se potriveşte îşi „trage" părintele în listă chiar dacă el nu se
  // potriveşte — altfel „db-01" (jump prin „bastion") era de negăsit din căutare
  const subtreeMatches = (h: Host, depth = 0): boolean =>
    depth < 4 && childrenOf(h.id).some((c) => textMatches(c) || subtreeMatches(c, depth + 1))
  const hostMatches = (h: Host) =>
    (!groupFilter || (h.folder || '') === groupFilter) && (textMatches(h) || subtreeMatches(h))

  // Sidebar = navigare: card de host → deschide pagina hostului. Sesiunile
  // (active + închise, istoric, atașare) trăiesc în pagina hostului, nu aici.
  const renderHost = (host: Host, depth = 0) => {
    const liveCount = props.sessions.filter(
      (s) => s.host_id === host.id && isSessionLive(s, props.hosts)).length
    const selected = props.selectedHost === host.id
    const canConnect = host.connection_type !== 'agent' || host.online
    const color = hostColor(host)
    const reach = reachState(host)
    // ţintele cuibărite sub acest host (SSH-jump / telnet-prin-agent), filtrate ca lista principală
    const kids = depth < 4 ? childrenOf(host.id).filter((c) => textMatches(c) || subtreeMatches(c, depth + 1)) : []
    // părinte afişat DOAR fiindcă un copil se potriveşte: estompat, ca să se vadă cine e rezultatul
    const viaChild = !!q && !textMatches(host)
    return (
      <Fragment key={host.id}>
      <div className="px-2 py-0.5"
        style={depth ? { paddingLeft: depth * 18 + 8 } : undefined}>
        <div
          onClick={() => props.onSelectHost(host.id)}
          style={selected ? { boxShadow: `inset 2px 0 0 ${color}` } : undefined}
          className={`group flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 ${
            selected ? 'bg-ink-800 ring-1 ring-ink-700' : 'hover:bg-ink-800/60'
          } ${viaChild ? 'opacity-60' : ''}`}
        >
          <div className="relative shrink-0">
            <div className="grid h-8 w-8 place-items-center rounded-md" style={{ background: `${color}22`, color }}>
              <ServerIcon />
            </div>
            {/* starea NU e doar culoare (WCAG 1.4.1): on-demand = inel gol, online = plin,
                offline = gri; textul pentru cititoare stă în span-ul sr-only de lângă nume */}
            <span
              aria-hidden="true"
              className={`absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full ring-2 ring-ink-900 ${
                reach === 'online' ? 'bg-emerald-400' : reach === 'ondemand' ? 'border-2 border-sky-500 bg-ink-900' : 'bg-slate-500'
              }`}
              title={reach === 'online' ? t('sidebar.stateOnline') : reach === 'ondemand' ? t('dashboard.onDemandConnect') : t('sidebar.stateOffline')}
            />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              {/* acţiunea principală stă pe NUMELE hostului, buton adevărat: rândul întreg
                  rămâne doar ţintă de mouse. `role="button"` pe div ar imbrica controalele
                  din rând (⋯, taguri, ✎) — exact violarea pe care poarta axe o prinde.
                  Acelaşi tipar ca pe cardurile din Dashboard. */}
              <button type="button"
                onClick={(e) => { e.stopPropagation(); props.onSelectHost(host.id) }}
                className="min-h-6 min-w-0 truncate rounded-md text-left text-sm font-medium focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-500">
                {host.name}
                <span className="sr-only">
                  {' — '}{reach === 'online' ? t('sidebar.stateOnline') : reach === 'ondemand' ? t('dashboard.onDemandConnect') : t('sidebar.stateOffline')}
                </span>
              </button>
              {/* hostul cere 2FA (step-up) la conectare: semnal mic, permanent — altfel afli abia
                  când ţi se cere codul. Textul stă în aria-label/title (role=img), nu doar culoare. */}
              {!!host.require_2fa && (
                <span role="img"
                  title={t('sidebar.require2faBadge')}
                  aria-label={t('sidebar.require2faBadgeAria', { name: host.name })}
                  className="wt-good shrink-0 leading-none opacity-80">
                  <ShieldSmallIcon />
                </span>
              )}
              {liveCount > 0 && (
                <Badge tone="ok" title={t('sidebar.liveSessions', { count: liveCount })}>
                  {liveCount}
                </Badge>
              )}
              {/* update-uri OS în aşteptare (din diagnosticele agentului v51+). Semnal DISCRET, sub
                  liveness şi sesiuni în ierarhie: update-urile obişnuite = doar număr în contur
                  (fără fond saturat — „încurca"), securitatea = punct roşu + număr. Modul global
                  şi mascarea per host vin din lib/updatesPref (Setări → Preferinţe, meniul ⋯). */}
              {(() => {
                const sig = updatesSignal(host.id, host.updates, updPref.mode, updPref.muted)
                if (sig === 'none' || !host.updates) return null
                const label = sig === 'security'
                  ? t('updates.badgeSecTitle', { count: host.updates.count, sec: host.updates.security ?? 0 })
                  : t('updates.badgeTitle', { count: host.updates.count })
                return (
                  <button type="button"
                    onClick={(e) => { e.stopPropagation(); setUpdFor(host) }}
                    title={label} aria-label={label}
                    className={`relative inline-flex min-h-6 shrink-0 items-center gap-1 rounded-full px-1.5 text-2xs tabular-nums ring-1 before:absolute before:-inset-1.5 before:content-[''] ${sig === 'security'
                      ? 'wt-danger font-semibold ring-rose-500/40 hover:bg-rose-500/10'
                      : 'text-slate-500 ring-ink-700 hover:bg-ink-800 hover:text-slate-300'}`}>
                    {sig === 'security'
                      ? <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-rose-500" />
                      : <ArrowUpIcon size={11} />}
                    {host.updates.count}
                  </button>
                )
              })()}
              {/* agentul NU porneşte singur la boot (agent v57+): după un reboot hostul rămâne offline
                  până îl porneşte cineva prin SSH. Semnal discret; detaliul + butonul sunt în
                  pagina hostului (cardul Agent). Necunoscut (agent mai vechi) = nimic. */}
              {(!host.connection_type || host.connection_type === 'agent') && host.supervision?.boot === false && (
                <span role="img"
                  title={t('sidebar.noAutostartTitle')}
                  aria-label={t('sidebar.noAutostartAria', { name: host.name })}
                  className="wt-warn shrink-0 leading-none opacity-70"><WarningIcon size={12} /></span>
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
            {host.tags && host.tags.length > 0 && (
              <div className="mt-0.5 flex flex-wrap gap-1">
                {host.tags.map((tag) => (
                  <button key={tag} type="button"
                    onClick={(e) => { e.stopPropagation(); setQuery(tag) }}
                    title={t('sidebar.filterByTag', { tag })}
                    className="relative inline-flex min-h-6 items-center rounded-md bg-ink-700/60 px-1.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-slate-200">
                    {tag}
                  </button>
                ))}
              </div>
            )}
            {/* host de agent căzut: de cât timp (heartbeat-ul din urmă) + nota — ca peste două
                săptămâni să ştii DE CE e jos („l-am oprit eu", „aşteaptă piese"), fără arheologie */}
            {reach === 'offline' && (
              <div className="mt-0.5 flex min-w-0 items-center gap-1 text-xs text-slate-500">
                <span className="shrink-0"
                  title={host.last_heartbeat ? fmtTs(host.last_heartbeat) : undefined}>
                  {host.last_heartbeat
                    ? t('sidebar.downFor', { ago: timeAgo(host.last_heartbeat, t) })
                    : t('sidebar.downNoHeartbeat')}
                </span>
                {host.note && <span className="truncate italic" title={host.note}>· {host.note}</span>}
                <IconButton touch={false}
                  onClick={(e) => { e.stopPropagation(); editNote(host) }}
                  label={t('sidebar.noteAria', { name: host.name })}
                  className="opacity-0 focus-visible:opacity-100 group-hover:opacity-100 [@media(hover:none)]:opacity-100"
                ><NoteIcon /></IconButton>
                {/* Alerte offline on/off: mut = clopoţel tăiat, vizibil şi fără hover (ca să ştii
                    că e tăcut); pornit = doar la hover. Doar host-uri de agent (doar ele alertează). */}
                {(!host.connection_type || host.connection_type === 'agent') && (
                  <button
                    onClick={(e) => { e.stopPropagation(); muteHost(host, !host.alerts_muted) }}
                    title={host.alerts_muted ? t('sidebar.alertsMutedTitle') : t('sidebar.alertsOnTitle')}
                    aria-label={host.alerts_muted
                      ? t('sidebar.alertsUnmuteAria', { name: host.name })
                      : t('sidebar.alertsMuteAria', { name: host.name })}
                    className={`grid min-h-6 min-w-6 shrink-0 place-items-center rounded-md p-1 focus-visible:opacity-100 ${host.alerts_muted
                      ? 'wt-warn opacity-100 hover:opacity-80'
                      : 'opacity-0 hover:text-slate-200 group-hover:opacity-100 [@media(hover:none)]:opacity-100'}`}
                  >{host.alerts_muted ? <BellOffIcon /> : <BellIcon />}</button>
                )}
                {/* Wake-on-LAN: cere unui agent vecin din acelaşi LAN să trimită magic packet-ul.
                    Doar host-uri de agent (WoL n-are sens pe SSH/telnet). */}
                {canWake(host) && (
                  <IconButton touch={false}
                    onClick={(e) => { e.stopPropagation(); wakeHost(host) }}
                    disabled={waking === host.id}
                    title={t('sidebar.wakeTitle')} label={t('sidebar.wakeAria', { name: host.name })}
                  >{waking === host.id ? '…' : <PowerIcon size={14} />}</IconButton>
                )}
              </div>
            )}
            {host.conflict && (
              <div className="flex items-center gap-1 text-xs wt-danger"
                title={t('sidebar.conflictTitle')}>
                <span className="shrink-0"><WarningIcon size={12} /></span><span className="truncate">{t('sidebar.conflictBody')}</span>
              </div>
            )}
            {/* link de instalare încă valabil şi nefolosit: ca să observi unul uitat/scurs */}
            {host.enroll_pending && (
              <div className="flex items-center gap-1 text-xs wt-warn" title={t('sidebar.enrollPendingTitle')}>
                <span className="shrink-0"><LinkIcon size={12} /></span><span className="truncate">{host.enroll_protected ? t('sidebar.enrollPendingProtected') : t('sidebar.enrollPending')}</span>
              </div>
            )}
            {/* Agentul a fost scos de pe host cu `ptyd.py uninstall`. Nu ştergem nimic
                singuri: poate vrei doar să-l reinstalezi, caz în care marcajul dispare de la
                sine la reconectare. Ştergerea rămâne o apăsare conştientă, aici. */}
            {host.uninstalled_at && !host.online && (
              <div className="mt-1 flex items-center gap-2">
                <span className="flex min-w-0 items-center gap-1 text-xs wt-warn" title={t('sidebar.uninstalledTitle')}>
                  <span className="shrink-0"><WarningIcon size={12} /></span><span className="truncate">{t('sidebar.uninstalledBadge')}</span>
                </span>
                <button
                  onClick={(e) => { e.stopPropagation(); deleteHost(host) }}
                  className="wt-danger shrink-0 rounded-md px-1.5 py-1 text-2xs ring-1 ring-ink-700 hover:bg-ink-800"
                >{t('sidebar.uninstalledRemove')}</button>
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
              // tokeni de stare (nu bg-rose-900/60): pe Aurora fundalul închis + roşul închis al
              // textului dădeau ~2:1
              className="shrink-0 cursor-help rounded-md bg-danger/10 px-1.5 py-0.5 text-xs text-danger"
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
              className="shrink-0 rounded-md bg-warn/10 px-1.5 py-1 text-xs text-warn hover:bg-warn/20"
            >
              ↑ v{host.agent_latest}
            </button>
          )}
          {/* „Sesiune nouă" a plecat de aici în meniul ⋯. Butonul apărea la hover, deci pe
              rândul îngust concura cu numele hostului şi cu insigna de update; în meniu are
              text întreg, primul loc şi un separator după el. */}
          <span onClick={(e) => e.stopPropagation()}>
            <HostMenu
              online={host.online}
              canConnect={canConnect}
              onNewSession={() => props.onNewSession(host)}
              require2fa={!!host.require_2fa}
              connectionType={host.connection_type}
              hostId={host.id}
              onFiles={() => props.onFiles(host)}
              onSerial={() => props.onSerial(host)}
              onAddJump={() => setJumpVia(host)}
              onDiagnostic={() => props.onDiagnostic(host)}
              onFolder={() => moveToFolder(host)}
              onEdit={() => setEditHost(host)}
              onReinstall={() => reinstall(host)}
              onProvision={() => provision(host)}
              onToggle2fa={() => toggle2fa(host)}
              updatesMuted={updPref.muted.has(host.id)}
              onToggleUpdatesMute={() => setHostMuted(host.id, !updPref.muted.has(host.id))}
              onUninstall={() => uninstallHost(host)}
              onDelete={() => deleteHost(host)}
            />
          </span>
        </div>
      </div>
      {kids.map((c) => renderHost(c, depth + 1))}
      </Fragment>
    )
  }

  // versiunea vine din headerul X-Webterm-Version al primului răspuns (fără apel dedicat);
  // hosturile online le avem deja în props — sidebarul le primeşte oricum pentru listă
  const version = getBootVersion()
  const hostsOnline = props.hosts.filter((h) => h.online).length

  // Lăţimea sidebar-ului (doar desktop), trasă de mânerul din dreapta şi persistată:
  // mai lat = note/taguri/hostname-uri fără truncare; mai îngust = mai mult terminal.
  // Drawer-ul mobil rămâne fix (w-72) — acolo lăţimea o dă degetul, nu preferinţa.
  const SB_MIN = 220, SB_MAX = 560, SB_DEF = 288
  const [sbWidth, setSbWidth] = useState(() => {
    try {
      const v = Number(lsGet('wt_sidebar_w'))
      return v >= SB_MIN && v <= SB_MAX ? v : SB_DEF
    } catch { return SB_DEF }
  })
  const clampSb = (w: number) => Math.min(SB_MAX, Math.max(SB_MIN, w))
  const saveSbWidth = (w: number) => { try { localStorage.setItem('wt_sidebar_w', String(w)) } catch { /* */ } }
  // curăţenia unui drag în curs, ţinută într-un ref: dacă Sidebar se demontează la jumătatea
  // unui drag, un useEffect scoate listenerii de pe window (altfel ar rămâne agăţaţi)
  const dragCleanup = useRef<(() => void) | null>(null)
  useEffect(() => () => dragCleanup.current?.(), [])
  const dragSb = (e: ReactPointerEvent) => {
    e.preventDefault()
    // sidebar-ul e lipit de marginea stângă → clientX E lăţimea; fără măsurători de rect
    const move = (ev: PointerEvent) => setSbWidth(clampSb(ev.clientX))
    const detach = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      dragCleanup.current = null
    }
    const up = (ev: PointerEvent) => { detach(); saveSbWidth(clampSb(ev.clientX)) }
    dragCleanup.current = detach
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const body = (
    <div className="wt-sidebar flex h-full w-full flex-col border-r border-ink-800 bg-ink-900">
      {/* overflow-hidden + min-w-0: garantează că butoanele de header NU ies din
          lățimea sidebar-ului peste conținutul principal (altfel un buton acoperă
          „Acasă" din TabBar pe desktop) */}
      <div className="wt-sbhead flex items-center justify-between gap-1 overflow-hidden border-b border-ink-800 px-4 py-3">
        {/* Sigla e mereu vizibilă; cuvântul „WebTerm" apare DOAR când încape (container query pe
            antet, vezi .wt-wordmark în index.css). Înainte se trunchia la „WebT…" lângă cele şase
            butoane — pe lăţimea implicită de 288px şi mereu pe telefon (butoane de 44px). Numele
            accesibil rămâne în aria-label/title. */}
        <button
          onClick={() => setShowAbout(true)}
          title={t('nav.about')}
          aria-label={t('nav.about')}
          className="wt-touch flex min-h-8 min-w-8 shrink-0 items-center justify-center gap-2 rounded-md py-1 font-semibold tracking-tight hover:underline"
        >
          <LogoMark /><span className="wt-wordmark whitespace-nowrap">WebTerm</span>
        </button>
        {/* `wt-touch` (44px, activ doar sub `pointer: coarse`) pe navigaţia PRINCIPALĂ.
            Auditul mobil raportează ţintele mici ca `ux`, nu ca `bug`, deci nu blochează
            imaginea — dar astea patru sunt butoanele atinse de zeci de ori pe zi, şi erau
            32×24. Restul listei rămâne raportat şi nereparat în bloc: pe iconiţele dintr-un
            rând dens de fişiere, 44px ar rupe layout-ul — acolo compromisul e deliberat. */}
        <div className="flex shrink-0 items-center gap-0.5">
          {/* Doar pe desktop: pe mobil sidebarul e un drawer, care se închide oricum. */}
          <IconButton size="md" label={t('nav.collapseSidebar')}
            onClick={props.onToggleCollapse}
            className="hidden md:grid"
          >
            <CollapseIcon />
          </IconButton>
          <IconButton size="md" label={t('nav.addHost')} onClick={() => setShowAdd(true)}>
            <PlusIcon />
          </IconButton>
          <IconButton size="md" label={t('nav.fleetRunAria')} title={t('nav.fleetRun')}
            onClick={() => setShowFleetRun(true)}>
            <TerminalPromptIcon />
          </IconButton>
          <IconButton size="md" label={t('nav.status')} onClick={() => setShowStatus(true)}>
            <ActivityIcon />
          </IconButton>
          <IconButton size="md"
            title={props.signingLocked
              ? t('sidebar.settingsSigningLocked')
              : props.signingMissing ? t('sidebar.settingsSigningMissing')
                : props.backupReady ? t('sidebar.settingsBackupReady') : t('sidebar.settingsPasskeys')}
            onClick={() => { setSettingsCat(undefined); setShowSettings(true) }}
            label={t('settings.title')}
            className="relative"
          >
            <GearIcon />
            {(props.backupReady || props.signingMissing || props.signingLocked) && (
              // decorativ: starea e deja în title-ul TRADUS al butonului părinte; aria-label pe
              // un span non-interactiv e oricum ignorat de cititoare (şi era hard-codat, cu
              // engleza şi româna amestecate — scăpa testului i18n, care prinde doar literali)
              <span aria-hidden="true"
                className={`absolute right-1 top-1 h-2 w-2 rounded-full ring-2 ring-ink-900 ${
                  props.signingLocked ? 'bg-rose-500' : props.signingMissing ? 'bg-amber-400' : 'bg-sky-400'}`} />
            )}
          </IconButton>
          <IconButton size="md" label={t('sidebar.signOut')} onClick={props.onLogout}>
            <PowerIcon />
          </IconButton>
        </div>
      </div>

      {/* rândul de căutare + clopoţelul de alerte (3.5.11). Clopoţelul NU stă în antet: acolo
          şase butoane umplu deja lăţimea implicită (288px) — un al şaptelea ieşea din sidebar pe
          desktop şi tăia „Deconectare" în drawer-ul de 44px/buton de pe telefon. */}
      <div className="flex items-center gap-1 px-3 py-2">
      <div className="relative min-w-0 flex-1">
        <span className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-slate-400">
          <SearchIcon />
        </span>
        <input
          data-wt-search
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label={t('sidebar.searchAria')}
          placeholder={t('sidebar.searchPlaceholder')}
          className="w-full rounded-md bg-ink-800 py-1.5 pl-8 pr-7 text-sm placeholder-slate-600 ring-1 ring-ink-700 focus:ring-sky-600"
        />
        {query ? (
          <IconButton touch={false}
            onClick={() => setQuery('')}
            label={t('sidebar.clearSearch')}
            className="absolute right-1 top-1/2 -translate-y-1/2"
          >
            <CloseIcon size={13} />
          </IconButton>
        ) : (
          /* badge-ul de scurtătură: doar unde EXISTĂ tastatură */
          <button
            onClick={props.onOpenPalette}
            title={t('sidebar.paletteTitle', { key: fmt('Mod+K') })}
            aria-label={t('sidebar.openPalette')}
            className="absolute right-0 top-1/2 hidden min-h-6 -translate-y-1/2 items-center rounded-md bg-white/5 px-1.5 text-2xs text-slate-400 hover:bg-white/10 hover:text-slate-200 [@media(hover:hover)]:inline-flex"
          >
            {fmt('Mod+K')}
          </button>
        )}
      </div>
      <AlertsBell hosts={props.hosts}
        onOpenHost={(id) => { props.onSelectHost(id); props.onClose() }}
        onOpenSettings={() => { setSettingsCat({ cat: 'notificari', section: 'alertPrefs' }); setShowSettings(true) }} />
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
          <div className="space-y-3 p-4 text-sm text-slate-500">
            <p>{t('sidebar.noHostsYet')}</p>
            {/* CTA vizibil: butonul din header e doar un „+" fără text, uşor de ratat */}
            <Button type="button" variant="primary" onClick={() => setShowAdd(true)}>
              <PlusIcon /> {t('nav.addHost')}
            </Button>
          </div>
        )}
        {(() => {
          // ţintele cuibărite (via_host_id) NU intră în bucla de foldere: le randează
          // recursiv renderHost sub agentul-părinte. Altfel ar apărea de două ori.
          const visible = props.hosts.filter((h) => hostMatches(h) && !isNested(h) && !h.ephemeral)
          // grupurile cu nume întâi (alfabetic), hosturile fără folder la FINAL —
          // altfel plutesc deasupra grupurilor etichetate și par un bug de randare
          const folders = [...new Set(visible.map((h) => h.folder || ''))].sort((a, b) =>
            a === '' ? 1 : b === '' ? -1 : a.localeCompare(b))
          const hasNamed = folders.some((f) => f !== '')
          return folders.map((folder) => {
            // host-urile căzute stau la FUNDUL grupului: sus rămâne „ce pot folosi acum",
            // iar un host oprit intenţionat nu se mai amestecă printre cele vii. Partiţie
            // stabilă — ordinea existentă se păstrează în interiorul fiecărei jumătăţi.
            const inAll = visible.filter((h) => (h.folder || '') === folder)
            const inFolder = [...inAll.filter((h) => reachState(h) !== 'offline'),
                              ...inAll.filter((h) => reachState(h) === 'offline')]
            const nDown = inFolder.filter((h) => reachState(h) === 'offline').length
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
                      <ChevronIcon open={!collapsed} size={12} />
                      <span className="opacity-70"><FolderMoveIcon /></span>
                      <span className={`truncate ${folder ? '' : 'italic text-slate-400'}`}>{folder || t('sidebar.noFolder')}</span>
                    </button>
                    {folder && (
                      <button
                        onClick={() => renameGroup(folder)}
                        title={t('sidebar.renameGroupAria', { folder })}
                        aria-label={t('sidebar.renameGroupAria', { folder })}
                        className="shrink-0 rounded-md p-1 opacity-0 hover:text-slate-200 focus-visible:opacity-100 group-hover/folder:opacity-100 [@media(hover:none)]:opacity-100"
                      >
                        <NoteIcon />
                      </button>
                    )}
                    {/* export CSV al grupului: dialogul se deschide cu hosturile folderului bifate */}
                    <button
                      onClick={() => setExportCsv({ folder })}
                      title={t('hostcsv.exportFolderAria', { folder: folder || t('sidebar.noFolder') })}
                      aria-label={t('hostcsv.exportFolderAria', { folder: folder || t('sidebar.noFolder') })}
                      className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md opacity-0 hover:text-slate-200 focus-visible:opacity-100 group-hover/folder:opacity-100 [@media(hover:none)]:opacity-100"
                    >
                      <DownloadIcon />
                    </button>
                    {/* cu host-uri căzute în grup, contorul devine „vii/total" — altfel un grup
                        PLIAT ascundea complet că are ceva jos */}
                    <span className="shrink-0 text-slate-400"
                      title={nDown > 0 ? t('sidebar.groupDownCount', { down: nDown }) : undefined}>
                      {nDown > 0 ? `${inFolder.length - nDown}/${inFolder.length}` : inFolder.length}
                    </span>
                  </div>
                )}
                {/* NU `inFolder.map(renderHost)`: `.map` ar pasa indexul drept `depth`, indentând
                    fiecare host progresiv (bug „decalat"). Apel explicit, depth 0 la rădăcină. */}
                {!collapsed && inFolder.map((h) => renderHost(h))}
              </div>
            )
          })
        })()}

        {historyHits !== null && (
          <div className="border-t border-ink-800 pb-2">
            <div className="px-4 pb-1 pt-3 text-xs font-medium uppercase tracking-wide text-slate-400">
              {t('sidebar.inSessionHistory')}
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
                  <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${stateDot[h.state]}`} />
                  <span className="sr-only">
                    {h.state === 'lost' ? t('host.stateLost') : h.state === 'closed' ? t('host.stateClosed') : t('host.stateActive')}
                  </span>
                  <span className="truncate text-sm">{h.title || t('sidebar.untitled')}</span>
                  {h.matches > 0 && (
                    <span className="ml-auto shrink-0 text-2xs text-slate-400">
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
        className="flex shrink-0 items-center gap-2 border-t border-ink-800 px-3 py-1.5 text-left text-2xs text-slate-500 hover:bg-ink-800/60"
      >
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${
          props.hosts.length === 0 ? 'bg-slate-600'
            : hostsOnline === props.hosts.length ? 'bg-emerald-500'
              : hostsOnline === 0 ? 'bg-rose-500' : 'bg-amber-500'}`} />
        <span className="tabular-nums">
          {hostsOnline}/{props.hosts.length} {t('nav.statusBarHosts')}
        </span>
        {newVersion && (
          // textul spune CE e (nu doar un număr de versiune lângă alt număr de versiune);
          // min-w-0 + truncate: în sidebarul îngust se scurtează pastila, nu se rupe bara
          <span className="wt-warn ml-auto min-w-0 truncate rounded-full bg-amber-500/15 px-1.5 py-0.5 text-2xs font-medium ring-1 ring-amber-500/25">
            {t('sidebar.updatePill', { version: newVersion })}
          </span>
        )}
        <span className={`font-mono text-slate-400 ${newVersion ? '' : 'ml-auto'}`}>v{version || '—'}</span>
      </button>
    </div>
  )

  return (
    <>
      {/* desktop — ascuns când e pliat; terminalul primeşte lăţimea înapoi.
          Redeschiderea se face din butonul ☰ al barei de sus, care pe desktop apare
          EXACT când sidebarul e pliat (altfel ai plia fereastra fără cale de întoarcere). */}
      <div className={props.collapsed ? 'hidden' : 'relative hidden shrink-0 md:block'}
        style={{ width: sbWidth }}>
        {body}
        {/* mâner de redimensionare: tras cu mouse-ul, săgeţi de la tastatură (splitter
            focusabil — tiparul ARIA de „window splitter"), dublu-click = lăţimea implicită */}
        <div
          role="separator" aria-orientation="vertical" tabIndex={0}
          aria-label={t('sidebar.resizeAria')}
          aria-valuenow={sbWidth} aria-valuemin={SB_MIN} aria-valuemax={SB_MAX}
          title={t('sidebar.resizeAria')}
          onPointerDown={dragSb}
          onDoubleClick={() => { setSbWidth(SB_DEF); saveSbWidth(SB_DEF) }}
          onKeyDown={(e) => {
            const d = e.key === 'ArrowLeft' ? -16 : e.key === 'ArrowRight' ? 16 : 0
            if (!d) return
            e.preventDefault()
            const w = clampSb(sbWidth + d)
            setSbWidth(w); saveSbWidth(w)
          }}
          className="absolute inset-y-0 -right-1 z-10 w-2 cursor-col-resize rounded-md hover:bg-sky-500/30 focus:outline-none focus-visible:bg-sky-500/50"
        />
      </div>
      {/* mobile drawer — lăţime fixă (body-ul e w-full, lăţimea o dă wrapperul) */}
      {props.open && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/70" onClick={props.onClose} />
          {/* wt-drawer: fundal OPAC pe mobil. Sticla translucidă (--glass-bg) lăsa
              dashboard-ul să se vadă prin drawer — exact „suprapunerea" raportată */}
          <div className="wt-drawer absolute inset-y-0 left-0 w-72 shadow-2xl">{body}</div>
        </div>
      )}
      {/* modalele se randează o singură dată, nu în fiecare copie a sidebarului;
         lazy → sub Suspense (fallback null: apar oricum doar la deschidere) */}
      <Suspense fallback={null}>
        {showAdd && (
          <AddHostModal
            tagSuggestions={allTags}
            onSaved={props.onChanged}
            onExportCsv={() => { setShowAdd(false); setExportCsv({}) }}
            onClose={() => {
              setShowAdd(false)
              props.onChanged()
            }}
          />
        )}
        {exportCsv && (
          <ExportHostsModal hosts={props.hosts} presetFolder={exportCsv.folder} onClose={() => setExportCsv(null)} />
        )}
        {editHost && (
          <AddHostModal
            host={editHost}
            tagSuggestions={allTags}
            onSaved={props.onChanged}
            onClose={() => setEditHost(null)}
          />
        )}
        {jumpVia && (
          <AddHostModal
            tagSuggestions={allTags}
            presetJump={{ viaHostId: jumpVia.id, viaName: jumpVia.name }}
            onSaved={props.onChanged}
            onConnect={(h) => { props.onChanged(); props.onNewSession(h) }}
            onClose={() => { setJumpVia(null); props.onChanged() }}
          />
        )}
        {showSettings && (
          <SettingsModal
            email={props.email}
            webauthnAvailable={props.webauthnAvailable}
            // fără ţintă explicită, punctul de pe rotiţă alege: cheia de semnare (lipsă sau blocată —
            // acelaşi lucru îl spune şi title-ul rotiţei) → backup gata → Cont
            initialCat={settingsCat?.cat ?? (props.signingMissing || props.signingLocked ? 'infrastructura' : props.backupReady ? 'backup' : undefined)}
            initialSection={settingsCat?.section ?? (props.signingMissing || props.signingLocked ? 'signingKey' : undefined)}
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
            <div className="font-medium">{t('sidebar.provisioningTitle', { name: provisioning })}</div>
            <div className="text-sm text-slate-500">
              {t('sidebar.provisioning')}
            </div>
          </div>
        </div>
      )}
      {/* modal update-uri: ce e disponibil + „fă upgrade într-un terminal". Nu instalăm din UI —
          deschidem o sesiune cu comanda interactivă (glue, nu un package-manager reimplementat). */}
      {updFor && updFor.updates && (
        <UpdatesDialog host={updFor} onClose={() => setUpdFor(null)}
          onMute={() => { setHostMuted(updFor.id, true); setUpdFor(null) }}
          onUpgrade={() => { const h = updFor; setUpdFor(null); props.onUpgrade(h) }} />
      )}
    </>
  )
}

/** Modalul de update-uri OS. Componentă separată ca să poată avea focus-trap (hook-urile nu pot
    sta într-un JSX condiţional): Tab rămâne înăuntru, Escape închide, focusul se întoarce pe badge. */
function UpdatesDialog(props: { host: Host; onClose: () => void; onUpgrade: () => void; onMute: () => void }) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  const u = props.host.updates!
  return (
    <div role="presentation" className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) props.onClose() }}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="wt-upd-title"
        className="glass w-full max-w-sm rounded-2xl p-5">
        <h2 id="wt-upd-title" className="text-base font-semibold">{t('updates.title', { name: props.host.name })}</h2>
        <p className="mt-2 text-sm text-slate-300">
          {t('updates.available', { count: u.count, mgr: u.manager || '?' })}
        </p>
        {!!u.security && (
          <p className="wt-danger mt-1 text-sm font-medium">
            {t('updates.securityLine', { sec: u.security })}
          </p>
        )}
        <p className="mt-2 text-xs text-slate-500">{t('updates.hint')}</p>
        <div className="mt-4 flex flex-wrap items-center justify-end gap-2 text-sm">
          {/* „nu-mi mai arăta" direct de unde vezi semnalul; revenirea e din meniul ⋯ al hostului */}
          <Button variant="ghost" size="sm" onClick={props.onMute} title={t('updates.muteHostHint')}
            className="mr-auto">{t('updates.muteHost')}</Button>
          <Button variant="ghost" onClick={props.onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={props.onUpgrade}>
            {t('updates.openTerminal')}
          </Button>
        </div>
      </div>
    </div>
  )
}

function GroupChip(props: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={props.onClick}
      aria-pressed={props.active}
      className={`rounded-full px-2.5 py-1 text-xs font-medium ring-1 transition ${
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
  canConnect: boolean
  onNewSession: () => void
  onFiles: () => void
  onSerial: () => void
  onAddJump: () => void
  onDiagnostic: () => void
  onFolder: () => void
  onEdit: () => void
  onReinstall: () => void
  onProvision: () => void
  onToggle2fa: () => void
  updatesMuted: boolean
  onToggleUpdatesMute: () => void
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
  const item = 'flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm hover:bg-ink-800'
  // La alegerea unei acţiuni meniul se închide şi item-ul dispare din DOM; dacă acţiunea deschide
  // un dialog (confirmare de ştergere), focus-trap-ul lui ar memora un element deja demontat
  // şi la Escape focusul ar cădea pe <body>. APG: închiderea unui meniu întoarce focusul pe
  // butonul lui — aşa dialogul porneşte de pe ⋯, un element stabil, şi tot acolo revine.
  const btnRef = useRef<HTMLButtonElement>(null)
  const act = (fn: () => void) => () => { setOpen(false); btnRef.current?.focus(); fn() }
  return (
    <div className="relative shrink-0">
      <IconButton
        ref={btnRef}
        label={t('sidebar.hostActions')} aria-haspopup="menu" aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <MoreIcon />
      </IconButton>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div role="menu" className="absolute right-0 z-40 mt-1 w-48 rounded-xl border border-ink-700 bg-ink-900 p-1 shadow-2xl">
            {/* Acţiunea pentru care deschizi meniul în 90% din cazuri stă prima, iar linia de
                sub ea o separă de administrare (fişiere, editare, dezinstalare) — ca un click
                greşit din inerţie să nu nimerească altceva. */}
            <button
              role="menuitem"
              disabled={!props.canConnect}
              onClick={act(props.onNewSession)}
              title={props.connectionType !== 'agent' ? t('sidebar.connect')
                     : props.online ? t('sidebar.newSession') : t('sidebar.hostOffline')}
              aria-label={props.online || props.connectionType !== 'agent'
                          ? t('host.newSession')
                          : `${t('host.newSession')} — ${t('sidebar.hostOffline')}`}
              className={`${item} font-medium text-slate-100 disabled:cursor-not-allowed disabled:text-slate-500 disabled:hover:bg-transparent`}
            >
              <PlusIcon /> {props.connectionType !== 'agent' ? t('sidebar.connect') : t('sidebar.newSession')}
            </button>
            <div className="my-1 border-t border-ink-700" role="separator" />
            {/* Files merge doar prin agent: pe SSH/telnet apelurile picau cu „host offline" */}
            {props.online && (!props.connectionType || props.connectionType === 'agent') && (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onFiles)}>
                <FilesIcon /> {t('sidebar.files')}
              </button>
            )}
            {props.online && (!props.connectionType || props.connectionType === 'agent') && (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onSerial)}>
                <PlugIcon /> {t('sidebar.serialConsole')}
              </button>
            )}
            {(!props.connectionType || props.connectionType === 'agent') && (
              // SSH-jump: adaugă o ţintă din LAN-ul acestui agent, tunelată prin el. Ţinta
              // salvată apare cuibărită sub host, în sidebar.
              <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onAddJump)}>
                <SubItemIcon /> {t('sidebar.addSshJump')}
              </button>
            )}
            {(!props.connectionType || props.connectionType === 'agent') && (
              // și când e OFFLINE: exact atunci vrei să vezi DE CE (jurnal de conexiune)
              <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onDiagnostic)}>
                <StethoscopeIcon /> {t('sidebar.diagnostic')}
              </button>
            )}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onEdit)}>
              <PencilIcon size={16} /> {t('sidebar.editHost')}
            </button>
            <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onFolder)}>
              <FolderMoveIcon /> {t('sidebar.moveToGroup')}
            </button>
            {props.connectionType === 'ssh' ? (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onProvision)}>
                <RefreshIcon /> {t('sidebar.installAgentSsh')}
              </button>
            ) : (
              <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onReinstall)}>
                <RefreshIcon /> {t('sidebar.reinstallAgent')}
              </button>
            )}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onToggle2fa)}>
              <KeyIcon /> {props.require2fa ? t('sidebar.require2faOn') : t('sidebar.require2faOff')}
            </button>
            {/* mascarea per host a semnalului de update-uri OS (preferinţă locală, lib/updatesPref):
                pentru hostul pe care-l actualizezi oricum pe alt drum şi nu vrei badge-ul în listă */}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={act(props.onToggleUpdatesMute)}>
              {props.updatesMuted ? <ArrowUpIcon size={16} /> : <BanIcon size={16} />}
              {props.updatesMuted ? t('updates.unmuteHost') : t('updates.muteHostMenu')}
            </button>
            {/* schemă de culori proprie hostului: „producția e roșiatică" —
                un semnal vizual imposibil de ratat când ai 5 host-uri deschise */}
            <button role="menuitem" className={`${item} text-slate-200`} onClick={() => setSchemeOpen((v) => !v)}>
              <PaletteIcon /> {t('sidebar.hostColours')}
            </button>
            {schemeOpen && (
              <div className="mb-1 ml-6 mr-1 space-y-0.5">
                <button
                  role="menuitem"
                  onClick={() => { setHostScheme(props.hostId, null); setOpen(false) }}
                  className={`${item} py-1 text-xs ${!hostSchemeRaw(props.hostId) ? 'wt-accent' : 'text-slate-400'}`}
                >
                  {t('sidebar.globalScheme')}
                </button>
                {allSchemes().map((s) => (
                  <button
                    key={s.id}
                    role="menuitem"
                    onClick={() => { setHostScheme(props.hostId, s.id); setOpen(false) }}
                    className={`${item} py-1 text-xs ${hostSchemeRaw(props.hostId) === s.id ? 'wt-accent' : 'text-slate-400'}`}
                  >
                    <span className="flex gap-0.5" aria-hidden="true">
                      {[s.theme.red, s.theme.green, s.theme.blue].map((c, i) => (
                        <span key={i} className="h-2.5 w-1 rounded-md" style={{ background: c }} />
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
                onClick={act(props.onUninstall)}>
                <CloseIcon size={16} /> {t('sidebar.uninstallAgent')}
              </button>
            )}
            <button role="menuitem" className={`${item} wt-danger hover:underline`}
              title={(!props.connectionType || props.connectionType === 'agent')
                ? t('sidebar.removeOnlyTitle') : undefined}
              onClick={act(props.onDelete)}>
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
  // Era singurul dialog fără Escape/backdrop/focus-trap: ieşirea era DOAR butonul „Close",
  // iar Tab circula prin pagina de sub scrim.
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  return (
    <div role="presentation" className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) props.onClose() }}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="wt-cmdmodal-title"
        className="glass w-full max-w-xl rounded-2xl p-6">
        <h2 id="wt-cmdmodal-title" className="font-semibold">{t('sidebar.installAgentTitle')}</h2>
        <p className="mt-1 text-sm text-slate-500">
          {t('sidebar.reinstallHint')}
        </p>
        <InstallCommand command={props.cmd} commandDedicated={props.cmdDedicated} />
        <div className="mt-4 text-right">
          <Button variant="ghost" size="lg" onClick={props.onClose}>
            {t('sidebar.close')}
          </Button>
        </div>
      </div>
    </div>
  )
}
