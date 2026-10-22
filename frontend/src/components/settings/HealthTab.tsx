import { useEffect, useRef, useState } from 'react'
import { api, ApiError, ensureStepup, errText, isStepupError } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { useMediaQuery } from '../../lib/sheet'
import { fmtTs, getTimezone } from '../../lib/tz'
import { copyText } from '../../lib/clipboard'
import { askSecret } from '../../lib/secretPrompt'
import {
  actionTarget, canMute, checkText, docUrl, fixMode, MUTE_MODES, needsAttention, optText, severityTone, splitChecks,
  type HealthCheck, type HealthStatus, type MuteMode,
} from '../../lib/health'
import { heading } from './ui'
import HelpTip from '../HelpTip'
import { Badge, Button } from '../ui'
import { ChevronDownIcon } from '../Icons'
import FileMenu, { type MenuItem } from '../FileMenu'
import type { LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'

// System health (3.6.8): one list of everything that can fail silently — what, why it matters,
// what to do, and the exact command. Commands come from the server (an allow-list there); this
// panel only copies them or asks the server to TYPE one (not run it) into a terminal on the
// gateway host — and for that it sends the check id + the command's index, never the text.
export default function HealthTab(props: { onJump?: (cat: string, section?: string) => void }) {
  const { t } = useI18n()
  const vis = useSectionVisible()
  const [st, setSt] = useState<HealthStatus | null>(null)
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [copied, setCopied] = useState('')
  const [opening, setOpening] = useState('')
  const [showOk, setShowOk] = useState(false)
  const [hostBusy, setHostBusy] = useState(0)
  // The mute menu (audit 2026-10-17, UI-05). It used to be a `<select value="">` acting on `change`:
  // picking an option muted at once (WCAG 3.2.2 On Input), and on Firefox/Windows or with a screen
  // reader the arrow keys on a CLOSED select change the value without opening the list — a keyboard
  // user could silence a check (even one that can turn critical) just by exploring the options. Now a
  // "Mute…" button (aria-haspopup="menu", ArrowDown opens too) + the FileMenu pattern: role=menu, items
  // are buttons (Enter/Space activate, ↑/↓/Home/End move, Escape/Tab close), a bottom sheet on touch.
  // Focus returns to the button when the menu closes, whichever way it closed — and to the check
  // row (tabIndex -1) when the button is gone: an Admin on a `mute_owner_only` check sees the button
  // only while the check is muted, so "Unmute" unmounts it once the reply lands; without the
  // fallback focus fell to <body> on exactly the path UI-05 fixed. `preventScroll`: FileMenu closes
  // itself on any scroll of the panel, and the return focus must not yank the panel back.
  const [muteMenu, setMuteMenu] = useState<{ id: string; at: { x: number; y: number } } | null>(null)
  const muteBtns = useRef(new Map<string, HTMLButtonElement>())
  const rows = useRef(new Map<string, HTMLLIElement>())
  const focusNear = (id: string) => (muteBtns.current.get(id) ?? rows.current.get(id))?.focus({ preventScroll: true })
  const coarse = useMediaQuery('(pointer: coarse)')
  const openMute = (c: HealthCheck, el: HTMLButtonElement) => {
    const r = el.getBoundingClientRect()
    setMuteMenu({ id: c.id, at: { x: r.left, y: r.bottom + 4 } })
  }
  const closeMute = () => {
    const id = muteMenu?.id
    setMuteMenu(null)
    if (id) requestAnimationFrame(() => focusNear(id))
  }
  const muteItems = (c: HealthCheck): MenuItem[] => {
    const can = !!st && canMute(c, st)
    const items: MenuItem[] = can
      ? MUTE_MODES.map((m) => ({ key: m, label: t('health.mute.' + m), onSelect: () => { void mute(c, m) } }))
      : []
    if (c.muted) items.push({ key: 'off', label: t('health.mute.off'), sep: can, onSelect: () => { void mute(c, 'off') } })
    return items
  }

  const reload = () => {
    setLoad({ status: 'loading' })
    return api<HealthStatus>('/api/health')
      .then((s) => { setSt(s); setLoad({ status: 'ok' }) })
      .catch((e) => setLoad({ status: 'error', error: errText(e, t) }))
  }
  useEffect(() => { if (vis('systemHealth')) void reload() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  async function recheck() {
    setBusy(true); setMsg(''); setErr('')
    try {
      setSt(await api<HealthStatus>('/api/health/check', { method: 'POST' }))
      setMsg(t('health.rechecked'))
    } catch (e) { setErr(errText(e, t)) } finally { setBusy(false) }
  }

  async function mute(c: HealthCheck, mode: MuteMode) {
    setErr(''); setMsg('')
    try {
      setSt(await api<HealthStatus>(`/api/health/${encodeURIComponent(c.id)}/mute`, {
        method: 'POST', body: JSON.stringify({ mode }),
      }))
      setMsg(mode === 'off' ? t('health.unmuted') : t('health.mutedMsg'))
      // the reply may have unmounted the button that held focus (see the comment at `rows`)
      requestAnimationFrame(() => { if (!muteBtns.current.get(c.id) && document.activeElement === document.body) focusNear(c.id) })
    } catch (e) { setErr(errText(e, t)) }
  }

  async function copy(text: string) {
    if (await copyText(text)) { setCopied(text); setTimeout(() => setCopied(''), 1500) }
  }

  // Same ceremony as Certificates → Renew: a FRESH factor travels in the request itself (a TOTP
  // code cannot go through the /stepup window route on a host without require_2fa).
  async function openTerminal(c: HealthCheck, index: number) {
    const host = st?.terminal_host
    if (!host) return
    setErr(''); setMsg(''); setOpening(c.id + ':' + index)
    const url = `/api/hosts/${host.id}/health-terminal`
    const send = (extra: Record<string, string> = {}) => api<{ id: string; command: string }>(url, {
      method: 'POST', body: JSON.stringify({ check_id: c.id, index, tz: getTimezone(), ...extra }),
    }, true)
    try {
      let r: { id: string; command: string } | null = null
      try {
        r = await send()
      } catch (e) {
        if (e instanceof ApiError && e.code === 'stepup.totp') {
          const otp = await askSecret(t('stepup.totpTitle'), {
            masked: false, otp: true, label: t('stepup.totpLabel'), hint: t('stepup.totpHint'),
          })
          if (otp === null) return
          r = await send({ stepup_totp: otp.trim() })
        } else if (isStepupError(e) && await ensureStepup(host.id, e instanceof ApiError ? e.code : '')) {
          r = await send()
        } else {
          throw e
        }
      }
      if (r?.id) window.dispatchEvent(new CustomEvent('wt-open-session', { detail: { sid: r.id } }))
    } catch (e) {
      setErr(errText(e, t))
    } finally { setOpening('') }
  }

  // UI actions on hosts: the existing routes (their own permission + step-up checks apply)
  async function hostAction(c: HealthCheck, hostId: number) {
    setErr(''); setMsg(''); setHostBusy(hostId)
    try {
      if (c.action === 'agent_update') {
        await api(`/api/hosts/${hostId}/update`, { method: 'POST' })
        setMsg(t('health.updateSent'))
      } else if (c.action === 'autostart') {
        await api(`/api/hosts/${hostId}/autostart`, { method: 'POST', body: JSON.stringify({ enable: true }) })
        setMsg(t('health.autostartOn'))
      }
    } catch (e) { setErr(errText(e, t)) } finally { setHostBusy(0) }
  }

  const { open, passing } = st ? splitChecks(st.checks) : { open: [], passing: [] }
  const muteCheck = muteMenu ? st?.checks.find((c) => c.id === muteMenu.id) : undefined
  // verificarea meniului deschis a dispărut (recheck / eroare): meniul se demontează fără onClose,
  // iar starea ar rămâne „deschis" (aria-expanded orfan, ArrowDown blocat pe celelalte butoane)
  useEffect(() => { if (muteMenu && !muteCheck) setMuteMenu(null) }, [muteMenu, muteCheck])
  const mode = st ? fixMode(st) : 'copy'
  const attention = st ? st.checks.filter(needsAttention).length : 0

  function renderCheck(c: HealthCheck) {
    const tone = severityTone(c.severity, c.muted)
    const why = optText('health.why.', c.why_key, t)
    const rec = optText('health.rec.', c.recommendation_key, t)
    const target = actionTarget(c.action)
    const doc = docUrl(c.doc)
    const hostButtons = (c.action === 'agent_update' || c.action === 'autostart') && st?.can_manage
    return (
      <li key={c.id} data-health={c.id} data-severity={c.severity} tabIndex={-1}
        ref={(el) => { if (el) rows.current.set(c.id, el); else rows.current.delete(c.id) }}
        className="rounded-md border border-ink-700 bg-ink-800/40 p-3 text-xs">
        <div className="flex flex-wrap items-start gap-2">
          <Badge tone={tone} size="md">{t('health.sev.' + c.severity)}</Badge>
          <span className="min-w-0 flex-1 break-words text-sm text-slate-200">{checkText(c, t)}</span>
          {c.muted && <Badge tone="neutral">{(c.muted_until === -1 ? t('health.mutedUntilChange')
            : t('health.mutedUntil', { when: fmtTs(c.muted_until) }))
            + (c.muted_by ? ' · ' + t('health.mutedBy', { who: c.muted_by }) : '')}</Badge>}
        </div>
        <div className="mt-1 text-2xs text-slate-500">
          {optText('health.check.', c.id.replace('.', '_'), t) || c.id}
          {c.first_failed_at && c.severity !== 'ok' ? ' · ' + t('health.since', { when: fmtTs(c.first_failed_at) }) : ''}
        </div>
        {c.severity !== 'ok' && why && (
          <p className="mt-2 text-slate-400"><span className="font-medium text-slate-300">{t('health.whyLabel')} </span>{why}</p>
        )}
        {c.severity !== 'ok' && rec && (
          <p className="mt-1 text-slate-400"><span className="font-medium text-slate-300">{t('health.recLabel')} </span>{rec}</p>
        )}
        {c.hosts.length > 0 && (
          <ul className="mt-2 flex flex-col gap-1">
            {c.hosts.map((h) => (
              <li key={h.id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-slate-300">{h.name}</span>
                {hostButtons && (
                  <Button variant="secondary" size="sm" type="button" loading={hostBusy === h.id}
                    disabled={!!hostBusy} onClick={() => { void hostAction(c, h.id) }}>
                    {c.action === 'agent_update' ? t('health.updateNow') : t('health.enableAutostart')}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {c.hosts_hidden > 0 && <p className="mt-1 text-slate-500">{t('health.hostsHidden', { count: c.hosts_hidden })}</p>}
        {c.severity !== 'ok' && c.commands.map((cmd, i) => (
          <div key={i} className="mt-2 flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded-md bg-ink-900 px-2 py-1 font-mono text-slate-300">{cmd.text}</code>
              <Button variant="ghost" size="sm" type="button" onClick={() => { void copy(cmd.text) }}
                aria-label={t('health.copyCommand')}>
                {copied === cmd.text ? t('fleet.copied') : t('settings.certs.copy')}
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-slate-500">
              {cmd.requires_root && <span>{t('health.needsRoot')}</span>}
              {mode === 'terminal' && (
                <Button variant="secondary" size="sm" type="button" loading={opening === c.id + ':' + i}
                  disabled={!!opening} onClick={() => { void openTerminal(c, i) }}>
                  {t('health.openTerminal')}
                </Button>
              )}
              {mode === 'terminal' && i === 0 && <span>{t('health.terminalHint', { host: st?.terminal_host?.name ?? '' })}</span>}
              {mode === 'pick' && i === 0 && <span>{t('health.pickHost')}</span>}
            </div>
          </div>
        ))}
        {(target || doc || (st?.can_manage && c.severity !== 'ok')) && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {target && props.onJump && c.severity !== 'ok' && (
              <Button variant="secondary" size="sm" type="button" onClick={() => props.onJump?.(target.cat, target.section)}>
                {t('health.goTo')}
              </Button>
            )}
            {doc && (
              <a href={doc} target="_blank" rel="noopener noreferrer" className="wt-link hover:underline">
                {t('health.readDoc', { doc: c.doc.replace(/#.*$/, '') })}
              </a>
            )}
            {st?.can_manage && c.severity !== 'ok' && (canMute(c, st) || c.muted) && (
              // visible text = accessible name ("Mute…" / "Muted…"); the menu itself carries health.muteLabel
              <Button variant="secondary" size="sm" type="button" aria-haspopup="menu"
                aria-expanded={muteMenu?.id === c.id} data-testid={`health-mute-${c.id}`}
                ref={(el) => { if (el) muteBtns.current.set(c.id, el); else muteBtns.current.delete(c.id) }}
                onClick={(e) => openMute(c, e.currentTarget)}
                onKeyDown={(e) => { if (e.key === 'ArrowDown' && !muteMenu) { e.preventDefault(); openMute(c, e.currentTarget) } }}>
                {c.muted ? t('health.mutedShort') : t('health.mute')}
                <ChevronDownIcon />
              </Button>
            )}
            {st?.can_manage && c.severity !== 'ok' && !canMute(c, st) && (
              <span className="text-2xs text-slate-500">{t('health.muteOwnerOnly')}</span>
            )}
          </div>
        )}
      </li>
    )
  }

  return (
    <section data-setting-id="systemHealth" hidden={!vis('systemHealth')}>
      <h3 className={heading + ' flex items-center gap-2'}>{t('health.title')}<HelpTip id="health" /></h3>
      <p className="mt-1 text-xs text-slate-500">{t('health.hint')}</p>
      <NotLoaded state={load} onRetry={() => { void reload() }} />
      {st && (
        <div className="mt-2 flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <Badge tone={attention ? severityTone(st.attention.severity) : 'ok'} size="md" data-testid="health-summary">
              {attention ? t('health.attention', { count: attention }) : t('health.allGood')}
            </Badge>
            {st.can_manage && (
              <Button variant="secondary" size="sm" type="button" loading={busy} onClick={recheck}>
                {t('health.recheck')}
              </Button>
            )}
            <span>{st.checked_at ? t('health.lastCheck', { when: fmtTs(st.checked_at) }) : t('health.notChecked')}</span>
          </div>
          <span role="status" className={msg ? 'text-sm wt-good' : 'sr-only'}>{msg}</span>
          <span role="alert" className={err ? 'text-sm wt-danger' : 'sr-only'}>{err}</span>
          {open.length > 0 && <ul className="flex flex-col gap-2">{open.map(renderCheck)}</ul>}
          {passing.length > 0 && (
            <div>
              <button type="button" className="text-xs wt-link hover:underline" aria-expanded={showOk}
                onClick={() => setShowOk((v) => !v)}>
                {showOk ? t('health.hidePassing') : t('health.showPassing', { count: passing.length })}
              </button>
              {showOk && <ul className="mt-2 flex flex-col gap-2">{passing.map(renderCheck)}</ul>}
            </div>
          )}
        </div>
      )}
      {muteMenu && muteCheck && (
        <FileMenu items={muteItems(muteCheck)} at={muteMenu.at} sheet={coarse}
          title={coarse ? checkText(muteCheck, t) : undefined} label={t('health.muteLabel')}
          anchor={muteBtns.current.get(muteCheck.id)} onClose={closeMute} />
      )}
    </section>
  )
}
