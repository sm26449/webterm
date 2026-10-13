import { useRef, useState } from 'react'
import { Host, errText } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useI18n } from '../lib/i18n'
import { notifyToast } from '../lib/notify'
import { setfaclCommand, uploadAndMoveAsRoot } from '../lib/rootmove'
import { CopyIcon, HomeIcon, LockIcon, UploadIcon } from './Icons'
import { Button, IconButton } from './ui'

/* 3.6.9 — the Files panel learned (from a refused write) that the agent's user cannot write in
   `dir`. Explains why (Files acts as the agent's user, not as the terminal's sudo user) and offers
   the three ways out. Nothing here runs anything: the setfacl command is for copying, and the
   "move as root" command is TYPED into the person's own terminal without Enter. */

export interface PendingFile { file: File; name: string }

function CmdBox(props: { cmd: string; label: string; testid?: string }) {
  const { t } = useI18n()
  return (
    <div className="mt-1 flex items-start gap-1 rounded-md bg-ink-950/60 px-2 py-1 ring-1 ring-ink-700">
      <code className="min-w-0 flex-1 select-all break-all font-mono text-2xs text-slate-300" data-testid={props.testid}>{props.cmd}</code>
      <IconButton touch={false} onClick={() => void copyText(props.cmd)} label={`${t('files.denied.copy')} ${props.label}`} title={t('files.denied.copy')}>
        <CopyIcon size={12} />
      </IconButton>
    </div>
  )
}

export default function WriteDeniedBanner(props: {
  host: Host
  dir: string
  /** textul erorii, deja tradus (cine nu poate scrie unde, cu modul dosarului când e cunoscut) */
  message: string
  /** terminalul în care tastăm comanda; "" (tab-ul hostului) → doar „copiază" */
  sessionId: string
  /** fişierele al căror upload tocmai a fost refuzat (simple, fără subdosare) */
  pending: PendingFile[]
  onUploadHome: (files: PendingFile[]) => void
  onDismiss: () => void
  /** după „move as root" reuşit: rândurile refuzate din Transferuri pot dispărea */
  onMoved?: () => void
}) {
  const { t } = useI18n()
  const user = props.host.agent_user || ''
  const acl = setfaclCommand(user, props.dir)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ command: string; typed: boolean } | null>(null)
  const [err, setErr] = useState('')
  const pick = useRef<HTMLInputElement>(null)

  async function moveAsRoot(files: PendingFile[]) {
    if (!files.length || busy) return
    setBusy(true); setErr(''); setResult(null)
    try {
      const r = await uploadAndMoveAsRoot({ hostId: props.host.id, hostName: props.host.name, dir: props.dir,
                                            files, sid: props.sessionId || undefined })
      if (r.failed.length) { setErr(t('files.denied.inboxFailed', { names: r.failed.slice(0, 3).join(', ') })); return }
      setResult({ command: r.command, typed: r.typed })
      props.onMoved?.()
      if (r.typed) notifyToast(t('files.denied.typedToast'), 'info')
    } catch (e) {
      setErr(errText(e, t) || t('files.genericErr'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div role="region" aria-label={t('files.denied.title')} data-testid="wt-files-denied"
      className="border-b border-ink-800 bg-amber-950/30 px-3 py-2 text-2xs">
      <div className="flex items-start gap-2">
        <span className="mt-0.5 wt-warn"><LockIcon size={14} /></span>
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-slate-200">{t('files.denied.title')}</p>
          <p className="mt-0.5 break-words text-slate-300" data-testid="wt-files-denied-msg">{props.message}</p>
          <p className="mt-0.5 text-slate-400">{t('files.denied.why', { user: user || '?' })}</p>
        </div>
        <IconButton touch={false} onClick={props.onDismiss} label={t('files.denied.dismiss')} title={t('files.denied.dismiss')}>
          <span aria-hidden="true">×</span>
        </IconButton>
      </div>

      <ol className="mt-2 space-y-2 pl-1">
        <li>
          <p className="font-medium text-slate-300">{t('files.denied.optRoot')}</p>
          <p className="text-slate-400">{props.sessionId ? t('files.denied.optRootHelp', { user: user || '?' }) : t('files.denied.optRootHelpCopy', { user: user || '?' })}</p>
          <div className="mt-1 flex flex-wrap gap-2">
            {props.pending.length > 0 && (
              <Button size="sm" variant="primary" loading={busy} onClick={() => void moveAsRoot(props.pending)} data-testid="wt-files-root-move">
                <UploadIcon size={12} /> {t('files.denied.moveN', { count: props.pending.length })}
              </Button>
            )}
            <Button size="sm" variant={props.pending.length ? 'ghost' : 'primary'} loading={busy && !props.pending.length}
              onClick={() => pick.current?.click()}>
              {t('files.denied.pickAndMove')}
            </Button>
            <input ref={pick} type="file" multiple className="hidden" data-testid="wt-files-root-move-pick"
              onChange={(e) => {
                const fs = Array.from(e.target.files ?? []).map((f) => ({ file: f, name: f.name }))
                e.target.value = ''
                void moveAsRoot(fs)
              }} />
          </div>
          {result && (result.typed
            ? <p className="mt-1 wt-good" role="status" data-testid="wt-files-root-typed">{t('files.denied.typed')}</p>
            : <div className="mt-1" role="status">
                <p className="text-slate-300">{t('files.denied.copyThis')}</p>
                <CmdBox cmd={result.command} label={t('files.denied.optRoot')} testid="wt-files-root-cmd" />
              </div>)}
          {err && <p role="alert" className="mt-1 wt-danger">{err}</p>}
        </li>
        {acl && (
          <li>
            <p className="font-medium text-slate-300">{t('files.denied.optAcl', { user })}</p>
            <p className="text-slate-400">{t('files.denied.optAclHelp')}</p>
            <CmdBox cmd={acl} label={t('files.denied.optAcl', { user })} testid="wt-files-acl-cmd" />
          </li>
        )}
        <li>
          <p className="font-medium text-slate-300">{t('files.denied.optHome', { user: user || '?' })}</p>
          <Button size="sm" variant="ghost" className="mt-1" onClick={() => props.onUploadHome(props.pending)}>
            <HomeIcon size={12} /> {props.pending.length ? t('files.denied.homeN', { count: props.pending.length }) : t('files.denied.openHome')}
          </Button>
        </li>
      </ol>
    </div>
  )
}
