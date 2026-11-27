import { useCallback, useEffect, useState, type HTMLAttributes } from 'react'
import { errText, type SettingsReturn } from '../../lib/api'
import { useConfirm } from '../../lib/confirm'
import {
  conflictWord, destState, destTone, discardMigration, eraseWord, healthTone, isEncryptionOwner,
  loadEncryption, loadQuarantine, migrationPercent, protectionView, recompactionPercent, recoverRecording,
  recoveryTranscriptUrl, recoveryWord, releaseRecording, requarantineRecording, resolveConflict,
  retireDestination, retryMigration, typedMatches,
  type ConflictHead, type EncryptionStatus, type EraseDestination, type FailedMigration, type QuarantineItem,
  type QuarantineList,
} from '../../lib/encryption'
import { useI18n } from '../../lib/i18n'
import type { LoadState } from '../../lib/loadable'
import { notifyError, notifyToast } from '../../lib/notify'
import { usePerms } from '../../lib/perms'
import { fmtTs } from '../../lib/tz'
import { fmtBytes } from '../../lib/uploads'
import { Badge, Button, SettingsSection } from '../ui'
import { iconButtonClass } from '../ui/classes'
import { DownloadIcon, RefreshIcon } from '../Icons'
import HelpTip from '../HelpTip'
import NotLoaded from './NotLoaded'

const RETURN: SettingsReturn = { cat: 'backup', section: 'backupEncryption' }
const LIST_MAX = 50          // un restore fără dovadă pune în carantină TOT: arătăm primele, cu numărul total
const row = 'flex flex-wrap items-center gap-2 rounded-md bg-ink-800 px-3 py-2 text-sm'
const h4 = 'mt-5 text-sm font-medium text-slate-200'

/** Setări → Backup → „Encryption at rest" (3.8): starea protecţiei şi a înregistrărilor, carantina
    (recuperare câte una, citire auditată, release / înapoi în carantină), destinaţiile jurnalului de
    ştergeri cu atestarea lor (retragere), conflictul de jurnal (rezolvare) şi migrările eşuate
    (retry / discard). Doar Owner @ all; fiecare acţiune distructivă cere confirmare, iar serverul
    cere din nou tot (Owner, factor REAL proaspăt, confirmarea tastată). Logica: lib/encryption.ts. */
export default function EncryptionSection(props: Omit<HTMLAttributes<HTMLElement>, 'title'>) {
  const { t } = useI18n()
  const perms = usePerms()
  const owner = isEncryptionOwner(perms)
  const { confirm, promptText } = useConfirm()
  const [st, setSt] = useState<EncryptionStatus | null>(null)
  const [q, setQ] = useState<QuarantineList | null>(null)
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busy, setBusy] = useState('')

  const reload = useCallback(async () => {
    try {
      const s = await loadEncryption()
      setSt(s)
      // carantina există doar cu jurnalul activ (altfel ruta răspunde 503)
      setQ(s.active ? await loadQuarantine() : null)
      setLoad({ status: 'ok' })
    } catch (e) {
      setLoad({ status: 'error', error: errText(e, t) })
    }
  }, [t])
  useEffect(() => { if (owner) void reload() }, [owner, reload])

  /** Rulează o acţiune: `null` (anulată / plecat la IdP) nu arată nimic; altfel toast + reîncărcare. */
  const act = async (id: string, fn: () => Promise<unknown>, okKey: string) => {
    setBusy(id)
    try {
      const r = await fn()
      if (r === null) return
      notifyToast(t(okKey), 'info', 'enc-' + id)
      await reload()
    } catch (e) {
      notifyError(t('enc.actionFailed'), errText(e, t), 'enc-' + id)
    } finally {
      setBusy('')
    }
  }
  // L3: după ce textul tastat s-a potrivit, se trimite cuvântul canonic (exact ce compară serverul),
  // nu varianta tastată (spaţii multiple, majuscule) pe care serverul ar refuza-o.
  const typed = (title: string, message: string, word: string, confirmLabel: string, danger = false) => promptText({
    title, message, label: t('enc.typeLabel', { word }), placeholder: word, confirmLabel, danger,
    validate: (v) => (typedMatches(v, word) ? null : t('enc.typeMismatch', { word })),
  })

  const recover = async (it: QuarantineItem) => {
    const word = q ? recoveryWord(it, q) : null
    if (!word) return
    const v = await typed(t('enc.q.recoverTitle'),
      t(it.recovery === 'journal' ? 'enc.q.recoverJournalBody' : 'enc.q.recoverBody'), word, t('enc.q.recover'))
    if (v === null) return
    await act('rec-' + it.sid, () => recoverRecording(it.sid, it.host_id ?? 0, word, { returnTo: RETURN }),
      'enc.q.recovered')
  }
  const release = async (it: QuarantineItem) => {
    if (!(await confirm({ title: t('enc.q.releaseTitle'), message: t('enc.q.releaseBody'), confirmLabel: t('enc.q.release'), danger: true }))) return
    await act('rel-' + it.sid, () => releaseRecording(it.sid, it.host_id ?? 0, { returnTo: RETURN }), 'enc.q.released')
  }
  const requarantine = async (it: QuarantineItem) => {
    if (!(await confirm({ title: t('enc.q.requarantineTitle'), message: t('enc.q.requarantineBody'), confirmLabel: t('enc.q.requarantine') }))) return
    await act('req-' + it.sid, () => requarantineRecording(it.sid), 'enc.q.requarantined')
  }
  const retire = async (d: EraseDestination) => {
    const v = await typed(t('enc.d.retireTitle'), t('enc.d.retireBody'), d.id, t('enc.d.retire'), true)
    if (v === null) return
    await act('ret-' + d.id, () => retireDestination(d.id, d.id, { returnTo: RETURN }), 'enc.d.retired')
  }
  const resolve = async (h: ConflictHead) => {
    const word = conflictWord(h)
    const v = await typed(t('enc.c.resolveTitle'), t('enc.c.resolveBody'), word, t('enc.c.resolve'), true)
    if (v === null) return
    await act('res-' + h.n, () => resolveConflict(h, word, { returnTo: RETURN }), 'enc.c.resolved')
  }
  const retry = async (f: FailedMigration) => {
    if (!(await confirm({ title: t('enc.m.retryTitle'), message: t('enc.m.retryBody'), confirmLabel: t('enc.m.retry') }))) return
    await act('try-' + f.sid, () => retryMigration(f.sid, f.host_id ?? 0, { returnTo: RETURN }), 'enc.m.retried')
  }
  const discard = async (f: FailedMigration) => {
    const v = await typed(t('enc.m.discardTitle'), t('enc.m.discardBody'), eraseWord(f.sid), t('enc.m.discard'), true)
    if (v === null) return
    await act('dis-' + f.sid, () => discardMigration(f.sid, f.host_id ?? 0, eraseWord(f.sid), { returnTo: RETURN }), 'enc.m.discarded')
  }

  const er = st?.erasure ?? null
  const mig = st?.migration ?? null
  const prot = protectionView(st?.protection)
  const items = q?.items ?? []

  return (
    <SettingsSection {...props} title={t('enc.title')} titleExtra={<HelpTip id="encryption" />} instanceWide
      description={t('enc.desc')} data-testid="encryption-section">
      {!owner ? (
        <p className="text-xs text-slate-500">{t('enc.ownerOnly')}</p>
      ) : load.status !== 'ok' ? (
        <NotLoaded state={load} onRetry={() => { setLoad({ status: 'loading' }); void reload() }} />
      ) : st && (
        <div className="flex flex-col">
          {/* ── stare ── */}
          <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[auto,1fr]">
            <dt className="text-slate-400">{t('enc.protection')}</dt>
            <dd className="flex flex-wrap items-center gap-2">
              <Badge tone={prot.tone}>{t(prot.key + '.badge')}</Badge>
              <span className="text-xs text-slate-400">{t(prot.key, { source: st.protection.source ?? '?' })}</span>
            </dd>
            <dt className="text-slate-400">{t('enc.recordings')}</dt>
            <dd className="flex flex-wrap items-center gap-2">
              <Badge tone={st.active ? 'ok' : 'neutral'}>{st.active ? t('enc.recordings.on') : t('enc.recordings.off')}</Badge>
              {!st.active && <span className="text-xs text-slate-400">{t('enc.recordings.offHint')}</span>}
              {er && <span className="text-xs text-slate-400">{t('enc.journal', { n: er.journal.n, cap: er.journal.cap })}</span>}
            </dd>
            {mig && (
              <>
                <dt className="text-slate-400">{t('enc.migration')}</dt>
                <dd>
                  <Progress pct={migrationPercent(mig)} label={t('enc.migration')}
                    text={mig.todo === 0 && mig.format === 'wtx1'
                      ? t('enc.migration.complete')
                      : t('enc.migration.progress', { done: mig.done, total: mig.total, left: fmtBytes(mig.left_bytes) })} />
                </dd>
                {(mig.recompaction.left > 0 || mig.recompaction.done > 0 || mig.recompaction.failed > 0) && (
                  <>
                    <dt className="text-slate-400">{t('enc.recompaction')}</dt>
                    <dd>
                      <Progress pct={recompactionPercent(mig.recompaction)} label={t('enc.recompaction')}
                        text={t('enc.recompaction.progress', {
                          done: mig.recompaction.done, left: mig.recompaction.left,
                          saved: fmtBytes(mig.recompaction.saved_bytes),
                        })} />
                      {mig.recompaction.failed > 0 && (
                        <p className="mt-1 text-xs wt-warn">{t('enc.recompaction.failed', { n: mig.recompaction.failed, error: mig.recompaction.error || '?' })}</p>
                      )}
                    </dd>
                  </>
                )}
              </>
            )}
          </dl>
          {er && er.health.length > 0 && (
            <ul className="mt-3 flex flex-col gap-1" aria-label={t('enc.alarms')}>
              {er.health.map((h) => (
                <li key={h.key + JSON.stringify(h.params)} className="flex items-start gap-2 text-xs text-slate-300">
                  <Badge tone={healthTone(h.severity)}>{t('enc.sev.' + h.severity)}</Badge>
                  <span className="min-w-0">{t('health.msg.' + h.key, h.params)}</span>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-3">
            <Button type="button" size="sm" variant="ghost" className="wt-touch" onClick={() => { void reload() }}>
              <RefreshIcon size={12} /> {t('enc.refresh')}
            </Button>
          </div>

          {/* ── carantina ── */}
          {st.active && (
            <>
              <h4 className={h4}>{t('enc.q.title')}</h4>
              <p className="mt-1 text-xs text-slate-500">{t('enc.q.hint')}</p>
              {items.length === 0 ? (
                <p className="mt-2 text-xs text-slate-500" data-testid="enc-quarantine-empty">{t('enc.q.empty')}</p>
              ) : (
                <ul className="mt-2 space-y-1" data-testid="enc-quarantine">
                  {items.slice(0, LIST_MAX).map((it) => (
                    <li key={it.sid} className={row}>
                      <span className="min-w-0 flex-1">
                        <span className="font-mono text-xs text-slate-300">{eraseWord(it.sid)}</span>
                        {it.title && <span className="ml-2 text-xs text-slate-400">{it.title}</span>}
                        <span className="ml-2 text-2xs text-slate-500">
                          {it.kinds.join(', ')} · {t('enc.q.reason.' + (it.reason.startsWith('journal:') ? 'journal' : it.reason === 'continuity' ? 'continuity' : 'unknown'), { reason: it.reason })}
                          {it.since ? ` · ${fmtTs(it.since)}` : ''}
                        </span>
                      </span>
                      <Badge tone={it.status === 'recovery' ? 'warn' : 'neutral'}>{t('enc.q.status.' + (['quarantined', 'recovery', 'plaintext', 'mixed'].includes(it.status) ? it.status : 'unknown'))}</Badge>
                      <span className="flex shrink-0 flex-wrap items-center gap-1">
                        {it.status === 'quarantined' && it.recoverable && (
                          <Button type="button" size="sm" variant="secondary" className="wt-touch" disabled={!!busy}
                            onClick={() => { void recover(it) }}>{t('enc.q.recover')}</Button>
                        )}
                        {it.status === 'recovery' && (
                          <>
                            <a href={recoveryTranscriptUrl(it.sid)} download className={iconButtonClass('ghost', 'md')}
                              title={t('enc.q.read')} aria-label={t('enc.q.readAria', { sid: eraseWord(it.sid) })}><DownloadIcon /></a>
                            {it.recovery !== 'journal' && (
                              <Button type="button" size="sm" variant="secondary" className="wt-touch" disabled={!!busy}
                                onClick={() => { void release(it) }}>{t('enc.q.release')}</Button>
                            )}
                            <Button type="button" size="sm" variant="ghost" className="wt-touch" disabled={!!busy}
                              onClick={() => { void requarantine(it) }}>{t('enc.q.requarantine')}</Button>
                          </>
                        )}
                        {it.status === 'quarantined' && !it.recoverable && (
                          <span className="text-2xs text-slate-500">{t('enc.q.notRecoverable')}</span>
                        )}
                      </span>
                    </li>
                  ))}
                  {items.length > LIST_MAX && (
                    <li className="px-3 text-xs text-slate-500">{t('enc.q.more', { n: items.length - LIST_MAX })}</li>
                  )}
                </ul>
              )}
            </>
          )}

          {/* ── destinaţii ── */}
          {er && (
            <>
              <h4 className={h4}>{t('enc.d.title')}</h4>
              <p className="mt-1 text-xs text-slate-500">{t('enc.d.hint')}</p>
              {!er.destinations_known && <p className="mt-1 text-xs wt-warn">{t('enc.d.unknown')}</p>}
              {er.destinations.length === 0 ? (
                <p className="mt-2 text-xs text-slate-500">{er.journal.n > 0 ? t('enc.d.localOnly') : t('enc.d.none')}</p>
              ) : (
                <ul className="mt-2 space-y-1" data-testid="enc-destinations">
                  {er.destinations.map((d) => {
                    const s = destState(d)
                    return (
                      <li key={d.id} className={row}>
                        <span className="min-w-0 flex-1">
                          <span className="break-all font-mono text-xs text-slate-300">{d.id}</span>
                          <span className="mt-0.5 block text-2xs text-slate-500">
                            {t('enc.d.attested', { n: d.attested_n, head: er.journal.n })}
                            {d.attested_time ? ` · ${fmtTs(d.attested_time / 1000)}` : ''}
                            {d.error ? ` · ${d.error}` : ''}
                          </span>
                        </span>
                        {d.configured && <Badge tone="neutral">{t('enc.d.configured')}</Badge>}
                        {d.required && <Badge tone="info">{t('enc.d.required')}</Badge>}
                        <Badge tone={destTone(s)}>{t('enc.d.state.' + s)}</Badge>
                        {d.retirable && (
                          <Button type="button" size="sm" variant="danger" className="wt-touch" disabled={!!busy}
                            onClick={() => { void retire(d) }}>{t('enc.d.retire')}</Button>
                        )}
                      </li>
                    )
                  })}
                </ul>
              )}
            </>
          )}

          {/* ── conflict ── */}
          {er?.conflict && (
            <>
              <h4 className={h4 + ' wt-danger'}>{t('enc.c.title')}</h4>
              <p className="mt-1 text-xs text-slate-400">{t('enc.c.hint', { sids: er.conflict.sids, dests: er.conflict.dests.join(', ') || '-' })}</p>
              {er.conflict.heads.length === 0 ? (
                <p className="mt-2 text-xs text-slate-500">{t('enc.c.noHeads')}</p>
              ) : (
                <ul className="mt-2 space-y-1" data-testid="enc-conflict">
                  {er.conflict.heads.map((h) => (
                    <li key={h.n + h.mac} className={row}>
                      <span className="min-w-0 flex-1 font-mono text-xs text-slate-300">
                        {t('enc.c.head', { n: h.n, mac: h.mac.slice(0, 16) })}
                        {h.time ? <span className="ml-2 text-slate-500">{fmtTs(h.time / 1000)}</span> : null}
                      </span>
                      <Button type="button" size="sm" variant="danger" className="wt-touch" disabled={!!busy}
                        onClick={() => { void resolve(h) }}>{t('enc.c.resolve')}</Button>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}

          {/* ── migrări eşuate ── */}
          {st.failed.length > 0 && (
            <>
              <h4 className={h4}>{t('enc.m.title')}</h4>
              <p className="mt-1 text-xs text-slate-500">{t('enc.m.hint')}</p>
              <ul className="mt-2 space-y-1" data-testid="enc-failed">
                {st.failed.map((f) => (
                  <li key={f.sid} className={row}>
                    <span className="min-w-0 flex-1">
                      <span className="font-mono text-xs text-slate-300">{eraseWord(f.sid)}</span>
                      {f.title && <span className="ml-2 text-xs text-slate-400">{f.title}</span>}
                      <span className="mt-0.5 block text-2xs text-slate-500">
                        {f.kinds.join(', ')} · {fmtBytes(f.size)}{f.error ? ` · ${f.error}` : ''}
                      </span>
                      {f.encrypted && <span className="block text-2xs wt-warn">{t('enc.m.encrypted')}</span>}
                      {f.live && <span className="block text-2xs wt-warn">{t('enc.m.live')}</span>}
                    </span>
                    <span className="flex shrink-0 items-center gap-1">
                      <Button type="button" size="sm" variant="secondary" className="wt-touch" disabled={!!busy || f.encrypted}
                        onClick={() => { void retry(f) }}>{t('enc.m.retry')}</Button>
                      <Button type="button" size="sm" variant="danger" className="wt-touch" disabled={!!busy || f.live}
                        onClick={() => { void discard(f) }}>{t('enc.m.discard')}</Button>
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </SettingsSection>
  )
}

function Progress(props: { pct: number; text: string; label: string }) {
  return (
    <div className="flex flex-col gap-1">
      <div role="progressbar" aria-label={props.label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={props.pct}
        className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-ink-700">
        <div className="h-full rounded-full bg-sky-500" style={{ width: `${props.pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{props.text}</span>
    </div>
  )
}
