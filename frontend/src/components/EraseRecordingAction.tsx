import { useEffect, useState } from 'react'
import { errText } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import {
  canErase, eraseRecording, eraseWord, isEncryptionOwner, loadEncryption, typedMatches,
  type EncryptionStatus,
} from '../lib/encryption'
import { useI18n } from '../lib/i18n'
import { notifyError, notifyToast } from '../lib/notify'
import { usePerms } from '../lib/perms'
import { Button, IconButton } from './ui'
import { ShieldIcon } from './Icons'

/** „Erase permanently" (3.8): pentru Owner, pe o sesiune ÎNCHISĂ cu înregistrare CRIPTATĂ (lista de
    sesiuni a hostului şi player-ul). Starea înregistrării vine de la server (`?sid=`), o dată per
    sesiune aleasă; confirmarea e tastată (primele 8 caractere), apoi factorul proaspăt prin
    `withFreshFactor`. Serverul decide totul din nou (Owner @ all, factor REAL, sesiune închisă). */
export default function EraseRecordingAction(props: {
  sid: string
  hostId: number
  live: boolean
  variant?: 'icon' | 'button'
  onErased?: () => void
}) {
  const { t } = useI18n()
  const perms = usePerms()
  const { promptText } = useConfirm()
  const owner = isEncryptionOwner(perms)
  const [rec, setRec] = useState<EncryptionStatus['recording']>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setRec(null)
    if (!owner || props.live) return
    let alive = true
    // o eroare (criptare oprită, cont care nu e Owner pe server) = nicio acţiune, fără zgomot
    loadEncryption(props.sid).then((s) => { if (alive) setRec(s.active ? s.recording : null) }).catch(() => {})
    return () => { alive = false }
  }, [props.sid, props.live, owner])

  if (!canErase(perms, rec, props.live, props.sid)) return null

  const run = async () => {
    const word = eraseWord(props.sid)
    const typed = await promptText({
      title: t('enc.erase.title'),
      message: t('enc.erase.body'),
      label: t('enc.erase.typeLabel', { word }),
      placeholder: word,
      confirmLabel: t('enc.erase.confirm'),
      danger: true,
      validate: (v) => (typedMatches(v, word) ? null : t('enc.typeMismatch', { word })),
    })
    if (typed === null) return
    setBusy(true)
    try {
      const res = await eraseRecording(props.sid, props.hostId, word)
      if (res === null) return
      notifyToast(res.attested ? t('enc.erase.done') : t('enc.erase.doneUnattested'), 'info', 'erase-' + props.sid)
      setRec(null)
      props.onErased?.()
    } catch (e) {
      notifyError(t('enc.erase.failed'), errText(e, t), 'erase-' + props.sid)
    } finally {
      setBusy(false)
    }
  }

  if (props.variant === 'button') {
    return (
      <Button type="button" size="sm" variant="danger" disabled={busy} onClick={() => { void run() }}
        className="wt-touch shrink-0" data-testid="erase-recording">
        <ShieldIcon size={12} /> {t('enc.erase.action')}
      </Button>
    )
  }
  return (
    <IconButton size="md" variant="danger" disabled={busy} onClick={() => { void run() }}
      label={t('enc.erase.action')} data-testid="erase-recording"><ShieldIcon /></IconButton>
  )
}
