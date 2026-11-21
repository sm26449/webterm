import { useSectionVisible } from '../../lib/perms'
import ForwardDomainSection from './ForwardDomainSection'
import CertificatesSection from './CertificatesSection'

// Reţea şi certificate (3.7.1, auditul UX Setări C2): certificatele TLS servite de instanţă şi domeniul
// de port-forwarding (care cere el însuşi un certificat wildcard) — erau ultimele două subiecte din
// „Infrastructure & tokens". Secţiunile sunt componentele de dinainte, mutate ca atare.
export default function NetworkTab() {
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  return (
    <div className="flex flex-col gap-4">
      {/* 3.7.1: fiecare componentă îşi randează SettingsSection-ul; `data-setting-id` stă scris aici,
          literal, fiindcă indexul căutării (settingsIndex.test.ts) îl citeşte din *Tab.tsx */}
      <CertificatesSection data-setting-id="certificates" hidden={!vis('certificates')} />
      <ForwardDomainSection data-setting-id="forwardDomain" hidden={!vis('forwardDomain')} />
    </div>
  )
}
