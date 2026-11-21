import { useSectionVisible } from '../../lib/perms'
import ForwardDomainSection from './ForwardDomainSection'
import CertificatesSection from './CertificatesSection'

// Reţea şi certificate (3.7.1, auditul UX Setări C2): certificatele TLS servite de instanţă şi domeniul
// de port-forwarding (care cere el însuşi un certificat wildcard) — erau ultimele două subiecte din
// „Infrastructure & tokens". Secţiunile sunt componentele de dinainte, mutate ca atare.
export default function NetworkTab() {
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  return (
    <div>
      <section data-setting-id="certificates" hidden={!vis('certificates')}>
        <CertificatesSection />
      </section>

      <section data-setting-id="forwardDomain" hidden={!vis('forwardDomain')}>
        <ForwardDomainSection />
      </section>
    </div>
  )
}
