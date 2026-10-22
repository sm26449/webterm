// FS-09: CRC-32 al unei felii, calculat în AFARA firului principal. Bucla byte-cu-byte peste
// 2–16 MiB per felie (zeci–sute de ms, mai mult pe telefon) îngheţa UI-ul în timpul upload-urilor
// mari. Worker-ul e fără stare: CRC-ul cumulativ stă pe firul principal şi vine ca `prev`, deci
// feliile rămân în ordine (apelantul aşteaptă fiecare răspuns). Buffer-ul e TRANSFERAT în ambele
// sensuri (zero-copy): worker-ul îl primeşte, calculează, apoi îl dă înapoi ca apelantul să-l poată
// trimite mai departe la upload. `id` împerechează cererea cu răspunsul.
import { crc32 } from './crc'

interface Req { id: number; prev: number; buf: ArrayBuffer }

const ctx = self as unknown as Worker

ctx.onmessage = (e: MessageEvent) => {
  const { id, prev, buf } = e.data as Req
  const crc = crc32(prev, new Uint8Array(buf))
  ctx.postMessage({ id, crc, buf }, [buf])
}
