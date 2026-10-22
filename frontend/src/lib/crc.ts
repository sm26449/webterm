// CRC-32 (IEEE, identic cu zlib.crc32 din agent) — extras din uploads.ts ca să poată fi importat
// şi de crcWorker.ts FĂRĂ a trage tot motorul de upload (XHR, DOM) în bundle-ul worker-ului.
// Verificare de integritate per felie: fiecare felie trimisă poartă CRC-ul cumulativ al octeţilor
// de pân-acum; agentul îl recalculează pe disc şi refuză o nepotrivire (corupţie accidentală:
// disc, trunchiere, offset). `prev` începe de la 0.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
    t[n] = c >>> 0
  }
  return t
})()

export function crc32(prev: number, bytes: Uint8Array): number {
  let c = (prev ^ 0xFFFFFFFF) >>> 0
  for (let i = 0; i < bytes.length; i++) c = (CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8)) >>> 0
  return (c ^ 0xFFFFFFFF) >>> 0
}
