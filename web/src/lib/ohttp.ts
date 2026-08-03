/**
 * Oblivious HTTP (RFC 9458) envelope decoding.
 *
 * OHTTP encapsulates a request under the *gateway's* HPKE public key. The relay
 * — which is what the proxy sees — cannot read the payload, and neither can we:
 * there is no key to obtain by intercepting. What is cleartext is the outer
 * envelope (key ID and HPKE cipher suite) and, for `application/ohttp-keys`,
 * the entire key configuration. These parsers decode exactly that much and
 * report the rest as opaque.
 *
 * Cipher suite identifiers come from the HPKE registries in RFC 9180.
 */

export interface KemInfo {
  name: string
  /** Length of an encapsulated shared secret / public key, in bytes. */
  nEnc: number
}

const KEMS: Record<number, KemInfo> = {
  0x0010: { name: 'DHKEM(P-256, HKDF-SHA256)', nEnc: 65 },
  0x0011: { name: 'DHKEM(P-384, HKDF-SHA384)', nEnc: 97 },
  0x0012: { name: 'DHKEM(P-521, HKDF-SHA512)', nEnc: 133 },
  0x0020: { name: 'DHKEM(X25519, HKDF-SHA256)', nEnc: 32 },
  0x0021: { name: 'DHKEM(X448, HKDF-SHA512)', nEnc: 56 },
}

const KDFS: Record<number, string> = {
  0x0001: 'HKDF-SHA256',
  0x0002: 'HKDF-SHA384',
  0x0003: 'HKDF-SHA512',
}

/** AEAD name plus key length, which sets the OHTTP response nonce size. */
const AEADS: Record<number, { name: string; nK: number; nN: number }> = {
  0x0001: { name: 'AES-128-GCM', nK: 16, nN: 12 },
  0x0002: { name: 'AES-256-GCM', nK: 32, nN: 12 },
  0x0003: { name: 'ChaCha20Poly1305', nK: 32, nN: 12 },
  0xffff: { name: 'Export-only', nK: 0, nN: 0 },
}

const hex4 = (n: number) => '0x' + n.toString(16).padStart(4, '0')

/** Render an ID as `0x0020  DHKEM(X25519, HKDF-SHA256)`, or mark it unknown. */
export function kemName(id: number): string {
  return `${hex4(id)}  ${KEMS[id]?.name ?? 'unknown KEM'}`
}
export function kdfName(id: number): string {
  return `${hex4(id)}  ${KDFS[id] ?? 'unknown KDF'}`
}
export function aeadName(id: number): string {
  return `${hex4(id)}  ${AEADS[id]?.name ?? 'unknown AEAD'}`
}

const u16 = (b: Uint8Array, off: number) => (b[off] << 8) | b[off + 1]

export interface OhttpRequest {
  keyId: number
  kemId: number
  kdfId: number
  aeadId: number
  encLength: number
  ciphertextLength: number
}

/**
 * Parse an `message/ohttp-req` body (RFC 9458 §4.1):
 * `key_id(1) ‖ kem_id(2) ‖ kdf_id(2) ‖ aead_id(2) ‖ enc(Nenc) ‖ ciphertext`.
 *
 * Returns null when the KEM is unknown (so Nenc cannot be derived) or the
 * length does not add up — the caller then falls back to a plain hex dump
 * rather than displaying fields that may be wrong.
 */
export function parseOhttpRequest(b: Uint8Array): OhttpRequest | null {
  if (b.length < 7) return null
  const kemId = u16(b, 1)
  const kem = KEMS[kemId]
  if (!kem) return null

  // Header, encapsulated secret, and at least an AEAD tag of ciphertext.
  const ctOffset = 7 + kem.nEnc
  if (b.length <= ctOffset) return null

  return {
    keyId: b[0],
    kemId,
    kdfId: u16(b, 3),
    aeadId: u16(b, 5),
    encLength: kem.nEnc,
    ciphertextLength: b.length - ctOffset,
  }
}

export interface OhttpResponse {
  totalLength: number
  /** Candidate nonce sizes: max(Nn, Nk) over the AEADs that OHTTP allows. */
  nonceNote: string
}

/**
 * Describe a `message/ohttp-res` body (RFC 9458 §4.2):
 * `response_nonce(max(Nn, Nk)) ‖ ciphertext`.
 *
 * A response carries no cleartext header — the nonce length depends on the
 * AEAD negotiated in the *request*, which is not available here. So this
 * reports the size and names the possibilities rather than inventing a split.
 */
export function parseOhttpResponse(b: Uint8Array): OhttpResponse | null {
  if (b.length < 16) return null
  return {
    totalLength: b.length,
    nonceNote: '16 bytes for AES-128-GCM, 32 for AES-256-GCM or ChaCha20Poly1305',
  }
}

export interface OhttpKeyConfig {
  keyId: number
  kemId: number
  publicKey: Uint8Array
  suites: Array<{ kdfId: number; aeadId: number }>
}

/**
 * Parse an `application/ohttp-keys` body (RFC 9458 §3): a concatenated
 * sequence of key configs, each
 * `key_id(1) ‖ kem_id(2) ‖ public_key(Npk) ‖ suites_len(2) ‖ [kdf_id(2) ‖ aead_id(2)]*`.
 *
 * This one is entirely cleartext, so it decodes in full.
 */
export function parseOhttpKeys(b: Uint8Array): OhttpKeyConfig[] | null {
  const out: OhttpKeyConfig[] = []
  let off = 0

  while (off < b.length) {
    if (off + 3 > b.length) return null
    const keyId = b[off]
    const kemId = u16(b, off + 1)
    const kem = KEMS[kemId]
    if (!kem) return null

    // Npk equals Nenc for every KEM in the RFC 9180 registry.
    const pkStart = off + 3
    const suitesLenAt = pkStart + kem.nEnc
    if (suitesLenAt + 2 > b.length) return null

    const suitesLen = u16(b, suitesLenAt)
    const suitesStart = suitesLenAt + 2
    if (suitesLen === 0 || suitesLen % 4 !== 0) return null
    if (suitesStart + suitesLen > b.length) return null

    const suites: Array<{ kdfId: number; aeadId: number }> = []
    for (let i = suitesStart; i < suitesStart + suitesLen; i += 4) {
      suites.push({ kdfId: u16(b, i), aeadId: u16(b, i + 2) })
    }

    out.push({ keyId, kemId, publicKey: b.subarray(pkStart, suitesLenAt), suites })
    off = suitesStart + suitesLen
  }

  return out.length > 0 ? out : null
}

export type OhttpKind = 'req' | 'res' | 'keys'

/** Classify a MIME type as an OHTTP media type, or null if it is not one. */
export function ohttpKind(mime: string): OhttpKind | null {
  const m = mime.split(';')[0].trim().toLowerCase()
  if (m === 'message/ohttp-req') return 'req'
  if (m === 'message/ohttp-res') return 'res'
  if (m === 'application/ohttp-keys') return 'keys'
  return null
}
