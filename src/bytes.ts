// Small, dependency-free byte helpers. Kept local so the identity-byte layout is defined in
// exactly one place and matches the `sealed_storage` Move modules bit-for-bit.
//
// Role: every Seal identity is built from bytes (an object id, a big-endian u64, a nonce). If this client and the Move module disagreed on one byte, a person
// could encrypt something that nobody (not even them) could ever decrypt, so the encodings live here once and are tested against the Move vectors.
// Main exports: `hexToBytes`, `bytesToHex`, `objectIdBytes`, `u64beBytes`, `randomBytes`, `concatBytes`. Tested in `tests/bytes.test.ts`.

/** Hex (with or without `0x`) → bytes. Odd-length input is left-padded with a nibble. */
export function hexToBytes(hex: string): Uint8Array {
  // An optional `0x` prefix, in either case.
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  // Reject anything that is not a hex digit (empty is allowed and gives no bytes).
  if (clean.length > 0 && !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error(`hexToBytes: non-hex characters in input: ${hex}`)
  }
  // An odd number of digits gets a leading zero nibble, so `0x1` is the byte 0x01.
  const padded = clean.length % 2 ? '0' + clean : clean
  const out = new Uint8Array(padded.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(padded.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

/** Bytes → lowercase hex (no `0x`). */
export function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  // Two digits per byte, zero-padded, so the output length is always twice the input's.
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

/** A Sui object id → its canonical 32-byte (right-aligned) representation. */
export function objectIdBytes(id: string): Uint8Array {
  const raw = hexToBytes(id)
  if (raw.length === 32) return raw
  // More than 32 bytes cannot be an object id.
  if (raw.length > 32) throw new Error(`object id too long: ${id}`)
  // A short id (`0x2`) is right-aligned: the value sits in the low bytes, the rest are zero, as Sui pads an address.
  const out = new Uint8Array(32)
  out.set(raw, 32 - raw.length)
  return out
}

/** The largest u64 (2^64 - 1). */
const U64_MAX = (1n << 64n) - 1n

/** A u64 → 8 big-endian bytes (matches the on-chain decode in `sealed_storage::timelock`). */
export function u64beBytes(v: number | bigint): Uint8Array {
  // A float or an integer above 2^53 has already lost precision; refuse it rather than encode a different number.
  if (typeof v === 'number' && !Number.isSafeInteger(v)) {
    throw new Error(`u64 must be a safe integer (got ${String(v)}); pass a bigint for larger values`)
  }
  let n = BigInt(v)
  // Unsigned, 64 bits.
  if (n < 0n) throw new Error('u64 must be non-negative')
  if (n > U64_MAX) throw new Error('u64 must be at most 2^64 - 1')
  // Fill from the last byte backwards: the least significant byte goes last (big-endian).
  const out = new Uint8Array(8)
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

/** Cryptographically-random bytes (Web Crypto; available in browsers and Node ≥ 18). */
export function randomBytes(len: number): Uint8Array {
  // The platform's secure generator; `Math.random` must never be used for a nonce or a key.
  return crypto.getRandomValues(new Uint8Array(len))
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  // Size the result once, then copy each part to its offset (no repeated reallocation).
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}
