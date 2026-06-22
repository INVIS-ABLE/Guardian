/**
 * Module 5 — Field-level encryption for sensitive profile/health/disability data.
 *
 * Library: libsodium XChaCha20-Poly1305 (IETF) AEAD. No custom crypto.
 *
 *   - Each field is encrypted with a DEK (from key management). The DEK is wrapped by a
 *     KEK and stored separately — never beside the ciphertext.
 *   - A fresh 192-bit random nonce per encryption (XChaCha nonces are large enough to be
 *     safely random).
 *   - Associated Data (AAD) binds the ciphertext to its context — `table:recordId:field`
 *     — so an attacker cannot transplant a valid ciphertext from one record/field to
 *     another (a "cut-and-paste" attack). Decryption with mismatched context fails.
 *   - The plaintext is never logged; envelopes carry only ciphertext + nonce.
 */
import { getSodium } from "./_sodium.js";

export interface FieldContext {
  /** Logical table/collection, e.g. "user_profile". */
  table: string;
  /** Stable record identifier, e.g. the user id. */
  recordId: string;
  /** Field name, e.g. "health_conditions". */
  field: string;
}

export interface EncryptedField {
  v: 1;
  alg: "xchacha20poly1305-ietf";
  nonce: string; // base64
  ct: string; // base64 (ciphertext + tag)
}

function aad(ctx: FieldContext): string {
  return `${ctx.table}:${ctx.recordId}:${ctx.field}`;
}

/** Encrypt a single sensitive field value under the given DEK and context. */
export async function encryptField(
  dek: Uint8Array,
  plaintext: string,
  ctx: FieldContext,
): Promise<EncryptedField> {
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    sodium.from_string(aad(ctx)),
    null,
    nonce,
    dek,
  );
  return {
    v: 1,
    alg: "xchacha20poly1305-ietf",
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ct: sodium.to_base64(ct, sodium.base64_variants.ORIGINAL),
  };
}

/** Decrypt a field. Throws if the context/AAD does not match or the ciphertext was altered. */
export async function decryptField(
  dek: Uint8Array,
  enc: EncryptedField,
  ctx: FieldContext,
): Promise<string> {
  const sodium = await getSodium();
  if (enc.alg !== "xchacha20poly1305-ietf") {
    throw new Error(`unsupported field alg: ${enc.alg}`);
  }
  const nonce = sodium.from_base64(enc.nonce, sodium.base64_variants.ORIGINAL);
  const ct = sodium.from_base64(enc.ct, sodium.base64_variants.ORIGINAL);
  const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ct,
    sodium.from_string(aad(ctx)),
    nonce,
    dek,
  );
  return sodium.to_string(pt);
}
