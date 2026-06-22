/**
 * Module 4 — Key management (envelope encryption).
 *
 * Design rule: encryption keys are NEVER stored beside the data they protect.
 *
 *   - Data Encryption Keys (DEKs) are random 256-bit keys that encrypt records/fields.
 *   - A DEK is "wrapped" (encrypted) by a Key Encryption Key (KEK) and only the WRAPPED
 *     DEK travels with the data. The plaintext KEK lives in a separate trust boundary
 *     (KMS / HashiCorp Vault / cloud KMS / a secret store) behind `KeyProvider`.
 *   - Wrapping uses libsodium XChaCha20-Poly1305 (AEAD). No custom crypto.
 *
 * Swap `EnvKeyProvider` for a real KMS provider in production; the envelope format is
 * identical so data does not need re-encrypting.
 */
import { getSodium } from "./_sodium.js";

export const DEK_BYTES = 32; // XChaCha20-Poly1305 key size

/** A wrapped (encrypted) DEK. Safe to store next to the ciphertext it helps decrypt. */
export interface WrappedDek {
  v: 1;
  kekId: string; // which KEK wrapped it — the KEK itself is NOT here
  nonce: string; // base64
  ct: string; // base64 (wrapped DEK + AEAD tag)
}

/**
 * Source of KEKs. Implementations resolve a KEK id to raw key bytes from a trust boundary
 * that is SEPARATE from the data store. The plaintext KEK must never be persisted with data.
 */
export interface KeyProvider {
  /** Default/active KEK id for new wraps. */
  activeKekId(): Promise<string>;
  /** Resolve a KEK id to 32 raw key bytes. Throws if unknown/unavailable. */
  getKek(kekId: string): Promise<Uint8Array>;
}

/**
 * Reference provider: reads base64 KEKs from environment variables of the form
 * `GUARDIAN_KEK_<ID>` (e.g. GUARDIAN_KEK_PRIMARY). Suitable for local/dev and CI; in
 * production back this with a managed KMS. The KEK is supplied out-of-band, never written
 * to the database.
 */
export class EnvKeyProvider implements KeyProvider {
  constructor(
    private readonly activeId = process.env.GUARDIAN_ACTIVE_KEK ?? "PRIMARY",
    private readonly env: NodeJS.ProcessEnv = process.env,
  ) {}

  async activeKekId(): Promise<string> {
    return this.activeId;
  }

  async getKek(kekId: string): Promise<Uint8Array> {
    const raw = this.env[`GUARDIAN_KEK_${kekId}`];
    if (!raw) {
      throw new Error(
        `KEK '${kekId}' not available (set GUARDIAN_KEK_${kekId}). ` +
          `KEKs are resolved from a separate secret store, never from the data store.`,
      );
    }
    const sodium = await getSodium();
    const key = sodium.from_base64(raw, sodium.base64_variants.ORIGINAL);
    if (key.length !== DEK_BYTES) {
      throw new Error(`KEK '${kekId}' must be ${DEK_BYTES} bytes (base64-encoded)`);
    }
    return key;
  }
}

/** In-memory provider for tests. Never use in production. */
export class InMemoryKeyProvider implements KeyProvider {
  private readonly keks = new Map<string, Uint8Array>();
  constructor(private readonly activeId = "TEST") {}

  async withRandomKek(id = this.activeId): Promise<this> {
    const sodium = await getSodium();
    this.keks.set(id, sodium.randombytes_buf(DEK_BYTES));
    return this;
  }
  setKek(id: string, key: Uint8Array): void {
    this.keks.set(id, key);
  }
  async activeKekId(): Promise<string> {
    return this.activeId;
  }
  async getKek(kekId: string): Promise<Uint8Array> {
    const k = this.keks.get(kekId);
    if (!k) throw new Error(`unknown KEK '${kekId}'`);
    return k;
  }
}

/** Generate a fresh random Data Encryption Key. */
export async function generateDek(): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.randombytes_buf(DEK_BYTES);
}

/** Wrap (encrypt) a DEK under the provider's active KEK. */
export async function wrapDek(provider: KeyProvider, dek: Uint8Array): Promise<WrappedDek> {
  const sodium = await getSodium();
  const kekId = await provider.activeKekId();
  const kek = await provider.getKek(kekId);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    dek,
    sodium.from_string(`wrap:${kekId}`), // AAD binds the wrap to its KEK id
    null,
    nonce,
    kek,
  );
  return {
    v: 1,
    kekId,
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ct: sodium.to_base64(ct, sodium.base64_variants.ORIGINAL),
  };
}

/** Unwrap (decrypt) a DEK. Throws if the KEK is wrong or the blob was tampered with. */
export async function unwrapDek(provider: KeyProvider, wrapped: WrappedDek): Promise<Uint8Array> {
  const sodium = await getSodium();
  const kek = await provider.getKek(wrapped.kekId);
  const nonce = sodium.from_base64(wrapped.nonce, sodium.base64_variants.ORIGINAL);
  const ct = sodium.from_base64(wrapped.ct, sodium.base64_variants.ORIGINAL);
  const dek = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ct,
    sodium.from_string(`wrap:${wrapped.kekId}`),
    nonce,
    kek,
  );
  return dek;
}
