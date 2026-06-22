/**
 * Module 1 — Password hashing (Argon2id).
 *
 * Library: argon2 (ranisalt/node-argon2 → P-H-C/phc-winner-argon2 reference impl).
 * We do NOT implement hashing ourselves.
 *
 * OWASP Password Storage Cheat Sheet compliance:
 *   - Algorithm: Argon2id (memory-hard, side-channel resistant).
 *   - Unique salt per hash: node-argon2 generates a CSPRNG salt automatically and stores
 *     it inside the PHC string — we never reuse or manage salts manually.
 *   - Slow, memory-hard parameters (see DEFAULT_PARAMS), tunable and verifiable.
 *   - Never a fast hash (MD5/SHA-1/SHA-256) for passwords.
 *   - Plaintext is never stored or logged; only the PHC-encoded hash is persisted.
 *   - Optional pepper (server-side secret) supplied via key management, kept OUT of the DB.
 */
import argon2 from "argon2";

/** OWASP-aligned Argon2id parameters (>= the documented minimums, with headroom). */
export interface Argon2Params {
  /** Memory cost in KiB. OWASP min 19456 (19 MiB); default here 65536 (64 MiB). */
  memoryCost: number;
  /** Iterations (time cost). OWASP min 2; default 3. */
  timeCost: number;
  /** Degree of parallelism. Default 1 (per OWASP guidance). */
  parallelism: number;
}

export const DEFAULT_PARAMS: Readonly<Argon2Params> = Object.freeze({
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
});

/** Hard cap on input length to prevent memory-amplification DoS via huge passwords. */
export const MAX_PASSWORD_BYTES = 4096;

export interface HashOptions {
  params?: Partial<Argon2Params>;
  /**
   * Optional server-side pepper (a secret key kept in a KMS/secret store, NOT beside the
   * hash). Applied as Argon2's keyed mode. Must be the SAME pepper at verify time.
   */
  pepper?: Buffer | Uint8Array;
}

function resolveParams(p?: Partial<Argon2Params>): Argon2Params {
  return { ...DEFAULT_PARAMS, ...(p ?? {}) };
}

function assertPasswordSize(password: string): void {
  const bytes = Buffer.byteLength(password, "utf8");
  if (bytes === 0) throw new Error("password must not be empty");
  if (bytes > MAX_PASSWORD_BYTES) {
    throw new Error(`password exceeds ${MAX_PASSWORD_BYTES} bytes; reject to avoid DoS`);
  }
}

/**
 * Hash a password with Argon2id. Returns a PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`)
 * which embeds the algorithm, parameters, and a unique random salt. Safe to store as-is.
 */
export async function hashPassword(password: string, opts: HashOptions = {}): Promise<string> {
  assertPasswordSize(password);
  const params = resolveParams(opts.params);
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    ...(opts.pepper ? { secret: Buffer.from(opts.pepper) } : {}),
  });
}

/**
 * Verify a password against a stored PHC hash. Constant-time comparison is handled by the
 * library. Returns false on mismatch; never throws on a wrong password.
 */
export async function verifyPassword(
  storedHash: string,
  password: string,
  opts: Pick<HashOptions, "pepper"> = {},
): Promise<boolean> {
  if (typeof storedHash !== "string" || !storedHash.startsWith("$argon2id$")) {
    // Refuse to verify against non-Argon2id material (e.g. a legacy SHA-256 column).
    return false;
  }
  try {
    assertPasswordSize(password);
  } catch {
    return false;
  }
  return argon2.verify(storedHash, password, {
    ...(opts.pepper ? { secret: Buffer.from(opts.pepper) } : {}),
  });
}

/**
 * Whether a stored hash should be re-hashed because it is not Argon2id or uses weaker
 * parameters than the current policy. Call after a successful verify to transparently
 * upgrade users on login.
 */
export function needsRehash(storedHash: string, params: Partial<Argon2Params> = {}): boolean {
  if (!storedHash.startsWith("$argon2id$")) return true;
  const target = resolveParams(params);
  const m = /\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(storedHash);
  if (!m) return true;
  const memoryCost = Number(m[1]);
  const timeCost = Number(m[2]);
  const parallelism = Number(m[3]);
  return (
    memoryCost < target.memoryCost ||
    timeCost < target.timeCost ||
    parallelism < target.parallelism
  );
}

/** True if a stored value is an Argon2id PHC string (used by the policy checker). */
export function isArgon2idHash(value: string): boolean {
  return typeof value === "string" && /^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$/.test(value);
}
