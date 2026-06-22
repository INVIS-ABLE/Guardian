/**
 * Module 3 — Token rotation.
 *
 * Library: `jose` for signed access tokens (JWS). Node `crypto` for opaque refresh tokens.
 *
 *   - Access tokens are short-lived (default 10 min) signed JWTs. They are delivered to the
 *     browser via the HttpOnly session cookie flow — NEVER stored in localStorage.
 *   - Refresh tokens are opaque 256-bit CSPRNG values. Only their SHA-256 hash is stored
 *     (high-entropy random ⇒ hashing is appropriate; these are not passwords).
 *   - Refresh-token ROTATION: every use issues a new refresh token and invalidates the old.
 *     Re-presentation of an already-rotated token ⇒ token theft ⇒ the whole token family is
 *     revoked (reuse detection).
 *   - Step-up: `auth_time`/`amr` claims drive reauthentication for sensitive actions.
 */
import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// ----------------------------- Access tokens (JWT) ---------------------------------------

export interface AccessTokenClaims {
  sub: string; // user id
  sid: string; // session id (ties token to the HttpOnly session)
  amr?: string[]; // auth methods, e.g. ["pwd","passkey"] or ["pwd","totp"]
  scope?: string;
}

export interface IssueAccessOptions {
  secret: string; // >= 32 bytes; from a secret store, not the repo
  ttlSeconds?: number; // default 600 (10 min)
  issuer?: string;
  audience?: string;
  authTime?: number; // unix seconds of the last interactive auth
}

function secretKey(secret: string): Uint8Array {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("access-token secret must be at least 32 bytes");
  }
  return new TextEncoder().encode(secret);
}

export async function issueAccessToken(
  claims: AccessTokenClaims,
  opts: IssueAccessOptions,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const ttl = opts.ttlSeconds ?? 600;
  const jwt = new SignJWT({
    sid: claims.sid,
    amr: claims.amr ?? [],
    scope: claims.scope ?? "",
    auth_time: opts.authTime ?? now,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .setJti(randomBytes(16).toString("hex"));
  if (opts.issuer) jwt.setIssuer(opts.issuer);
  if (opts.audience) jwt.setAudience(opts.audience);
  return jwt.sign(secretKey(opts.secret));
}

export async function verifyAccessToken(
  token: string,
  opts: { secret: string; issuer?: string; audience?: string },
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, secretKey(opts.secret), {
    algorithms: ["HS256"], // pin the algorithm; reject "none"/RS confusion
    ...(opts.issuer ? { issuer: opts.issuer } : {}),
    ...(opts.audience ? { audience: opts.audience } : {}),
  });
  return payload;
}

/**
 * Step-up: whether a sensitive action requires reauthentication because the last
 * interactive auth is older than `maxAgeSeconds`.
 */
export function requiresReauth(payload: JWTPayload, maxAgeSeconds: number): boolean {
  const authTime = typeof payload.auth_time === "number" ? payload.auth_time : 0;
  const now = Math.floor(Date.now() / 1000);
  return now - authTime > maxAgeSeconds;
}

// ----------------------------- Refresh tokens (opaque) -----------------------------------

export class ReuseDetectedError extends Error {
  constructor(public readonly familyId: string) {
    super("refresh token reuse detected; family revoked");
    this.name = "ReuseDetectedError";
  }
}
export class InvalidRefreshTokenError extends Error {
  constructor() {
    super("invalid or unknown refresh token");
    this.name = "InvalidRefreshTokenError";
  }
}

export interface RefreshRecord {
  tokenHash: string;
  familyId: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  rotated: boolean;
}

export interface RefreshTokenStore {
  save(rec: RefreshRecord): Promise<void>;
  findByHash(tokenHash: string): Promise<RefreshRecord | null>;
  markRotated(tokenHash: string): Promise<void>;
  revokeFamily(familyId: string): Promise<void>;
  isFamilyRevoked(familyId: string): Promise<boolean>;
}

/** Reference in-memory store for tests; production backs this with a database. */
export class InMemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly records = new Map<string, RefreshRecord>();
  private readonly revoked = new Set<string>();
  async save(rec: RefreshRecord): Promise<void> {
    this.records.set(rec.tokenHash, rec);
  }
  async findByHash(tokenHash: string): Promise<RefreshRecord | null> {
    return this.records.get(tokenHash) ?? null;
  }
  async markRotated(tokenHash: string): Promise<void> {
    const r = this.records.get(tokenHash);
    if (r) r.rotated = true;
  }
  async revokeFamily(familyId: string): Promise<void> {
    this.revoked.add(familyId);
  }
  async isFamilyRevoked(familyId: string): Promise<boolean> {
    return this.revoked.has(familyId);
  }
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function constantTimeEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export interface IssuedRefresh {
  token: string; // give to client (in HttpOnly cookie); store only the hash
  familyId: string;
  expiresAt: number;
}

/** Issue a brand-new refresh token, starting a new family (e.g. at login). */
export async function issueRefreshToken(
  store: RefreshTokenStore,
  params: { userId: string; familyId?: string; ttlSeconds?: number },
): Promise<IssuedRefresh> {
  const token = randomBytes(32).toString("base64url");
  const familyId = params.familyId ?? randomBytes(16).toString("hex");
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + (params.ttlSeconds ?? 60 * 60 * 24 * 14); // 14 days
  await store.save({
    tokenHash: hashRefreshToken(token),
    familyId,
    userId: params.userId,
    issuedAt: now,
    expiresAt,
    rotated: false,
  });
  return { token, familyId, expiresAt };
}

/**
 * Rotate a refresh token. On success returns a NEW refresh token in the same family and
 * the user id (caller then mints a fresh access token). Detects reuse of an already-rotated
 * token and revokes the whole family.
 */
export async function rotateRefreshToken(
  store: RefreshTokenStore,
  presentedToken: string,
  opts: { ttlSeconds?: number } = {},
): Promise<IssuedRefresh & { userId: string }> {
  const hash = hashRefreshToken(presentedToken);
  const rec = await store.findByHash(hash);
  if (!rec) throw new InvalidRefreshTokenError();

  if (await store.isFamilyRevoked(rec.familyId)) {
    throw new ReuseDetectedError(rec.familyId);
  }
  if (rec.rotated) {
    // The token was already exchanged once — this is a replay of a stolen token.
    await store.revokeFamily(rec.familyId);
    throw new ReuseDetectedError(rec.familyId);
  }
  if (!constantTimeEqualHex(hash, rec.tokenHash)) {
    throw new InvalidRefreshTokenError();
  }
  if (Math.floor(Date.now() / 1000) > rec.expiresAt) {
    throw new InvalidRefreshTokenError();
  }

  await store.markRotated(hash);
  const next = await issueRefreshToken(store, {
    userId: rec.userId,
    familyId: rec.familyId,
    ttlSeconds: opts.ttlSeconds,
  });
  return { ...next, userId: rec.userId };
}
