/**
 * Module 2 — Session security (cookies).
 *
 * Library: `cookie` for RFC 6265 serialization. This module enforces secure defaults and
 * REFUSES to emit an insecure session cookie:
 *   - HttpOnly (no JS access — defeats XSS token theft)
 *   - Secure (HTTPS only)
 *   - SameSite=Strict by default (Lax allowed for top-level nav flows)
 *   - `__Host-` name prefix → Path=/ and no Domain, binding the cookie to the exact host
 *   - Session ids are 256-bit CSPRNG values; the cookie carries an opaque id, never a JWT
 *     and never tokens in localStorage.
 */
import { serialize, type SerializeOptions } from "cookie";
import { randomBytes } from "node:crypto";

export type SameSite = "strict" | "lax";

export interface SessionCookieOptions {
  /** Cookie name. Use the default `__Host-` prefixed name for strongest binding. */
  name?: string;
  /** Lifetime in seconds. Short-lived; pair with refresh-token rotation. Default 1h. */
  maxAgeSeconds?: number;
  sameSite?: SameSite;
  path?: string;
  /** Allow disabling Secure/`__Host-` ONLY for local http dev. Never in production. */
  insecureDevAllowed?: boolean;
}

export const DEFAULT_SESSION_COOKIE_NAME = "__Host-invisable_session";

/** Generate a 256-bit opaque session id (base64url). Store the hash server-side, not this. */
export function generateSessionId(): string {
  return randomBytes(32).toString("base64url");
}

function assertHostPrefixRules(name: string, opts: SerializeOptions): void {
  // Per the cookie spec, `__Host-` requires Secure, Path=/, and NO Domain attribute.
  if (name.startsWith("__Host-")) {
    if (!opts.secure) throw new Error("__Host- cookies must be Secure");
    if (opts.path !== "/") throw new Error("__Host- cookies must have Path=/");
    if (opts.domain) throw new Error("__Host- cookies must not set Domain");
  }
}

/** Serialize a hardened session Set-Cookie header value. */
export function serializeSessionCookie(value: string, options: SessionCookieOptions = {}): string {
  const name = options.name ?? DEFAULT_SESSION_COOKIE_NAME;
  const secure = !options.insecureDevAllowed;
  if (!secure && name.startsWith("__Host-")) {
    throw new Error("refusing: __Host- cookie cannot be insecure. Use a non-prefixed dev name.");
  }
  const opts: SerializeOptions = {
    httpOnly: true, // non-negotiable
    secure, // non-negotiable in production
    sameSite: options.sameSite ?? "strict",
    path: options.path ?? "/",
    maxAge: options.maxAgeSeconds ?? 3600,
  };
  assertHostPrefixRules(name, opts);
  return serialize(name, value, opts);
}

/** Serialize a cookie that immediately clears the session. */
export function clearSessionCookie(name: string = DEFAULT_SESSION_COOKIE_NAME): string {
  const opts: SerializeOptions = {
    httpOnly: true,
    secure: !name.startsWith("__Host-") ? true : true,
    sameSite: "strict",
    path: "/",
    maxAge: 0,
    expires: new Date(0),
  };
  assertHostPrefixRules(name, opts);
  return serialize(name, "", opts);
}

/**
 * Static guard for reviewers/tests: returns problems with a proposed cookie config, or []
 * if it is hardened. Used by the Guardian crypto-policy checker's session checks.
 */
export function auditCookieConfig(cfg: {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  name?: string;
}): string[] {
  const problems: string[] = [];
  if (cfg.httpOnly === false) problems.push("session cookie missing HttpOnly");
  if (cfg.secure === false) problems.push("session cookie missing Secure");
  if (cfg.sameSite && !["strict", "lax"].includes(String(cfg.sameSite).toLowerCase())) {
    problems.push(`unsafe SameSite=${cfg.sameSite} (use Strict or Lax)`);
  }
  return problems;
}
