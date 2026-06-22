/**
 * Module 8 — Admin audit-log integrity (tamper-evident).
 *
 * Two layers, both using established primitives:
 *   - Hash chain: each entry embeds the SHA-256 of the previous entry (Node `crypto`).
 *     Any retroactive edit breaks the chain and is detected by `verify()`.
 *   - Optional Ed25519 signatures (libsodium) over each entry for non-repudiation, so a
 *     party who can append cannot forge or silently rewrite history without the signing key.
 *
 * SHA-256 here is for INTEGRITY, not password storage — an appropriate, fast hash for this
 * purpose. Every privileged/admin access should be recorded via `recordAdminAccess`.
 */
import { createHash } from "node:crypto";

import { getSodium } from "./_sodium.js";

const GENESIS = "0".repeat(64);

/** Deterministic JSON: object keys sorted recursively so hashing is stable. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}
function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    return Object.keys(v as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = sortDeep((v as Record<string, unknown>)[k]);
        return acc;
      }, {});
  }
  return v;
}

export interface AuditBody {
  ts: string;
  actor: string;
  action: string;
  target?: string;
  detail?: Record<string, unknown>;
}

export interface AuditEntry extends AuditBody {
  prev: string;
  hash: string;
  sig?: string; // base64 Ed25519 signature over `hash`
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

export class HashChainAuditLog {
  private entries: AuditEntry[] = [];

  constructor(seed: AuditEntry[] = []) {
    this.entries = [...seed];
  }

  private lastHash(): string {
    return this.entries.length ? this.entries[this.entries.length - 1]!.hash : GENESIS;
  }

  /** Append an entry. If `signingKey` is given, attach an Ed25519 signature over the hash. */
  async append(body: AuditBody, signingKey?: Uint8Array): Promise<AuditEntry> {
    const prev = this.lastHash();
    const core = { ...body, prev };
    const hash = sha256Hex(canonicalize(core));
    const entry: AuditEntry = { ...core, hash };
    if (signingKey) {
      const sodium = await getSodium();
      const sig = sodium.crypto_sign_detached(sodium.from_string(hash), signingKey);
      entry.sig = sodium.to_base64(sig, sodium.base64_variants.ORIGINAL);
    }
    this.entries.push(entry);
    return entry;
  }

  /** Convenience: record an admin/privileged access. */
  async recordAdminAccess(
    params: { actor: string; action: string; target?: string; detail?: Record<string, unknown> },
    signingKey?: Uint8Array,
  ): Promise<AuditEntry> {
    return this.append({ ts: new Date().toISOString(), ...params }, signingKey);
  }

  all(): readonly AuditEntry[] {
    return this.entries;
  }

  /** Recompute the chain (and optionally verify signatures). Returns true if intact. */
  async verify(verifyKey?: Uint8Array): Promise<boolean> {
    let prev = GENESIS;
    const sodium = verifyKey ? await getSodium() : null;
    for (const e of this.entries) {
      if (e.prev !== prev) return false;
      const { hash, sig, ...core } = e;
      if (sha256Hex(canonicalize(core)) !== hash) return false;
      if (verifyKey) {
        if (!sig) return false;
        const ok = sodium!.crypto_sign_verify_detached(
          sodium!.from_base64(sig, sodium!.base64_variants.ORIGINAL),
          sodium!.from_string(hash),
          verifyKey,
        );
        if (!ok) return false;
      }
      prev = hash;
    }
    return true;
  }
}

/** Generate an Ed25519 signing keypair for audit signatures. */
export async function generateAuditSigningKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const sodium = await getSodium();
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}
