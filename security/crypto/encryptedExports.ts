/**
 * Module 6 — Encrypted backup / export.
 *
 * Library: libsodium secretstream (XChaCha20-Poly1305) for chunked authenticated
 * encryption of arbitrarily large exports, plus:
 *   - passphrase mode: key derived with Argon2id (libsodium crypto_pwhash, MODERATE limits)
 *     using a unique random salt.
 *   - recipient mode: a random stream key sealed to a recipient X25519 public key
 *     (crypto_box_seal), so only the holder of the private key can open the export.
 *
 * Guarantees: every export produced here is encrypted end-to-end; the container holds only
 * ciphertext + public parameters (salt/header/sealed key). The Guardian policy checker
 * verifies that sensitive export paths use this module rather than emitting raw data.
 */
import { Buffer } from "node:buffer";

import { getSodium } from "./_sodium.js";

const MAGIC = Buffer.from("INVXBK1\0", "binary"); // 8 bytes
const MODE_PASSPHRASE = 1;
const MODE_RECIPIENT = 2;
const CHUNK = 64 * 1024;

export interface RecipientKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generate an X25519 keypair for recipient-mode exports. */
export async function generateRecipientKeypair(): Promise<RecipientKeypair> {
  const sodium = await getSodium();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

function u32(n: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n, 0);
  return b;
}

async function streamEncrypt(key: Uint8Array, data: Uint8Array): Promise<Buffer> {
  const sodium = await getSodium();
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const parts: Buffer[] = [Buffer.from(header)];
  const total = data.length;
  if (total === 0) {
    const c = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array(0),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    );
    parts.push(u32(c.length), Buffer.from(c));
    return Buffer.concat(parts);
  }
  for (let off = 0; off < total; off += CHUNK) {
    const end = Math.min(off + CHUNK, total);
    const last = end >= total;
    const tag = last
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const c = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      data.subarray(off, end),
      null,
      tag,
    );
    parts.push(u32(c.length), Buffer.from(c));
  }
  return Buffer.concat(parts);
}

async function streamDecrypt(key: Uint8Array, body: Buffer): Promise<Buffer> {
  const sodium = await getSodium();
  const headerLen = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  const header = body.subarray(0, headerLen);
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  const out: Buffer[] = [];
  let pos = headerLen;
  for (;;) {
    if (pos + 4 > body.length) throw new Error("truncated export");
    const len = body.readUInt32BE(pos);
    pos += 4;
    const c = body.subarray(pos, pos + len);
    pos += len;
    const res = sodium.crypto_secretstream_xchacha20poly1305_pull(state, c, null);
    if (!res) throw new Error("export decryption failed (tampered or wrong key)");
    out.push(Buffer.from(res.message));
    if (res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
  }
  return Buffer.concat(out);
}

/** Encrypt an export protected by a passphrase (Argon2id-derived key). */
export async function encryptExportWithPassphrase(
  data: Uint8Array,
  passphrase: string,
): Promise<Buffer> {
  const sodium = await getSodium();
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  const key = sodium.crypto_pwhash(
    sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    passphrase,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  const body = await streamEncrypt(key, data);
  return Buffer.concat([
    MAGIC,
    Buffer.from([MODE_PASSPHRASE]),
    Buffer.from(salt),
    u32(opslimit),
    u32(memlimit),
    body,
  ]);
}

/** Encrypt an export to a recipient's X25519 public key (only their private key opens it). */
export async function encryptExportToRecipient(
  data: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<Buffer> {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES);
  const sealed = sodium.crypto_box_seal(key, recipientPublicKey);
  const body = await streamEncrypt(key, data);
  return Buffer.concat([
    MAGIC,
    Buffer.from([MODE_RECIPIENT]),
    u32(sealed.length),
    Buffer.from(sealed),
    body,
  ]);
}

function readHeader(container: Buffer): { mode: number; pos: number } {
  if (!container.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("not an INVISABLE encrypted export");
  }
  const mode = container[MAGIC.length]!;
  return { mode, pos: MAGIC.length + 1 };
}

/** Decrypt a passphrase-protected export. */
export async function decryptExportWithPassphrase(
  container: Buffer,
  passphrase: string,
): Promise<Buffer> {
  const sodium = await getSodium();
  const { mode, pos } = readHeader(container);
  if (mode !== MODE_PASSPHRASE) throw new Error("export is not passphrase-protected");
  let p = pos;
  const salt = container.subarray(p, p + sodium.crypto_pwhash_SALTBYTES);
  p += sodium.crypto_pwhash_SALTBYTES;
  const opslimit = container.readUInt32BE(p);
  p += 4;
  const memlimit = container.readUInt32BE(p);
  p += 4;
  const key = sodium.crypto_pwhash(
    sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    passphrase,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  return streamDecrypt(key, container.subarray(p));
}

/** Decrypt a recipient-protected export using the recipient's keypair. */
export async function decryptExportForRecipient(
  container: Buffer,
  keypair: RecipientKeypair,
): Promise<Buffer> {
  const sodium = await getSodium();
  const { mode, pos } = readHeader(container);
  if (mode !== MODE_RECIPIENT) throw new Error("export is not recipient-protected");
  let p = pos;
  const sealedLen = container.readUInt32BE(p);
  p += 4;
  const sealed = container.subarray(p, p + sealedLen);
  p += sealedLen;
  const key = sodium.crypto_box_seal_open(sealed, keypair.publicKey, keypair.privateKey);
  if (!key) throw new Error("could not unseal export key (wrong recipient)");
  return streamDecrypt(key, container.subarray(p));
}
