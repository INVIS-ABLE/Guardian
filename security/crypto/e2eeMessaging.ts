/**
 * Module 7 — Optional end-to-end encrypted private messaging.
 *
 * Two supported paths, both established crypto — never custom:
 *
 *   1. RECOMMENDED (Signal-style, full forward secrecy): @signalapp/libsignal-client
 *      implements X3DH + the Double Ratchet. It is an OPTIONAL dependency; when installed,
 *      use `loadLibsignal()` and the Signal session APIs. This gives per-message forward
 *      secrecy and post-compromise security.
 *
 *   2. BASELINE (no extra native deps): libsodium `crypto_box` (X25519 + XSalsa20-Poly1305)
 *      — authenticated public-key encryption. Each message is sender-authenticated and
 *      confidential. NOTE: the baseline does NOT provide ratcheting/forward secrecy; a
 *      compromised long-term key exposes past messages. Use libsignal for that.
 *
 * The server never sees plaintext in either path: keys live on the client; the server only
 * relays ciphertext. This module runs in the PWA (libsodium is WASM) and in Node.
 */
import { getSodium } from "./_sodium.js";

export interface IdentityKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface BoxMessage {
  v: 1;
  alg: "crypto_box_easy";
  nonce: string; // base64
  ct: string; // base64
}

export interface SealedMessage {
  v: 1;
  alg: "crypto_box_seal"; // anonymous sender (sealed sender)
  ct: string; // base64
}

/** Generate an X25519 identity keypair for the baseline path. */
export async function generateIdentityKeypair(): Promise<IdentityKeypair> {
  const sodium = await getSodium();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Encrypt a message to `recipientPublicKey`, authenticated as `senderPrivateKey`. */
export async function encryptMessage(
  senderPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  plaintext: string,
): Promise<BoxMessage> {
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ct = sodium.crypto_box_easy(
    sodium.from_string(plaintext),
    nonce,
    recipientPublicKey,
    senderPrivateKey,
  );
  return {
    v: 1,
    alg: "crypto_box_easy",
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ct: sodium.to_base64(ct, sodium.base64_variants.ORIGINAL),
  };
}

/** Decrypt a message from `senderPublicKey`. Throws if forged or tampered. */
export async function decryptMessage(
  recipientPrivateKey: Uint8Array,
  senderPublicKey: Uint8Array,
  msg: BoxMessage,
): Promise<string> {
  const sodium = await getSodium();
  const nonce = sodium.from_base64(msg.nonce, sodium.base64_variants.ORIGINAL);
  const ct = sodium.from_base64(msg.ct, sodium.base64_variants.ORIGINAL);
  const pt = sodium.crypto_box_open_easy(ct, nonce, senderPublicKey, recipientPrivateKey);
  return sodium.to_string(pt);
}

/** Sealed-sender: encrypt to a recipient without revealing the sender's identity key. */
export async function sealMessage(
  recipientPublicKey: Uint8Array,
  plaintext: string,
): Promise<SealedMessage> {
  const sodium = await getSodium();
  const ct = sodium.crypto_box_seal(sodium.from_string(plaintext), recipientPublicKey);
  return { v: 1, alg: "crypto_box_seal", ct: sodium.to_base64(ct, sodium.base64_variants.ORIGINAL) };
}

/** Open a sealed-sender message with the recipient's keypair. */
export async function openSealedMessage(
  recipient: IdentityKeypair,
  msg: SealedMessage,
): Promise<string> {
  const sodium = await getSodium();
  const ct = sodium.from_base64(msg.ct, sodium.base64_variants.ORIGINAL);
  const pt = sodium.crypto_box_seal_open(ct, recipient.publicKey, recipient.privateKey);
  if (!pt) throw new Error("could not open sealed message (wrong recipient or tampered)");
  return sodium.to_string(pt);
}

/**
 * Lazy-load the optional Signal protocol library for full forward secrecy. Returns null if
 * it isn't installed, so callers can fall back to the baseline path and surface guidance.
 */
export async function loadLibsignal(): Promise<unknown | null> {
  try {
    // Optional dependency; may be absent. Dynamic import avoids a hard requirement.
    return await import("@signalapp/libsignal-client");
  } catch {
    return null;
  }
}

export const E2EE_NOTES = Object.freeze({
  baselineForwardSecrecy: false,
  recommended: "@signalapp/libsignal-client (X3DH + Double Ratchet)",
  serverSeesPlaintext: false,
});
