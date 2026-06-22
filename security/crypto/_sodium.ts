/**
 * Shared libsodium loader.
 *
 * libsodium-wrappers-sumo is a WASM build of libsodium (jedisct1/libsodium) and works in
 * both Node and the browser/PWA. We never implement primitives ourselves — every AEAD,
 * KDF, box, and signature call routes through libsodium.
 */
import _sodium from "libsodium-wrappers-sumo";

let ready: Promise<typeof _sodium> | null = null;

/** Returns the initialised libsodium instance (idempotent). */
export async function getSodium(): Promise<typeof _sodium> {
  if (ready === null) {
    ready = _sodium.ready.then(() => _sodium);
  }
  return ready;
}

export type Sodium = Awaited<ReturnType<typeof getSodium>>;
