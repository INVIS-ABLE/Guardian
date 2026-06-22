import { describe, it, expect } from "vitest";
import {
  generateIdentityKeypair,
  encryptMessage,
  decryptMessage,
  sealMessage,
  openSealedMessage,
  E2EE_NOTES,
} from "../e2eeMessaging.js";

describe("e2eeMessaging (libsodium baseline)", () => {
  it("encrypts and decrypts an authenticated message", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const msg = await encryptMessage(alice.privateKey, bob.publicKey, "hello bob");
    expect(msg.ct).not.toContain("hello");
    const out = await decryptMessage(bob.privateKey, alice.publicKey, msg);
    expect(out).toBe("hello bob");
  });

  it("fails to decrypt with the wrong recipient key", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const mallory = await generateIdentityKeypair();
    const msg = await encryptMessage(alice.privateKey, bob.publicKey, "secret");
    await expect(decryptMessage(mallory.privateKey, alice.publicKey, msg)).rejects.toThrow();
  });

  it("supports sealed-sender messages", async () => {
    const bob = await generateIdentityKeypair();
    const sealed = await sealMessage(bob.publicKey, "anonymous hi");
    expect(await openSealedMessage(bob, sealed)).toBe("anonymous hi");
  });

  it("documents that the baseline lacks forward secrecy (libsignal recommended)", () => {
    expect(E2EE_NOTES.baselineForwardSecrecy).toBe(false);
    expect(E2EE_NOTES.serverSeesPlaintext).toBe(false);
  });
});
