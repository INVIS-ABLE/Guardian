import { describe, it, expect } from "vitest";
import {
  encryptExportWithPassphrase,
  decryptExportWithPassphrase,
  encryptExportToRecipient,
  decryptExportForRecipient,
  generateRecipientKeypair,
} from "../encryptedExports.js";

const data = () => Buffer.from(JSON.stringify({ user: "u-1", health: "private", note: "x".repeat(200000) }));

describe("encryptedExports", () => {
  it("passphrase round-trip; output contains no plaintext", async () => {
    const plain = data();
    const container = await encryptExportWithPassphrase(plain, "correct-horse-battery");
    expect(container.includes(Buffer.from("private"))).toBe(false);
    const out = await decryptExportWithPassphrase(container, "correct-horse-battery");
    expect(out.equals(plain)).toBe(true);
  });

  it("wrong passphrase fails", async () => {
    const container = await encryptExportWithPassphrase(data(), "right");
    await expect(decryptExportWithPassphrase(container, "wrong")).rejects.toThrow();
  });

  it("recipient round-trip; only the private key opens it", async () => {
    const plain = data();
    const kp = await generateRecipientKeypair();
    const container = await encryptExportToRecipient(plain, kp.publicKey);
    const out = await decryptExportForRecipient(container, kp);
    expect(out.equals(plain)).toBe(true);

    const other = await generateRecipientKeypair();
    await expect(decryptExportForRecipient(container, other)).rejects.toThrow();
  });

  it("handles empty exports", async () => {
    const container = await encryptExportWithPassphrase(Buffer.alloc(0), "pw");
    const out = await decryptExportWithPassphrase(container, "pw");
    expect(out.length).toBe(0);
  });
});
