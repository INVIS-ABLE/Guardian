import { describe, it, expect } from "vitest";
import { encryptField, decryptField, type FieldContext } from "../fieldEncryption.js";
import { generateDek } from "../keyManagement.js";

const ctx: FieldContext = { table: "user_profile", recordId: "u-123", field: "health_conditions" };

describe("fieldEncryption (XChaCha20-Poly1305 AEAD)", () => {
  it("round-trips a sensitive field", async () => {
    const dek = await generateDek();
    const enc = await encryptField(dek, "asthma; anxiety", ctx);
    expect(enc.ct).not.toContain("asthma");
    expect(await decryptField(dek, enc, ctx)).toBe("asthma; anxiety");
  });

  it("fails to decrypt with a different context (AAD binding stops cut-and-paste)", async () => {
    const dek = await generateDek();
    const enc = await encryptField(dek, "secret value", ctx);
    const otherRecord = { ...ctx, recordId: "u-999" };
    await expect(decryptField(dek, enc, otherRecord)).rejects.toThrow();
    const otherField = { ...ctx, field: "display_name" };
    await expect(decryptField(dek, enc, otherField)).rejects.toThrow();
  });

  it("fails to decrypt if the ciphertext is tampered", async () => {
    const dek = await generateDek();
    const enc = await encryptField(dek, "tamper me", ctx);
    const bytes = Buffer.from(enc.ct, "base64");
    bytes[0]! ^= 0xff;
    const tampered = { ...enc, ct: bytes.toString("base64") };
    await expect(decryptField(dek, tampered, ctx)).rejects.toThrow();
  });

  it("uses a unique nonce per encryption", async () => {
    const dek = await generateDek();
    const a = await encryptField(dek, "x", ctx);
    const b = await encryptField(dek, "x", ctx);
    expect(a.nonce).not.toEqual(b.nonce);
  });
});
