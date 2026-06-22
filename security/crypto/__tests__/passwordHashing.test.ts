import { describe, it, expect } from "vitest";
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  isArgon2idHash,
  DEFAULT_PARAMS,
  MAX_PASSWORD_BYTES,
} from "../passwordHashing.js";

describe("passwordHashing (Argon2id)", () => {
  it("produces an Argon2id PHC hash, never the plaintext", async () => {
    const h = await hashPassword("correct horse battery staple");
    expect(h.startsWith("$argon2id$")).toBe(true);
    expect(h).not.toContain("correct horse");
    expect(isArgon2idHash(h)).toBe(true);
  });

  it("verifies correct passwords and rejects wrong ones", async () => {
    const h = await hashPassword("s3cret-pass");
    expect(await verifyPassword(h, "s3cret-pass")).toBe(true);
    expect(await verifyPassword(h, "wrong")).toBe(false);
  });

  it("uses a unique salt per hash (same input ⇒ different hash)", async () => {
    const a = await hashPassword("same-input");
    const b = await hashPassword("same-input");
    expect(a).not.toEqual(b);
    expect(await verifyPassword(a, "same-input")).toBe(true);
    expect(await verifyPassword(b, "same-input")).toBe(true);
  });

  it("refuses to verify against non-Argon2id material (e.g. a SHA-256 column)", async () => {
    const sha256Hex = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    expect(await verifyPassword(sha256Hex, "password")).toBe(false);
  });

  it("flags rehash when params are weaker than policy", async () => {
    const weak = await hashPassword("x", { params: { memoryCost: 19456, timeCost: 2 } });
    expect(needsRehash(weak, DEFAULT_PARAMS)).toBe(true);
    const strong = await hashPassword("x");
    expect(needsRehash(strong, DEFAULT_PARAMS)).toBe(false);
  });

  it("rejects empty and oversized inputs", async () => {
    await expect(hashPassword("")).rejects.toThrow();
    await expect(hashPassword("a".repeat(MAX_PASSWORD_BYTES + 1))).rejects.toThrow();
  });

  it("supports an optional server-side pepper", async () => {
    const pepper = Buffer.from("0123456789abcdef0123456789abcdef");
    const h = await hashPassword("p@ss", { pepper });
    expect(await verifyPassword(h, "p@ss", { pepper })).toBe(true);
    expect(await verifyPassword(h, "p@ss")).toBe(false); // wrong/no pepper fails
  });
});
