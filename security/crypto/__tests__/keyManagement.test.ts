import { describe, it, expect } from "vitest";
import {
  generateDek,
  wrapDek,
  unwrapDek,
  EnvKeyProvider,
  InMemoryKeyProvider,
  DEK_BYTES,
} from "../keyManagement.js";
import { getSodium } from "../_sodium.js";

describe("keyManagement (envelope encryption)", () => {
  it("wraps and unwraps a DEK round-trip", async () => {
    const provider = await new InMemoryKeyProvider().withRandomKek();
    const dek = await generateDek();
    expect(dek.length).toBe(DEK_BYTES);
    const wrapped = await wrapDek(provider, dek);
    const unwrapped = await unwrapDek(provider, wrapped);
    expect(Buffer.from(unwrapped)).toEqual(Buffer.from(dek));
  });

  it("never exposes the raw DEK in the wrapped blob", async () => {
    const provider = await new InMemoryKeyProvider().withRandomKek();
    const dek = await generateDek();
    const wrapped = await wrapDek(provider, dek);
    const sodium = await getSodium();
    const dekB64 = sodium.to_base64(dek, sodium.base64_variants.ORIGINAL);
    expect(wrapped.ct).not.toContain(dekB64);
  });

  it("fails to unwrap with the wrong KEK", async () => {
    const a = await new InMemoryKeyProvider("A").withRandomKek("A");
    const b = await new InMemoryKeyProvider("A").withRandomKek("A"); // different random key, same id
    const dek = await generateDek();
    const wrapped = await wrapDek(a, dek);
    await expect(unwrapDek(b, wrapped)).rejects.toThrow();
  });

  it("EnvKeyProvider throws when the KEK is not in the environment", async () => {
    const provider = new EnvKeyProvider("MISSING", {} as NodeJS.ProcessEnv);
    await expect(provider.getKek("MISSING")).rejects.toThrow(/not available/);
  });

  it("EnvKeyProvider reads a base64 KEK from the environment", async () => {
    const sodium = await getSodium();
    const raw = sodium.to_base64(sodium.randombytes_buf(DEK_BYTES), sodium.base64_variants.ORIGINAL);
    const env = { GUARDIAN_KEK_PRIMARY: raw } as unknown as NodeJS.ProcessEnv;
    const provider = new EnvKeyProvider("PRIMARY", env);
    const dek = await generateDek();
    const wrapped = await wrapDek(provider, dek);
    expect(Buffer.from(await unwrapDek(provider, wrapped))).toEqual(Buffer.from(dek));
  });
});
