import { describe, it, expect } from "vitest";
import {
  HashChainAuditLog,
  generateAuditSigningKeypair,
  type AuditEntry,
} from "../auditLogIntegrity.js";

describe("auditLogIntegrity (tamper-evident)", () => {
  it("verifies an intact hash chain", async () => {
    const log = new HashChainAuditLog();
    await log.recordAdminAccess({ actor: "admin_test", action: "view_user", target: "u-1" });
    await log.recordAdminAccess({ actor: "admin_test", action: "export_data", target: "u-2" });
    expect(await log.verify()).toBe(true);
  });

  it("detects tampering with a past entry", async () => {
    const log = new HashChainAuditLog();
    await log.recordAdminAccess({ actor: "admin_test", action: "view_user", target: "u-1" });
    await log.recordAdminAccess({ actor: "admin_test", action: "view_user", target: "u-2" });
    const entries = log.all() as AuditEntry[];
    entries[0]!.target = "u-999"; // mutate history
    expect(await log.verify()).toBe(false);
  });

  it("supports Ed25519 signatures and detects forged ones", async () => {
    const { publicKey, privateKey } = await generateAuditSigningKeypair();
    const log = new HashChainAuditLog();
    await log.recordAdminAccess({ actor: "admin_test", action: "disable_protection" }, privateKey);
    expect(await log.verify(publicKey)).toBe(true);

    const other = await generateAuditSigningKeypair();
    expect(await log.verify(other.publicKey)).toBe(false); // wrong verify key
  });
});
