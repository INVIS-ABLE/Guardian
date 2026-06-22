import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCryptoPolicyChecks, shouldFail } from "../cryptoPolicyChecker.js";

let badRoot: string;
let goodRoot: string;

beforeAll(() => {
  badRoot = mkdtempSync(join(tmpdir(), "guardian-bad-"));
  goodRoot = mkdtempSync(join(tmpdir(), "guardian-good-"));

  mkdirSync(join(badRoot, "src"), { recursive: true });
  writeFileSync(
    join(badRoot, "src", "auth.ts"),
    [
      'const password = "hunter2";',
      "localStorage.setItem('access_token', token);",
      "const h = createHash('sha256').update(password).digest('hex');",
      "console.log('user health', user.health_conditions);",
      "const record = { ct: cipher, key: rawKey };",
    ].join("\n"),
  );
  writeFileSync(
    join(badRoot, "package.json"),
    JSON.stringify({ dependencies: { argon2: "^0.41.1" } }),
  );

  mkdirSync(join(goodRoot, "src"), { recursive: true });
  writeFileSync(
    join(goodRoot, "src", "auth.ts"),
    [
      "import { hashPassword } from './passwordHashing.js';",
      "const stored = await hashPassword(input);",
      "// token lives in an HttpOnly cookie, never localStorage",
    ].join("\n"),
  );
  writeFileSync(
    join(goodRoot, "package.json"),
    JSON.stringify({ dependencies: { argon2: "0.41.1", jose: "5.9.6" } }),
  );
});

afterAll(() => {
  rmSync(badRoot, { recursive: true, force: true });
  rmSync(goodRoot, { recursive: true, force: true });
});

describe("cryptoPolicyChecker", () => {
  it("flags the full set of violations in a bad repo", () => {
    const res = runCryptoPolicyChecks(badRoot);
    const rules = new Set(res.findings.map((f) => f.rule));
    expect(rules.has("no-plaintext-password")).toBe(true);
    expect(rules.has("no-token-in-localstorage")).toBe(true);
    expect(rules.has("no-fast-hash-for-password")).toBe(true);
    expect(rules.has("no-health-data-in-logs")).toBe(true);
    expect(rules.has("key-stored-with-ciphertext")).toBe(true);
    expect(rules.has("crypto-libs-must-be-pinned")).toBe(true);
    expect(shouldFail(res)).toBe(true);
  });

  it("passes a clean repo with pinned crypto libs", () => {
    const res = runCryptoPolicyChecks(goodRoot);
    expect(res.summary.high).toBe(0);
    expect(res.summary.critical).toBe(0);
    expect(shouldFail(res)).toBe(false);
  });

  it("every finding carries a user-safety impact", () => {
    const res = runCryptoPolicyChecks(badRoot);
    for (const f of res.findings) {
      expect(f.userSafetyImpact.length).toBeGreaterThan(0);
    }
  });
});
