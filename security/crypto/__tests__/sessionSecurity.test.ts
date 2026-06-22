import { describe, it, expect } from "vitest";
import {
  serializeSessionCookie,
  clearSessionCookie,
  generateSessionId,
  auditCookieConfig,
  DEFAULT_SESSION_COOKIE_NAME,
} from "../sessionSecurity.js";

describe("sessionSecurity (hardened cookies)", () => {
  it("emits HttpOnly, Secure, SameSite and __Host- bound cookie", () => {
    const c = serializeSessionCookie("sid-value");
    expect(c).toContain(DEFAULT_SESSION_COOKIE_NAME);
    expect(c).toMatch(/HttpOnly/i);
    expect(c).toMatch(/Secure/i);
    expect(c).toMatch(/SameSite=Strict/i);
    expect(c).toMatch(/Path=\//i);
    expect(c).not.toMatch(/Domain=/i); // __Host- forbids Domain
  });

  it("refuses an insecure __Host- cookie", () => {
    expect(() => serializeSessionCookie("v", { insecureDevAllowed: true })).toThrow();
  });

  it("generates 256-bit opaque session ids", () => {
    const id = generateSessionId();
    expect(Buffer.from(id, "base64url").length).toBe(32);
    expect(generateSessionId()).not.toEqual(id);
  });

  it("clear cookie expires immediately", () => {
    const c = clearSessionCookie();
    expect(c).toMatch(/Max-Age=0/i);
  });

  it("auditCookieConfig flags insecure configs", () => {
    expect(auditCookieConfig({ httpOnly: false, secure: true })).toContain(
      "session cookie missing HttpOnly",
    );
    expect(auditCookieConfig({ httpOnly: true, secure: false })).toContain(
      "session cookie missing Secure",
    );
    expect(auditCookieConfig({ httpOnly: true, secure: true, sameSite: "none" }).length).toBe(1);
    expect(auditCookieConfig({ httpOnly: true, secure: true, sameSite: "strict" })).toEqual([]);
  });
});
