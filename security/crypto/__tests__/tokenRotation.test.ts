import { describe, it, expect } from "vitest";
import {
  issueAccessToken,
  verifyAccessToken,
  requiresReauth,
  issueRefreshToken,
  rotateRefreshToken,
  InMemoryRefreshTokenStore,
  ReuseDetectedError,
} from "../tokenRotation.js";

const SECRET = "test-secret-test-secret-test-secret-32!"; // >= 32 bytes

describe("tokenRotation — access tokens", () => {
  it("issues and verifies a short-lived access token", async () => {
    const jwt = await issueAccessToken(
      { sub: "u-1", sid: "s-1", amr: ["pwd", "passkey"] },
      { secret: SECRET, ttlSeconds: 600 },
    );
    const payload = await verifyAccessToken(jwt, { secret: SECRET });
    expect(payload.sub).toBe("u-1");
    expect(payload.sid).toBe("s-1");
    expect(payload.amr).toEqual(["pwd", "passkey"]);
  });

  it("rejects a token signed with a different secret", async () => {
    const jwt = await issueAccessToken({ sub: "u", sid: "s" }, { secret: SECRET });
    await expect(verifyAccessToken(jwt, { secret: "another-secret-another-secret-32xx" })).rejects.toThrow();
  });

  it("requires reauth for stale auth_time", async () => {
    const old = Math.floor(Date.now() / 1000) - 3600;
    const jwt = await issueAccessToken({ sub: "u", sid: "s" }, { secret: SECRET, authTime: old });
    const payload = await verifyAccessToken(jwt, { secret: SECRET });
    expect(requiresReauth(payload, 300)).toBe(true); // older than 5 min
    expect(requiresReauth(payload, 7200)).toBe(false);
  });

  it("rejects too-short secrets", async () => {
    await expect(issueAccessToken({ sub: "u", sid: "s" }, { secret: "short" })).rejects.toThrow();
  });
});

describe("tokenRotation — refresh rotation + reuse detection", () => {
  it("rotates a refresh token, invalidating the old one", async () => {
    const store = new InMemoryRefreshTokenStore();
    const first = await issueRefreshToken(store, { userId: "u-1" });
    const rotated = await rotateRefreshToken(store, first.token);
    expect(rotated.token).not.toEqual(first.token);
    expect(rotated.userId).toBe("u-1");
    expect(rotated.familyId).toBe(first.familyId);
  });

  it("detects reuse of an already-rotated token and revokes the family", async () => {
    const store = new InMemoryRefreshTokenStore();
    const first = await issueRefreshToken(store, { userId: "u-1" });
    const second = await rotateRefreshToken(store, first.token);
    // Replaying the FIRST (already-rotated) token = theft signal.
    await expect(rotateRefreshToken(store, first.token)).rejects.toBeInstanceOf(ReuseDetectedError);
    // Family now revoked: even the legitimate latest token is refused.
    await expect(rotateRefreshToken(store, second.token)).rejects.toBeInstanceOf(ReuseDetectedError);
  });

  it("rejects unknown refresh tokens", async () => {
    const store = new InMemoryRefreshTokenStore();
    await expect(rotateRefreshToken(store, "not-a-real-token")).rejects.toThrow();
  });
});
