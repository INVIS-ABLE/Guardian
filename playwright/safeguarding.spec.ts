import { test, expect } from "@playwright/test";

/**
 * Guardian safeguarding user-journeys.
 *
 * These journeys assert that protective controls for vulnerable users hold on OWNED
 * staging, using SYNTHETIC test accounts only. They never access real user data, never
 * perform destructive actions, and run within the scope's rate limits.
 *
 * Credentials are provided via env vars (set from the test-account registry in CI):
 *   GUARDIAN_STAGING_URL, VULNERABLE_USER_USER, VULNERABLE_USER_PW,
 *   STANDARD_USER_USER, STANDARD_USER_PW, BANNED_USER_USER, BANNED_USER_PW
 */

const creds = {
  vulnerable: {
    user: process.env.VULNERABLE_USER_USER ?? "vulnerable_user_test",
    pw: process.env.VULNERABLE_USER_PW ?? "",
  },
  standard: {
    user: process.env.STANDARD_USER_USER ?? "standard_user_test",
    pw: process.env.STANDARD_USER_PW ?? "",
  },
  banned: {
    user: process.env.BANNED_USER_USER ?? "banned_user_test",
    pw: process.env.BANNED_USER_PW ?? "",
  },
};

async function login(page, user: string, pw: string) {
  await page.goto("/login");
  await page.getByLabel(/username|email/i).fill(user);
  await page.getByLabel(/password/i).fill(pw);
  await page.getByRole("button", { name: /sign in|log in/i }).click();
}

test.describe("Safeguarding: vulnerable user protections", () => {
  test.skip(!creds.vulnerable.pw, "synthetic vulnerable-user credential not provided");

  test("vulnerable user has protective privacy defaults", async ({ page }) => {
    await login(page, creds.vulnerable.user, creds.vulnerable.pw);
    await page.goto("/settings/privacy");
    // At-risk users must default to the most protective settings.
    await expect(page.getByLabel(/discoverable by others/i)).not.toBeChecked();
    await expect(page.getByLabel(/show online status/i)).not.toBeChecked();
    await expect(page.getByLabel(/allow direct messages from strangers/i)).not.toBeChecked();
  });

  test("a reporting/blocking path is reachable from a profile", async ({ page }) => {
    await login(page, creds.vulnerable.user, creds.vulnerable.pw);
    await page.goto("/u/standard_user_test");
    await expect(page.getByRole("button", { name: /report/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /block/i })).toBeVisible();
  });
});

test.describe("Safeguarding: ban enforcement", () => {
  test.skip(!creds.banned.pw, "synthetic banned-user credential not provided");

  test("a banned user cannot reach the app", async ({ page }) => {
    await login(page, creds.banned.user, creds.banned.pw);
    // Expect to be kept out — no access to the authenticated app shell.
    await expect(page).toHaveURL(/login|suspended|banned/i);
    await expect(page.getByText(/account.*(suspended|banned|restricted)/i)).toBeVisible();
  });
});

test.describe("Safeguarding: no cross-user PII exposure", () => {
  test.skip(!creds.standard.pw, "synthetic standard-user credential not provided");

  test("another user's sensitive fields are not exposed on their profile", async ({ page }) => {
    await login(page, creds.standard.user, creds.standard.pw);
    await page.goto("/u/vulnerable_user_test");
    // Sensitive/safeguarding fields must never render to another user.
    await expect(page.getByText(/date of birth/i)).toHaveCount(0);
    await expect(page.getByText(/health/i)).toHaveCount(0);
    await expect(page.getByText(/safeguarding/i)).toHaveCount(0);
    await expect(page.getByText(/@/)).toHaveCount(0); // no email address leaked
  });
});
