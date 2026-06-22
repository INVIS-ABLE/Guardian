import { defineConfig, devices } from "@playwright/test";

/**
 * Guardian Playwright config.
 *
 * Safety: baseURL is the OWNED staging domain only. Credentials come from env vars
 * for SYNTHETIC test accounts (never real users). Tests are read-mostly and never
 * perform destructive actions.
 */
export default defineConfig({
  testDir: ".",
  fullyParallel: false, // keep load controlled / within scope rate limits
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 2,
  reporter: [
    ["list"],
    ["html", { outputFolder: "../reports/generated/playwright-report", open: "never" }],
  ],
  use: {
    baseURL: process.env.GUARDIAN_STAGING_URL ?? "https://staging.invisable.co.uk",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    actionTimeout: 15000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
