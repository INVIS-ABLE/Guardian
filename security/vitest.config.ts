import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["crypto/__tests__/**/*.test.ts"],
    testTimeout: 20000, // Argon2id MODERATE limits can be slow
    hookTimeout: 20000,
  },
});
