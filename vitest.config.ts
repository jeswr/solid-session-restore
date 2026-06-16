import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Pure unit tests — no browser, no network, no ports. The IndexedDB /
    // localStorage / WebCrypto surfaces are exercised through faithful in-memory
    // doubles installed per-test (see test/*.test.ts), so the suite is fast and
    // parallel-safe and needs no jsdom/happy-dom env. WebCrypto (crypto.subtle)
    // is available natively under Node's test runtime.
    include: ["test/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 20_000,
  },
});
