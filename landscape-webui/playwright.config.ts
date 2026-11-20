import { defineConfig } from "@playwright/test";

const baseURL = "https://127.0.0.1:4173";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.e2e.ts",
  use: {
    baseURL,
    browserName: "chromium",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  webServer: {
    command:
      "vite build && vite preview --host 127.0.0.1 --port 4173 --strictPort",
    url: baseURL,
    ignoreHTTPSErrors: true,
    timeout: 120_000,
  },
});
