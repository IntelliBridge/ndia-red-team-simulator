import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 120000,
  retries: 0,
  use: {
    headless: true,
    baseURL: process.env.AEGIS_WEB_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
  },
});
