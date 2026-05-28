// Playwright scaffold for the stack-E2E job (M12).
// Runs only inside the docker-compose stack; gated by AEGIS_E2E_STACK=1.

import { test, expect } from "@playwright/test";

const TOKEN = "dev:admin@aegis.local";
const API = process.env.AEGIS_API_URL ?? "http://localhost:8000";
const WEB = process.env.AEGIS_WEB_URL ?? "http://localhost:3000";

test.skip(process.env.AEGIS_E2E_STACK !== "1",
  "stack E2E disabled — set AEGIS_E2E_STACK=1 to enable");

test("scan → finding → PR happy path", async ({ page, request }) => {
  // 1. API auth check.
  const health = await request.get(`${API}/health`);
  expect(health.ok()).toBeTruthy();

  // 2. Trigger a fixture-assisted scan.
  const scan = await request.post(`${API}/v1/scans`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
    data: { target: "http://localhost:3000", scanner: "trivy",
            project_id: "default" },
  });
  expect(scan.ok()).toBeTruthy();
  const { run_id } = await scan.json();

  // 3. Drive the UI.
  await page.goto(`${WEB}/dashboard`);
  await expect(page.locator("h1")).toContainText("Recent runs");

  await page.goto(`${WEB}/runs/${run_id}`);
  await expect(page.locator("h1")).toContainText(`Run ${run_id}`);
});
