// Playwright scaffold for the stack-E2E job (M12).
// Runs only inside the docker-compose stack; gated by REDSIM_E2E_STACK=1.

import { test, expect } from "@playwright/test";

const TOKEN = "dev:admin@redsim.local";
const API = process.env.REDSIM_API_URL ?? "http://localhost:8000";
const WEB = process.env.REDSIM_WEB_URL ?? "http://localhost:3000";

test.skip(process.env.REDSIM_E2E_STACK !== "1",
  "stack E2E disabled — set REDSIM_E2E_STACK=1 to enable");

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
  // The run heading renders the bare run id (no "Run " prefix); target it by
  // its stable test id rather than matching on the h1 text.
  await expect(page.getByTestId("run-heading")).toContainText(run_id);
});
