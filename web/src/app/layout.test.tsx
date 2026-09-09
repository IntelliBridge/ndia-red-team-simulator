import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

// CommandPalette (mounted in the layout) calls useRouter(); provide a stub so
// the layout renders outside a Next app-router context.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/findings/abc",
}));

import RootLayout, { metadata } from "./layout";

afterEach(cleanup);

function renderLayout() {
  render(
    React.createElement(
      RootLayout,
      null,
      React.createElement("div", null, "child-sentinel"),
    ),
  );
}

describe("RootLayout", () => {
  it("renders the core nav links with the correct hrefs", () => {
    renderLayout();

    const expected: Record<string, string> = {
      Dashboard: "/dashboard",
      Findings: "/findings",
      Audit: "/audit",
    };
    for (const [label, href] of Object.entries(expected)) {
      const link = screen.getByText(label, { selector: "a" });
      expect(link.getAttribute("href")).toBe(href);
    }
  });

  it("renders exactly the pruned nav, in order, with no Agents / Kali tools links", () => {
    const { container } = render(
      React.createElement(
        RootLayout,
        null,
        React.createElement("div", null, "child-sentinel"),
      ),
    );

    const navLinks = Array.from(
      container.querySelectorAll("header nav a"),
    ).map((a) => [a.textContent, a.getAttribute("href")]);
    expect(navLinks).toEqual([
      ["Dashboard", "/dashboard"],
      ["Models", "/models"],
      ["Runs", "/runs"],
      ["Tests", "/tests"],
      ["Findings", "/findings"],
      ["Audit", "/audit"],
    ]);

    // Projects, Auth Profiles and Logs stay reachable at their paths but are
    // hidden from the nav (owner requests, 2026-09-09).
    for (const hidden of ["Projects", "Auth Profiles", "Logs", "Cost"]) {
      expect(screen.queryByText(hidden, { selector: "a" })).toBeNull();
    }
    expect(screen.queryByText("Projects", { selector: "a" })).toBeNull();
    expect(screen.queryByText("Agents", { selector: "a" })).toBeNull();
    expect(screen.queryByText("Kali tools", { selector: "a" })).toBeNull();
  });

  it("brands the header with the Agile Defense Labs mark linking home", () => {
    const { container } = render(
      React.createElement(
        RootLayout,
        null,
        React.createElement("div", null, "child-sentinel"),
      ),
    );
    const brand = container.querySelector('header a[data-testid="brand-link"]');
    expect(brand?.getAttribute("href")).toBe("/dashboard");
    const logo = brand?.querySelector("img");
    expect(logo?.getAttribute("src")).toBe("/brand/agile-labs.svg");
    expect(logo?.getAttribute("alt")).toBe("Agile Defense Labs");
  });

  it("is dark only: the html root carries the dark class and the header has no theme toggle", () => {
    const { container } = render(
      React.createElement(
        RootLayout,
        null,
        React.createElement("div", null, "child-sentinel"),
      ),
    );
    expect(container.querySelector("html")?.className).toContain("dark");
    expect(container.querySelector("header nav button")).toBeNull();
  });

  it("marks the nav link of the current route section with aria-current", () => {
    const { container } = render(
      React.createElement(
        RootLayout,
        null,
        React.createElement("div", null, "child-sentinel"),
      ),
    );
    const current = Array.from(container.querySelectorAll("header nav a")).filter(
      (a) => a.getAttribute("aria-current") === "page",
    );
    expect(current.map((a) => a.textContent)).toEqual(["Findings"]);
  });

  it("themes the shell with semantic token classes", () => {
    const { container } = render(
      React.createElement(
        RootLayout,
        null,
        React.createElement("div", null, "child-sentinel"),
      ),
    );
    const body = container.querySelector("body");
    expect(body?.className).toContain("bg-background");
    expect(body?.className).toContain("text-foreground");
    const header = container.querySelector("header");
    expect(header?.className).toContain("border-border");
  });

  it("renders the Dashboard and Audit nav links with the correct hrefs", () => {
    renderLayout();

    const dashboardLink = screen.getByText("Dashboard", { selector: "a" });
    expect(dashboardLink.getAttribute("href")).toBe("/dashboard");

    const auditLink = screen.getByText("Audit", { selector: "a" });
    expect(auditLink.getAttribute("href")).toBe("/audit");
  });

  it("renders passed children inside the layout", () => {
    renderLayout();
    expect(screen.getByText("child-sentinel")).toBeTruthy();
  });

  it("exported metadata has a truthy title equal to the defined string", () => {
    expect(metadata.title).toBeTruthy();
    expect(metadata.title).toBe("redsim");
  });

  it("paints no fixture ribbon when the fixture flag is off", () => {
    renderLayout();
    expect(screen.queryByTestId("fixture-ribbon")).toBeNull();
  });

  it("paints the fixture ribbon when the build carries the fixture flag", async () => {
    // The env module validates once per module graph, so the flag has to be
    // set before the layout and its env import are evaluated afresh.
    //
    // The public flag is the right authority here even though the server flag
    // is what actually serves fixtures. A server component cannot read a
    // server variable in jsdom, and the env refinement makes the direction
    // that matters airtight: fixtures served means REDSIM_DEV_FIXTURES is on,
    // which means the raw public flag is exactly "1", which means the ribbon
    // is painted. The reverse over-discloses, which is the safe side.
    const saved = process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "1";
    vi.resetModules();
    try {
      const { default: Layout } = (await import("./layout")) as {
        default: typeof RootLayout;
      };
      render(
        React.createElement(Layout, null, React.createElement("div", null, "child-sentinel")),
      );
      const ribbon = screen.getByTestId("fixture-ribbon");
      expect(ribbon.textContent).toMatch(/illustrative/i);
      expect(ribbon.textContent).toMatch(/not measurements/i);
    } finally {
      if (saved === undefined) delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
      else process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = saved;
      vi.resetModules();
    }
  });

  it("exported metadata has a truthy description", () => {
    expect(metadata.description).toBeTruthy();
    expect(metadata.description).toBe("Adversarial ML Red-Team Simulator");
  });
});
