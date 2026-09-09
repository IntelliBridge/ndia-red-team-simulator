import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";

// CommandPalette and the top bar (mounted in the layout) call useRouter();
// provide a stub so the layout renders outside a Next app-router context.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/findings/abc",
}));

import RootLayout, { metadata } from "./layout";

afterEach(cleanup);

function renderLayout() {
  return render(
    React.createElement(
      RootLayout,
      null,
      React.createElement("div", null, "child-sentinel"),
    ),
  );
}

// The shell carries the six links twice: in the sidebar from the md
// breakpoint up, and in the compact header row below it. jsdom applies no
// stylesheet, so both are present and each is asserted on its own.
function sidebarNav(container: HTMLElement): HTMLElement {
  const nav = container.querySelector("aside nav");
  if (!(nav instanceof HTMLElement)) throw new Error("sidebar nav missing");
  return nav;
}

function linkPairs(root: ParentNode, selector: string): (string | null)[][] {
  return Array.from(root.querySelectorAll(selector)).map((a) => [
    a.textContent,
    a.getAttribute("href"),
  ]);
}

const PRUNED_NAV = [
  ["Dashboard", "/dashboard"],
  ["Models", "/models"],
  ["Runs", "/runs"],
  ["Tests", "/tests"],
  ["Findings", "/findings"],
  ["Audit", "/audit"],
];

describe("RootLayout", () => {
  it("renders the core nav links with the correct hrefs", () => {
    const { container } = renderLayout();
    const sidebar = within(sidebarNav(container));

    const expected: Record<string, string> = {
      Dashboard: "/dashboard",
      Findings: "/findings",
      Audit: "/audit",
    };
    for (const [label, href] of Object.entries(expected)) {
      const link = sidebar.getByText(label, { selector: "a" });
      expect(link.getAttribute("href")).toBe(href);
    }
  });

  it("renders exactly the pruned nav, in order, with no Agents / Kali tools links", () => {
    const { container } = renderLayout();

    // The sidebar and the compact header row read the same list, so both
    // carry the six links in the same order.
    expect(linkPairs(container, "aside nav a")).toEqual(PRUNED_NAV);
    expect(linkPairs(container, "header nav a")).toEqual(PRUNED_NAV);

    // Projects, Auth Profiles and Logs stay reachable at their paths but are
    // hidden from the nav (owner requests, 2026-09-09).
    for (const hidden of ["Projects", "Auth Profiles", "Logs", "Cost"]) {
      expect(screen.queryAllByText(hidden, { selector: "a" })).toEqual([]);
    }
    expect(screen.queryAllByText("Agents", { selector: "a" })).toEqual([]);
    expect(screen.queryAllByText("Kali tools", { selector: "a" })).toEqual([]);
  });

  it("brands the shell with the Agile Defense Labs mark linking home", () => {
    const { container } = renderLayout();

    // In the sidebar head from md up, and in the header below md, where the
    // sidebar is not rendered.
    for (const selector of [
      'aside a[data-testid="brand-link"]',
      'header a[data-testid="brand-link-compact"]',
    ]) {
      const brand = container.querySelector(selector);
      expect(brand?.getAttribute("href")).toBe("/dashboard");
      const logo = brand?.querySelector("img");
      expect(logo?.getAttribute("src")).toBe("/brand/agile-labs.svg");
      expect(logo?.getAttribute("alt")).toBe("Agile Defense Labs");
    }
  });

  it("is dark only: the html root carries the dark class and the shell has no theme toggle", () => {
    const { container } = renderLayout();
    expect(container.querySelector("html")?.className).toContain("dark");
    expect(container.querySelector("header nav button")).toBeNull();
    expect(container.querySelector("aside button")).toBeNull();
    expect(screen.queryByLabelText("Toggle theme")).toBeNull();
  });

  it("marks the nav link of the current route section with aria-current", () => {
    const { container } = renderLayout();
    for (const selector of ["aside nav a", "header nav a"]) {
      const current = Array.from(container.querySelectorAll(selector)).filter(
        (a) => a.getAttribute("aria-current") === "page",
      );
      expect(current.map((a) => a.textContent)).toEqual(["Findings"]);
    }
  });

  it("themes the shell with semantic token classes", () => {
    const { container } = renderLayout();
    const body = container.querySelector("body");
    // The ground is painted by the root element in globals.css, not by body:
    // a body fill would cover the login page's fixed hero layer.
    expect(body?.className).not.toContain("bg-background");
    expect(body?.className).toContain("text-foreground");
    const header = container.querySelector("header");
    expect(header?.className).toContain("border-border");
    const aside = container.querySelector("aside");
    expect(aside?.className).toContain("border-border");
  });

  it("renders the Dashboard and Audit nav links with the correct hrefs", () => {
    const { container } = renderLayout();
    const sidebar = within(sidebarNav(container));

    const dashboardLink = sidebar.getByText("Dashboard", { selector: "a" });
    expect(dashboardLink.getAttribute("href")).toBe("/dashboard");

    const auditLink = sidebar.getByText("Audit", { selector: "a" });
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
      // Inside the banner landmark and first within it.
      expect(ribbon.closest("header")).not.toBeNull();
      expect(ribbon.closest("header")?.firstElementChild).toBe(ribbon);
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
