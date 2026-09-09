import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

// CommandPalette (mounted in the layout) calls useRouter(); provide a stub so
// the layout renders outside a Next app-router context.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
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
      Projects: "/projects",
      Findings: "/findings",
      Logs: "/logs",
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
      ["Projects", "/projects"],
      ["Auth Profiles", "/auth-profiles"],
      ["Findings", "/findings"],
      ["Logs", "/logs"],
      ["Audit", "/audit"],
      ["Cost", "/cost"],
    ]);

    expect(screen.queryByText("Agents", { selector: "a" })).toBeNull();
    expect(screen.queryByText("Kali tools", { selector: "a" })).toBeNull();
  });

  it("mounts the theme toggle button in the header", () => {
    const { container } = render(
      React.createElement(
        RootLayout,
        null,
        React.createElement("div", null, "child-sentinel"),
      ),
    );
    // The mount-gated ThemeToggle renders a <button> (an inert placeholder
    // until the provider resolves on the client). Either way a button exists
    // inside the header nav.
    const navButton = container.querySelector("header nav button");
    expect(navButton).not.toBeNull();
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

  it("renders the Cost and Auth Profiles nav links with the correct hrefs", () => {
    renderLayout();

    const dashboardLink = screen.getByText("Dashboard", { selector: "a" });
    expect(dashboardLink.getAttribute("href")).toBe("/dashboard");

    const projectsLink = screen.getByText("Projects", { selector: "a" });
    expect(projectsLink.getAttribute("href")).toBe("/projects");

    const costLink = screen.getByText("Cost", { selector: "a" });
    expect(costLink.getAttribute("href")).toBe("/cost");

    const authProfilesLink = screen.getByText("Auth Profiles", { selector: "a" });
    expect(authProfilesLink.getAttribute("href")).toBe("/auth-profiles");

    const logsLink = screen.getByText("Logs", { selector: "a" });
    expect(logsLink.getAttribute("href")).toBe("/logs");

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
