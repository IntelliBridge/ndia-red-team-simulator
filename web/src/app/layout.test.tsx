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
      Targets: "/targets",
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
      ["Runs", "/runs"],
      ["Projects", "/projects"],
      ["Targets", "/targets"],
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

    const targetsLink = screen.getByText("Targets", { selector: "a" });
    expect(targetsLink.getAttribute("href")).toBe("/targets");

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

  it("exported metadata has a truthy description", () => {
    expect(metadata.description).toBeTruthy();
    expect(metadata.description).toBe("Adversarial ML Red-Team Simulator");
  });
});
