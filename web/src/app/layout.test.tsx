import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

// The shell calls useRouter() (CommandPalette, TopBar) and usePathname()
// (AppShell, SidebarNav); provide stubs so the layout renders outside a Next
// app-router context. usePathname returns a real route rather than "/login",
// which the shell deliberately renders without its chrome.
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

/** The primary nav, in the order spec section 18.1 fixes. */
const NAV_IN_SPEC_ORDER: [string, string][] = [
  ["Dashboard", "/dashboard"],
  ["Runs", "/runs"],
  ["Models", "/models"],
  ["Findings", "/findings"],
  ["Projects", "/projects"],
  ["Audit", "/audit"],
  ["Logs", "/logs"],
  ["Cost", "/cost"],
  ["Auth Profiles", "/auth-profiles"],
];

describe("RootLayout", () => {
  it("renders the core nav links with the correct hrefs", () => {
    renderLayout();
    for (const [label, href] of NAV_IN_SPEC_ORDER) {
      const link = screen.getByText(label, { selector: "a" });
      expect(link.getAttribute("href")).toBe(href);
    }
  });

  it("renders exactly the pruned nav, in spec order, with no Agents / Kali tools links", () => {
    renderLayout();

    // Scoped to the primary landmark rather than to `header nav`: the nav
    // moved into the sidebar with the design port, and the assertion that
    // matters is the list and its order, not which element wraps it.
    const nav = screen.getByRole("navigation", { name: "Primary" });
    const navLinks = Array.from(nav.querySelectorAll("a")).map((a) => [
      a.textContent,
      a.getAttribute("href"),
    ]);
    expect(navLinks).toEqual(NAV_IN_SPEC_ORDER);

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
    const { container } = renderLayout();
    const body = container.querySelector("body");
    expect(body?.className).toContain("bg-background");
    expect(body?.className).toContain("text-foreground");
    // The sidebar carries the ported surface tokens.
    const aside = container.querySelector("aside");
    expect(aside?.className).toContain("bg-panel");
    expect(aside?.className).toContain("border-hairline");
  });

  it("ships one fixed theme, written into the markup", () => {
    const { container } = renderLayout();
    expect(container.querySelector("html")?.className).toContain("dark");
  });

  it("mounts nothing that could repaint the theme after hydration", () => {
    renderLayout();
    // The flash this guards against is a client effect resolving a theme and
    // rewriting the class the server already sent. There is no provider and
    // no toggle now, so the assertion is that nothing offers to switch.
    expect(screen.queryByRole("button", { name: /light mode/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /dark mode/i })).toBeNull();
    expect(document.documentElement.classList.contains("light")).toBe(false);
  });

  it("renders passed children inside the layout", () => {
    renderLayout();
    expect(screen.getByText("child-sentinel")).toBeTruthy();
  });

  it("renders the footer disclosure under every page", () => {
    renderLayout();
    const footer = document.querySelector("footer");
    expect(footer?.textContent).toMatch(/not a safety, readiness, or certification determination/i);
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
