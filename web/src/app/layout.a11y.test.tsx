import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";

// CommandPalette (mounted in the layout) calls useRouter(); stub it so the
// shell renders outside a Next app-router context.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/dashboard",
}));

import RootLayout from "./layout";

afterEach(cleanup);

function renderLayout() {
  return render(
    React.createElement(
      RootLayout,
      null,
      React.createElement("h1", null, "Page heading"),
    ),
  );
}

describe("RootLayout a11y", () => {
  it("renders a skip link that targets the main landmark", () => {
    renderLayout();
    const skip = screen.getByText("Skip to content", { selector: "a" });
    expect(skip.getAttribute("href")).toBe("#main-content");

    const main = document.querySelector("main");
    expect(main?.getAttribute("id")).toBe("main-content");
  });

  it("the app shell has no axe violations", async () => {
    const { container } = renderLayout();
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });

  it("keeps the skip link first in the tab order once the fixture ribbon paints", async () => {
    const saved = process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "1";
    vi.resetModules();
    try {
      const { default: Layout } = (await import("./layout")) as {
        default: typeof RootLayout;
      };
      const { container } = render(
        React.createElement(Layout, null, React.createElement("h1", null, "Page heading")),
      );

      // The ribbon is not focusable, so it must not come between the top of
      // the document and the skip link a keyboard user reaches first.
      const focusable = Array.from(container.querySelectorAll("a[href], button"));
      expect(focusable[0]?.textContent).toBe("Skip to content");

      const results = await axe(container);
      expect(results.violations).toEqual([]);
    } finally {
      if (saved === undefined) delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
      else process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = saved;
      vi.resetModules();
    }
  });
});
