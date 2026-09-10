import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

let pathname = "/dashboard";
vi.mock("next/navigation", () => ({ usePathname: () => pathname }));

import { SiteFooter } from "./site-footer";

afterEach(cleanup);

describe("SiteFooter", () => {
  it("renders the disclaimer on an app page", () => {
    pathname = "/dashboard";
    render(React.createElement(SiteFooter));
    expect(screen.getByRole("contentinfo").textContent).toMatch(/not a safety, readiness, or certification determination/);
  });

  it("renders nothing on the login page", () => {
    pathname = "/login";
    const { container } = render(React.createElement(SiteFooter));
    expect(container.innerHTML).toBe("");
  });
});
