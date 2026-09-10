import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import Home from "./page";

const replaceMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
}));

function clearCookies(): void {
  for (const c of document.cookie.split(";")) {
    const name = c.split("=")[0]?.trim();
    if (name) document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }
}

beforeEach(() => {
  replaceMock.mockReset();
  clearCookies();
});

afterEach(cleanup);

describe("Home (root page)", () => {
  it("redirects to /dashboard when the browser holds a session", async () => {
    document.cookie = "redsim_csrf=csrf-value";
    render(React.createElement(Home));
    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/dashboard");
    });
    expect(replaceMock).not.toHaveBeenCalledWith("/login");
  });

  it("redirects to /login when it holds none", async () => {
    render(React.createElement(Home));
    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/login");
    });
    expect(replaceMock).not.toHaveBeenCalledWith("/dashboard");
  });

  it("renders the Redsim heading while the redirect effect fires", () => {
    render(React.createElement(Home));
    expect(screen.getByRole("heading", { name: "Redsim" })).toBeTruthy();
  });

  it("renders a loading paragraph", () => {
    render(React.createElement(Home));
    expect(screen.getByText("Loading…")).toBeTruthy();
  });
});
