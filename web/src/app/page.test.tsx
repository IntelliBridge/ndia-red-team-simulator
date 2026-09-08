import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import Home from "./page";

const replaceMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
}));

beforeEach(() => {
  replaceMock.mockReset();
  localStorage.clear();
});

afterEach(cleanup);

describe("Home (root page)", () => {
  it("redirects to /dashboard when a token is present in localStorage", async () => {
    localStorage.setItem("redsim_token", "dev:admin@redsim.local");
    render(React.createElement(Home));
    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/dashboard");
    });
    expect(replaceMock).not.toHaveBeenCalledWith("/login");
  });

  it("redirects to /login when no token is in localStorage", async () => {
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
