import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// This workspace's vitest transforms via oxc and web/tsconfig.json sets
// `jsx: "preserve"`, so test files build elements with createElement.

let pathname = "/dashboard";
const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push: pushMock }),
}));

// SWR is the only reader of the me route. Driven per test rather than mocked
// at the fetch layer, so the assertions stay about what the menu renders.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const isAuthenticatedMock = vi.hoisted(() => vi.fn(() => true));
const logoutMock = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
vi.mock("@/lib/auth", () => ({
  isAuthenticated: isAuthenticatedMock,
  loginPath: () => "/login?next=%2Fdashboard",
  logout: logoutMock,
}));

import { initialsFor, UserMenu } from "./user-menu";

beforeEach(() => {
  pathname = "/dashboard";
  pushMock.mockReset();
  logoutMock.mockReset();
  logoutMock.mockResolvedValue(undefined);
  isAuthenticatedMock.mockReturnValue(true);
  useSWRMock.mockReturnValue({ data: { sub: "u-1", email: "analyst@example.test", name: "Ada Lovelace" } });
});

afterEach(cleanup);

describe("initialsFor", () => {
  it("takes the first and last initial of a display name", () => {
    expect(initialsFor({ name: "Ada Lovelace", email: "a@example.test" })).toBe("AL");
  });

  it("falls back to the email when there is no name", () => {
    expect(initialsFor({ name: "  ", email: "analyst@example.test" })).toBe("A");
  });

  it("is never empty", () => {
    expect(initialsFor({})).toBe("?");
  });
});

describe("UserMenu", () => {
  it("renders the avatar with the account's initials when signed in", () => {
    render(h(UserMenu));

    const button = screen.getByTestId("user-menu-button");
    expect(button.textContent).toBe("AL");
    expect(button.getAttribute("aria-label")).toBe("Account: Ada Lovelace");
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("opens the menu on click and shows the account and Sign out", () => {
    render(h(UserMenu));
    fireEvent.click(screen.getByTestId("user-menu-button"));

    const menu = screen.getByRole("menu");
    expect(menu.textContent).toContain("Ada Lovelace");
    expect(menu.textContent).toContain("analyst@example.test");
    expect(screen.getByRole("menuitem", { name: "Sign out" })).toBeTruthy();
  });

  it("signs out: calls logout() then routes to /login", async () => {
    render(h(UserMenu));
    fireEvent.click(screen.getByTestId("user-menu-button"));
    fireEvent.click(screen.getByRole("menuitem", { name: "Sign out" }));

    expect(logoutMock).toHaveBeenCalledTimes(1);
    // logout() clears the cookies before it resolves, so the redirect lands a
    // microtask later rather than on the click.
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/login"));
  });

  it("closes on Escape", () => {
    render(h(UserMenu));
    fireEvent.click(screen.getByTestId("user-menu-button"));
    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("offers Sign in, carrying the current route, when there is no session", () => {
    isAuthenticatedMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined });

    render(h(UserMenu));

    const link = screen.getByRole("link", { name: "Sign in" });
    expect(link.getAttribute("href")).toBe("/login?next=%2Fdashboard");
    expect(screen.queryByTestId("user-menu-button")).toBeNull();
  });

  it("renders nothing on the login page", () => {
    pathname = "/login";
    const { container } = render(h(UserMenu));

    expect(container.innerHTML).toBe("");
  });
});
