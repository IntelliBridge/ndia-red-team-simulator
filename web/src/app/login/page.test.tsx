import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { cookieReaderFromHeader } from "@/server/trpc/context";

import LoginPage from "./page";

const pushMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

// The OIDC button drives Better Auth's Keycloak code flow.
const socialMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth-client", () => ({
  signIn: { social: socialMock },
}));

beforeEach(() => {
  pushMock.mockReset();
  socialMock.mockReset();
  socialMock.mockResolvedValue({ data: {}, error: null });
  localStorage.clear();
  clearDevTokenCookie();
});

afterEach(() => {
  cleanup();
  clearDevTokenCookie();
});

/** jsdom keeps one cookie jar per file, so a case has to clear its own. */
function clearDevTokenCookie() {
  document.cookie = "redsim_dev_token=; path=/; max-age=0";
}

describe("LoginPage", () => {
  it("renders the Sign in heading and email input with default value", () => {
    render(React.createElement(LoginPage));
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeTruthy();
    const input = screen.getByDisplayValue("admin@redsim.local");
    expect(input).toBeTruthy();
  });

  it("renders the Keycloak/OIDC sign-in button", () => {
    render(React.createElement(LoginPage));
    expect(
      screen.getByRole("button", { name: "Continue with Keycloak" })
    ).toBeTruthy();
  });

  it("clicking Continue with Keycloak starts the keycloak social sign-in for /dashboard", () => {
    render(React.createElement(LoginPage));
    fireEvent.click(
      screen.getByRole("button", { name: "Continue with Keycloak" })
    );
    expect(socialMock).toHaveBeenCalledTimes(1);
    expect(socialMock).toHaveBeenCalledWith({
      provider: "keycloak",
      callbackURL: "/dashboard",
    });
    // The OIDC flow does NOT mint a dev bearer token.
    expect(localStorage.getItem("redsim_token")).toBeNull();
  });

  it("re-enables the Keycloak button when sign-in comes back with an error", async () => {
    socialMock.mockResolvedValue({ data: null, error: { message: "nope" } });
    render(React.createElement(LoginPage));
    const button = screen.getByRole("button", {
      name: "Continue with Keycloak",
    });
    fireEvent.click(button);
    await waitFor(() =>
      expect((button as HTMLButtonElement).disabled).toBe(false),
    );
  });

  it("the Keycloak button becomes disabled after being clicked (busy state)", () => {
    render(React.createElement(LoginPage));
    const button = screen.getByRole("button", {
      name: "Continue with Keycloak",
    });
    expect((button as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(button);
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it("updating the email input changes its displayed value", () => {
    render(React.createElement(LoginPage));
    const input = screen.getByDisplayValue("admin@redsim.local");
    fireEvent.change(input, { target: { value: "other@redsim.local" } });
    expect(screen.getByDisplayValue("other@redsim.local")).toBeTruthy();
  });

  it("clicking Continue writes both localStorage keys and navigates to /dashboard with default email", () => {
    render(React.createElement(LoginPage));
    const button = screen.getByRole("button", { name: "Continue as dev admin" });
    fireEvent.click(button);
    expect(localStorage.getItem("redsim_token")).toBe("dev:admin@redsim.local");
    expect(localStorage.getItem("redsim_email")).toBe("admin@redsim.local");
    expect(pushMock).toHaveBeenCalledWith("/dashboard");
    expect(pushMock).toHaveBeenCalledTimes(1);
    // The dev path does NOT trigger the OIDC flow.
    expect(socialMock).not.toHaveBeenCalled();
  });

  it("writes the dev-token cookie the tRPC context reads", () => {
    // localStorage reaches the old fetch client only. The tRPC layer runs on
    // the server and sees cookies, so the dev bearer has to travel as one or
    // every procedure call answers 401 and the gate bounces back to /login.
    // Read back through the server's own parser, so an encoding that parser
    // cannot decode fails here rather than in a browser.
    render(React.createElement(LoginPage));
    fireEvent.click(screen.getByRole("button", { name: "Continue as dev admin" }));

    const cookie = cookieReaderFromHeader(document.cookie);
    expect(cookie("redsim_dev_token")).toBe("dev:admin@redsim.local");
  });

  it("percent-encodes the cookie so the colon and the at sign survive the round trip", () => {
    render(React.createElement(LoginPage));
    const input = screen.getByDisplayValue("admin@redsim.local");
    fireEvent.change(input, { target: { value: "tester@redsim.local" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue as dev admin" }));

    // The raw jar holds the encoded form, and the reader decodes it. Both
    // halves matter: an unencoded value would split on the colon.
    expect(document.cookie).toContain("redsim_dev_token=dev%3Atester%40redsim.local");
    expect(cookieReaderFromHeader(document.cookie)("redsim_dev_token")).toBe(
      "dev:tester@redsim.local",
    );
  });

  it("clicking Continue uses the updated email when the input was edited", () => {
    render(React.createElement(LoginPage));
    const input = screen.getByDisplayValue("admin@redsim.local");
    fireEvent.change(input, { target: { value: "tester@redsim.local" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue as dev admin" }));
    expect(localStorage.getItem("redsim_token")).toBe("dev:tester@redsim.local");
    expect(localStorage.getItem("redsim_email")).toBe("tester@redsim.local");
    expect(pushMock).toHaveBeenCalledWith("/dashboard");
  });

  it("the Continue button becomes disabled after being clicked (busy state)", () => {
    render(React.createElement(LoginPage));
    const button = screen.getByRole("button", { name: "Continue as dev admin" });
    expect((button as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(button);
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});
