import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import LoginPage from "./page";

const pushMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

// The OIDC button drives NextAuth's Keycloak code flow.
const signInMock = vi.hoisted(() => vi.fn());
vi.mock("next-auth/react", () => ({
  signIn: signInMock,
}));

beforeEach(() => {
  pushMock.mockReset();
  signInMock.mockReset();
  localStorage.clear();
});

afterEach(cleanup);

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

  it("clicking Continue with Keycloak calls signIn('keycloak') with the dashboard callbackUrl", () => {
    render(React.createElement(LoginPage));
    fireEvent.click(
      screen.getByRole("button", { name: "Continue with Keycloak" })
    );
    expect(signInMock).toHaveBeenCalledTimes(1);
    expect(signInMock).toHaveBeenCalledWith("keycloak", {
      callbackUrl: "/dashboard",
    });
    // The OIDC flow does NOT mint a dev bearer token.
    expect(localStorage.getItem("redsim_token")).toBeNull();
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
    expect(signInMock).not.toHaveBeenCalled();
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
