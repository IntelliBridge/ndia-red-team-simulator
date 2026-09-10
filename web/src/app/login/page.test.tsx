import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

import LoginPage from "./page";

const replaceMock = vi.fn();
let searchParams = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
  useSearchParams: () => searchParams,
}));

const signInMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth", () => ({ signInWithPassword: signInMock }));

beforeEach(() => {
  replaceMock.mockReset();
  signInMock.mockReset();
  searchParams = new URLSearchParams();
});

afterEach(cleanup);

function fill(email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
}

function submit() {
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("LoginPage", () => {
  it("renders an email field, a password field and one submit button, with no heading", () => {
    render(React.createElement(LoginPage));
    expect(screen.queryByRole("heading")).toBeNull();
    expect(screen.getByRole("form", { name: "Sign in" })).toBeTruthy();
    const email = screen.getByLabelText("Email") as HTMLInputElement;
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    expect(email.type).toBe("email");
    expect(email.autocomplete).toBe("username");
    expect(email.value).toBe("");
    expect(password.type).toBe("password");
    expect(password.autocomplete).toBe("current-password");
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  });

  it("paints the hero as a decorative layer hidden from assistive technology", () => {
    render(React.createElement(LoginPage));
    const hero = screen.getByTestId("login-hero");
    expect(hero.getAttribute("aria-hidden")).toBe("true");
    expect(hero.className).toContain("redsim-login-hero");
    expect(hero.textContent).toBe("");
  });

  it("offers no other way in and never names the identity provider", () => {
    const { container } = render(React.createElement(LoginPage));
    expect(screen.queryByText(/dev/i)).toBeNull();
    expect(screen.getAllByRole("button")).toHaveLength(2);
    expect(container.textContent?.toLowerCase()).not.toMatch(/keycloak|oidc|oauth/);
    expect(container.querySelectorAll("input")).toHaveLength(2);
  });

  it("submits the trimmed email and the password, then replaces to the dashboard", async () => {
    signInMock.mockResolvedValue({ ok: true });
    render(React.createElement(LoginPage));
    fill("  alice@redsim.local ", "correct horse");
    submit();

    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/dashboard"));
    expect(signInMock).toHaveBeenCalledWith("alice@redsim.local", "correct horse");
  });

  it("returns to the same-origin next path and ignores a foreign one", async () => {
    signInMock.mockResolvedValue({ ok: true });
    searchParams = new URLSearchParams({ next: "/runs/abc?tab=curve" });
    render(React.createElement(LoginPage));
    fill("a@b.c", "pw");
    submit();
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/runs/abc?tab=curve"));
    cleanup();

    replaceMock.mockReset();
    searchParams = new URLSearchParams({ next: "https://evil.test/" });
    render(React.createElement(LoginPage));
    fill("a@b.c", "pw");
    submit();
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/dashboard"));
  });

  it("shows the refusal as an alert, clears the password and keeps the email", async () => {
    signInMock.mockResolvedValue({ ok: false, code: "invalid_credentials" });
    render(React.createElement(LoginPage));
    fill("alice@redsim.local", "wrong");
    submit();

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/did not match/i);
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("Email") as HTMLInputElement).value).toBe("alice@redsim.local");
    expect(screen.getByLabelText("Email").getAttribute("aria-invalid")).toBe("true");
    expect(replaceMock).not.toHaveBeenCalled();
    // The button is usable again for another attempt.
    expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("explains a locked account and an unavailable service in plain words", async () => {
    signInMock.mockResolvedValue({ ok: false, code: "account_locked" });
    render(React.createElement(LoginPage));
    fill("a@b.c", "pw");
    submit();
    expect((await screen.findByRole("alert")).textContent).toMatch(/locked/i);
    cleanup();

    signInMock.mockResolvedValue({ ok: false, code: "unavailable" });
    render(React.createElement(LoginPage));
    fill("a@b.c", "pw");
    submit();
    expect((await screen.findByRole("alert")).textContent).toMatch(/not available right now/i);
  });

  it("refuses an empty form locally without calling the route", async () => {
    render(React.createElement(LoginPage));
    submit();
    expect((await screen.findByRole("alert")).textContent).toMatch(/enter your email and password/i);
    expect(signInMock).not.toHaveBeenCalled();
  });

  it("disables the form while a sign-in is in flight and says so", async () => {
    let resolve: (value: { ok: true }) => void = () => {};
    signInMock.mockReturnValue(new Promise((r) => (resolve = r)));
    render(React.createElement(LoginPage));
    fill("a@b.c", "pw");
    submit();

    const busy = await screen.findByRole("button", { name: "Signing in…" });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByLabelText("Email") as HTMLInputElement).disabled).toBe(true);
    expect(signInMock).toHaveBeenCalledTimes(1);
    resolve({ ok: true });
    await waitFor(() => expect(replaceMock).toHaveBeenCalled());
  });

  it("toggles the password between hidden and shown", () => {
    render(React.createElement(LoginPage));
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    fireEvent.click(screen.getByRole("button", { name: "Show" }));
    expect(password.type).toBe("text");
    fireEvent.click(screen.getByRole("button", { name: "Hide" }));
    expect(password.type).toBe("password");
  });

  it("explains why the browser landed here when the reason is known", () => {
    searchParams = new URLSearchParams({ reason: "rejected" });
    render(React.createElement(LoginPage));
    expect(screen.getByRole("status").textContent).toMatch(/session ended/i);
    cleanup();

    searchParams = new URLSearchParams({ reason: "nonsense" });
    render(React.createElement(LoginPage));
    expect(screen.queryByRole("status")).toBeNull();
  });
});
