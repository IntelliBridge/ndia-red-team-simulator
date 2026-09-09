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

// The branded form posts to /api/auth/login, which runs the Keycloak password
// grant server-side. The page only ever sees the status and the reason.
const fetchMock = vi.fn();

beforeEach(() => {
  pushMock.mockReset();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  localStorage.clear();
  clearDevTokenCookie();
});

afterEach(() => {
  cleanup();
  clearDevTokenCookie();
  vi.unstubAllGlobals();
});

/** Fill the organization form and submit it. */
function submitCredentials(username: string, password: string) {
  fireEvent.change(screen.getByLabelText("Username or email"), {
    target: { value: username },
  });
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: password },
  });
  fireEvent.submit(screen.getByRole("form", { name: "Organization account sign in" }));
}

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

  it("posts the credentials to /api/auth/login and lands on the dashboard", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ ok: true, email: "admin@redsim.local" }), { status: 200 }),
    );
    localStorage.setItem("redsim_token", "dev:stale@redsim.local");
    render(React.createElement(LoginPage));

    submitCredentials("admin", "correct horse");

    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/dashboard"));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/auth/login");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ username: "admin", password: "correct horse" });
    // A stale dev bearer would win over the fresh cookie pair in api().
    expect(localStorage.getItem("redsim_token")).toBeNull();
    expect(localStorage.getItem("redsim_email")).toBe("admin@redsim.local");
  });

  it("shows the refusal and re-enables the form on a 401", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_credentials" }), { status: 401 }),
    );
    render(React.createElement(LoginPage));

    submitCredentials("admin", "wrong");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Incorrect username or password.");
    expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(
      false,
    );
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("explains a missing session key distinctly from a bad password", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: "mint_failed" }), { status: 500 }),
    );
    render(React.createElement(LoginPage));

    submitCredentials("admin", "correct horse");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("no API session key");
  });

  it("tells a bounced user their session ended", () => {
    render(React.createElement(LoginPage, { searchParams: { reason: "rejected" } }));
    expect(screen.getByRole("status").textContent).toContain("Your session ended");
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
    // The dev path never reaches the sign-in route.
    expect(fetchMock).not.toHaveBeenCalled();
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
