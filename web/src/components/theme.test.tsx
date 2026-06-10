import React from "react";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ThemeProvider, useTheme } from "./theme-provider";
import { ThemeToggle } from "./theme-toggle";

const h = React.createElement;

afterEach(cleanup);
beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
});

// A small probe that surfaces the resolved theme + a manual setter so tests
// can drive useTheme() without relying solely on the toggle button.
function Probe() {
  const { theme, mounted, setTheme, toggleTheme } = useTheme();
  return h(
    "div",
    null,
    h("span", { "data-testid": "theme" }, theme),
    h("span", { "data-testid": "mounted" }, String(mounted)),
    h(
      "button",
      { "data-testid": "to-dark", onClick: () => setTheme("dark") },
      "dark",
    ),
    h("button", { "data-testid": "toggle", onClick: toggleTheme }, "toggle"),
  );
}

describe("ThemeProvider / useTheme", () => {
  it("resolves and reports mounted after the client effect runs", () => {
    render(h(ThemeProvider, null, h(Probe)));
    expect(screen.getByTestId("mounted").textContent).toBe("true");
    // Default OS (jsdom) is light; no stored preference.
    expect(screen.getByTestId("theme").textContent).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("setTheme('dark') adds the dark class and persists to localStorage", () => {
    render(h(ThemeProvider, null, h(Probe)));
    act(() => {
      fireEvent.click(screen.getByTestId("to-dark"));
    });
    expect(screen.getByTestId("theme").textContent).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(window.localStorage.getItem("theme")).toBe("dark");
  });

  it("toggleTheme flips light <-> dark and keeps the class + storage in sync", () => {
    render(h(ThemeProvider, null, h(Probe)));
    act(() => {
      fireEvent.click(screen.getByTestId("toggle"));
    });
    expect(screen.getByTestId("theme").textContent).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(window.localStorage.getItem("theme")).toBe("dark");

    act(() => {
      fireEvent.click(screen.getByTestId("toggle"));
    });
    expect(screen.getByTestId("theme").textContent).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(window.localStorage.getItem("theme")).toBe("light");
  });

  it("reads an existing 'dark' preference from localStorage on mount", () => {
    window.localStorage.setItem("theme", "dark");
    render(h(ThemeProvider, null, h(Probe)));
    expect(screen.getByTestId("theme").textContent).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("useTheme throws when used outside a ThemeProvider", () => {
    // Silence the expected React error boundary console noise is unnecessary
    // here since render throws synchronously.
    expect(() => render(h(Probe))).toThrow(/within a <ThemeProvider>/);
  });
});

describe("ThemeToggle", () => {
  it("renders an active toggle button that flips the theme on click", () => {
    render(h(ThemeProvider, null, h(ThemeToggle)));
    // After mount the button is interactive (aria-label present).
    const btn = screen.getByRole("button", { name: /dark mode/i });
    act(() => {
      fireEvent.click(btn);
    });
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(window.localStorage.getItem("theme")).toBe("dark");
    // Label flips to offer switching back to light.
    expect(
      screen.getByRole("button", { name: /light mode/i }),
    ).toBeTruthy();
  });
});
