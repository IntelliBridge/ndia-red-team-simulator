"use client";

// ThemeToggle — a button that flips between light and dark mode.
//
// Reads/writes via useTheme() from ./theme-provider, so it must be
// rendered inside a <ThemeProvider>. Uses inline sun/moon SVGs (no icon
// dependency). Mount-gated: until the provider resolves the real theme it
// renders an inert placeholder of identical size to avoid hydration
// mismatch and layout shift.

import * as React from "react";
import { useTheme } from "./theme-provider";

function SunIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </svg>
  );
}

function MoonIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </svg>
  );
}

export type ThemeToggleProps = React.ComponentProps<"button">;

export function ThemeToggle({ className, ...props }: ThemeToggleProps) {
  const { theme, mounted, toggleTheme } = useTheme();

  const base =
    "inline-flex size-9 items-center justify-center rounded-md border border-border bg-background text-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

  // Render an inert, identically-sized placeholder until the client
  // resolves the theme — prevents hydration mismatch and layout shift.
  if (!mounted) {
    return (
      <button
        type="button"
        className={[base, className].filter(Boolean).join(" ")}
        aria-hidden="true"
        tabIndex={-1}
        disabled
        {...props}
      >
        <span className="size-4" />
      </button>
    );
  }

  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className={[base, className].filter(Boolean).join(" ")}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      title={isDark ? "Switch to light mode" : "Switch to dark mode"}
      {...props}
    >
      {isDark ? (
        <SunIcon className="size-4" />
      ) : (
        <MoonIcon className="size-4" />
      )}
    </button>
  );
}
