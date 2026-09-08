"use client";

// ThemeProvider / useTheme — the dark-mode foundation for the redsim web app.
//
// Mount <ThemeProvider> high in the tree (e.g. inside <body> in
// app/layout.tsx). On mount it reads localStorage["theme"] (falling back
// to the OS `prefers-color-scheme`) and toggles `class="dark"` on
// <html> (document.documentElement) to drive Tailwind's `darkMode: "class"`.
//
// SSR safety: the resolved theme is only known on the client, so the
// provider mount-gates — it renders children immediately (no layout
// shift / no blank flash) but only exposes the *resolved* theme after
// mount. Combined with `suppressHydrationWarning` on <html>, this avoids
// hydration mismatches. For a zero-FOUC experience a sync inline script
// can also be added to <head>; that is the layout owner's call.

import * as React from "react";

export type Theme = "light" | "dark";

const STORAGE_KEY = "theme";

export interface ThemeContextValue {
  /** The active theme. Before mount this reports "light" (SSR default). */
  theme: Theme;
  /** Whether the provider has mounted and resolved the real theme. */
  mounted: boolean;
  /** Set an explicit theme; persists to localStorage. */
  setTheme: (theme: Theme) => void;
  /** Flip between light and dark; persists to localStorage. */
  toggleTheme: () => void;
}

const ThemeContext = React.createContext<ThemeContextValue | null>(null);

function applyThemeClass(theme: Theme) {
  const root = document.documentElement;
  if (theme === "dark") {
    root.classList.add("dark");
  } else {
    root.classList.remove("dark");
  }
}

function readInitialTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") {
      return stored;
    }
  } catch {
    // localStorage may be unavailable (private mode, SSR); ignore.
  }
  if (
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  ) {
    return "dark";
  }
  return "light";
}

export interface ThemeProviderProps {
  children: React.ReactNode;
  /** Theme used for the initial SSR render before the client resolves. */
  defaultTheme?: Theme;
}

export function ThemeProvider({
  children,
  defaultTheme = "light",
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<Theme>(defaultTheme);
  const [mounted, setMounted] = React.useState(false);

  // Resolve + apply the real theme once on the client.
  React.useEffect(() => {
    const initial = readInitialTheme();
    setThemeState(initial);
    applyThemeClass(initial);
    setMounted(true);
  }, []);

  const setTheme = React.useCallback((next: Theme) => {
    setThemeState(next);
    applyThemeClass(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore persistence failures
    }
  }, []);

  const toggleTheme = React.useCallback(() => {
    setThemeState((prev) => {
      const next: Theme = prev === "dark" ? "light" : "dark";
      applyThemeClass(next);
      try {
        window.localStorage.setItem(STORAGE_KEY, next);
      } catch {
        // ignore persistence failures
      }
      return next;
    });
  }, []);

  const value = React.useMemo<ThemeContextValue>(
    () => ({ theme, mounted, setTheme, toggleTheme }),
    [theme, mounted, setTheme, toggleTheme],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = React.useContext(ThemeContext);
  if (ctx === null) {
    throw new Error("useTheme must be used within a <ThemeProvider>");
  }
  return ctx;
}
