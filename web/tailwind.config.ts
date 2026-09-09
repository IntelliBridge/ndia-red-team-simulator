import type { Config } from "tailwindcss";

/**
 * A token name resolved through its CSS variable.
 *
 * `<alpha-value>` is what lets an opacity modifier such as `bg-panel/40`
 * keep working: Tailwind substitutes the channel it computed, and a bare
 * `hsl(var(--x))` would swallow it silently.
 */
const token = (name: string) => `hsl(var(--${name}) / <alpha-value>)`;

const config: Config = {
  // One dark theme (labs.agiledefense.com). `<html class="dark">` is set in
  // app/layout.tsx so the vendored shadcn primitives' `dark:` variants apply.
  darkMode: "class",
  content: [
    "./src/**/*.{ts,tsx}",
    "../packages/design-system/src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // The Labs pairing: Helvetica Neue for prose, JetBrains Mono for
        // labels. Both stacks are also exposed as --sans / --mono in
        // globals.css for CSS-only callers.
        sans: ['"Helvetica Neue"', "Helvetica", "Arial", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Courier New"', "monospace"],
      },
      colors: {
        // Semantic tokens backed by CSS variables defined in globals.css.
        // Utilities like `bg-background`, `text-foreground`, `border-border`,
        // `bg-card`, `text-muted-foreground` resolve through these.
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: token("primary"),
          foreground: token("primary-foreground"),
        },
        secondary: {
          DEFAULT: token("secondary"),
          foreground: token("secondary-foreground"),
        },
        // Amber-orange, not red: red is the brand accent and never means
        // danger in this UI.
        destructive: {
          DEFAULT: token("destructive"),
          foreground: token("destructive-foreground"),
        },
        warning: {
          DEFAULT: "hsl(var(--warning))",
          foreground: "hsl(var(--warning-foreground))",
        },
        success: {
          DEFAULT: "hsl(var(--success))",
          foreground: "hsl(var(--success-foreground))",
        },
        info: {
          DEFAULT: "hsl(var(--info))",
          foreground: "hsl(var(--info-foreground))",
        },
        muted: {
          DEFAULT: token("muted"),
          foreground: token("muted-foreground"),
        },
        accent: {
          DEFAULT: token("accent"),
          foreground: token("accent-foreground"),
        },
        popover: {
          DEFAULT: token("popover"),
          foreground: token("popover-foreground"),
        },
        card: {
          DEFAULT: token("card"),
          foreground: token("card-foreground"),
        },
        // The raw Labs navy steps, for the rare place a token is too coarse.
        navy: {
          deepest: "#04060f",
          deep: "#060c1a",
          mid: "#0a1628",
          surface: "#0f1f36",
          elevated: "#142640",
        },
        brand: {
          DEFAULT: "#ff5a58",
          muted: "#d23c3a",
        },
      },
    },
  },
  plugins: [],
};

export default config;
