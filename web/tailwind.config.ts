import type { Config } from "tailwindcss";

const config: Config = {
  // One dark theme. `<html class="dark">` is set in app/layout.tsx so the
  // vendored shadcn primitives' `dark:` variants apply.
  darkMode: "class",
  content: [
    "./src/**/*.{ts,tsx}",
    "../packages/design-system/src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // Public Sans for interface and measurement, Source Serif 4 for the
        // written interpretation, JetBrains Mono for identifiers. The same
        // stacks are exposed as --sans / --serif / --mono in globals.css for
        // CSS-only callers.
        sans: ['"Public Sans"', "system-ui", "-apple-system", '"Segoe UI"', "Roboto", "sans-serif"],
        serif: ['"Source Serif 4"', "Georgia", '"Times New Roman"', "serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", '"SF Mono"', "Menlo", "monospace"],
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
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        // Amber-orange, not red: red is the brand accent and never means
        // danger in this UI.
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
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
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        // The ink surfaces and rules by name, for the place a semantic token
        // is too coarse.
        ground: "var(--ground)",
        surface: {
          1: "var(--surface-1)",
          2: "var(--surface-2)",
          3: "var(--surface-3)",
        },
        ink: {
          1: "var(--ink-1)",
          2: "var(--ink-2)",
          3: "var(--ink-3)",
          4: "var(--ink-4)",
        },
        line: {
          DEFAULT: "var(--line)",
          strong: "var(--line-strong)",
        },
        // Data marks: adversarial, control, clean. Every chart uses these.
        data: {
          adv: "var(--data-adv)",
          control: "var(--data-control)",
          clean: "var(--data-clean)",
        },
        // The Labs navy steps, kept so existing `navy-*` utilities resolve.
        navy: {
          deepest: "var(--navy-deepest)",
          deep: "var(--navy-deep)",
          mid: "var(--navy-mid)",
          surface: "var(--navy-surface)",
          elevated: "var(--navy-elevated)",
        },
        brand: {
          DEFAULT: "#ff5a58",
          muted: "#c93f3d",
        },
      },
    },
  },
  plugins: [],
};

export default config;
