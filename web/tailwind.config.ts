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
  darkMode: "class",
  content: [
    "./src/**/*.{ts,tsx}",
    "../packages/design-system/src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Semantic tokens backed by CSS variables defined in globals.css.
        // Utilities like `bg-background`, `text-foreground`, `border-border`,
        // `bg-card`, `text-muted-foreground` resolve through these and flip
        // automatically under the `.dark` class.
        border: token("border"),
        input: token("input"),
        ring: token("ring"),
        background: token("background"),
        foreground: token("foreground"),
        primary: {
          DEFAULT: token("primary"),
          foreground: token("primary-foreground"),
        },
        secondary: {
          DEFAULT: token("secondary"),
          foreground: token("secondary-foreground"),
        },
        destructive: {
          DEFAULT: token("destructive"),
          foreground: token("destructive-foreground"),
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

        // Surface and text names the redsim-designs export introduced. They
        // sit beside the shadcn names above over one palette, so a ported
        // component and a shipped one read the same colours.
        base: token("base"),
        panel: {
          DEFAULT: token("panel"),
          2: token("panel-2"),
        },
        hairline: token("hairline"),
        "muted-2": token("muted-2"),
        "primary-fg": token("primary-fg"),
        focus: token("focus"),

        // Derived-severity and status palette. Never a readiness reading:
        // these colour a measured value, not a verdict about fitness.
        robust: token("robust"),
        degraded: token("degraded"),
        critical: token("critical"),
        adversarial: token("adversarial"),

        // Label-badge accents, one per `redsim/ml/schema.py` literal.
        candidate: token("candidate"),
        inferred: token("inferred"),
        heuristic: token("heuristic"),
        measured: token("measured"),
        illustrative: token("illustrative"),
        partial: token("partial"),
        phaseb: token("phaseb"),
      },
      fontFamily: {
        sans: [
          "var(--font-inter)",
          "IBM Plex Sans",
          "ui-sans-serif",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "var(--font-jbmono)",
          "IBM Plex Mono",
          "ui-monospace",
          "monospace",
        ],
      },
      borderRadius: {
        sm: "calc(var(--radius) - 2px)",
        md: "var(--radius)",
        lg: "calc(var(--radius) + 4px)",
      },
    },
  },
  plugins: [],
};

export default config;
