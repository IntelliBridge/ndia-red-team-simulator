import "@/styles/globals.css";

import { CommandPalette } from "@/components/command-palette";
import { NavLinks } from "@/components/nav-links";
import { env } from "@/env";
import { TRPCReactProvider } from "@/lib/trpc/client";

/**
 * Whether this build says on screen that its rows are recorded fixtures.
 *
 * The public flag rather than `REDSIM_DEV_FIXTURES`, which is the runtime
 * authority that actually serves them, for two reasons. A server variable is
 * unreadable from a component that also renders under jsdom, and the pair is
 * kept consistent in the direction that matters: `env.js` refuses to boot when
 * `REDSIM_DEV_FIXTURES` is on and the raw public flag is not exactly `"1"`.
 * So fixtures being served implies the ribbon, which is the implication a
 * viewer depends on. The other direction only over-discloses.
 */
const showsFixtureRibbon = env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;

export const metadata = {
  title: "redsim",
  description: "Adversarial ML Red-Team Simulator",
};

const NAV_LINKS: { href: string; label: string }[] = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/models", label: "Models" },
  { href: "/runs", label: "Runs" },
  { href: "/tests", label: "Tests" },
  { href: "/auth-profiles", label: "Auth Profiles" },
  { href: "/findings", label: "Findings" },
  { href: "/logs", label: "Logs" },
  { href: "/audit", label: "Audit" },
  { href: "/cost", label: "Cost" },
];

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    // One dark theme, after labs.agiledefense.com. The `dark` class is fixed
    // so the vendored shadcn primitives' `dark:` variants apply; there is no
    // light theme and no toggle.
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <TRPCReactProvider>
          {/* Skip link: first focusable element, visually hidden until
              keyboard-focused, so keyboard/screen-reader users can jump
              past the nav straight to the page content. */}
          <a
            href="#main-content"
            className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
          >
            Skip to content
          </a>
          <header className="sticky top-0 z-40 border-b border-border bg-navy-deepest/80 backdrop-blur-xl">
            {/* Inside the banner landmark rather than loose above it, so the
                shell keeps every element inside a landmark, and first within
                it, so it is read before the nav and any page content. A
                fixture build serves recorded rows in place of API data, and a
                page that showed them with no marker would read as measured. */}
            {showsFixtureRibbon ? (
              <div
                data-testid="fixture-ribbon"
                className="border-b border-border bg-warning px-6 py-2 text-center font-mono text-xs font-medium uppercase tracking-wider text-warning-foreground"
              >
                Fixture mode. Every row on these pages is illustrative recorded
                data, not measurements from a run.
              </div>
            ) : null}
            <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-6 px-6">
              <div className="flex items-center gap-4">
                <a
                  href="/dashboard"
                  className="flex h-[26px] items-center"
                  data-testid="brand-link"
                >
                  {/* The Agile Defense Labs mark, white on the navy header.
                      Vendored from labs.agiledefense.com. */}
                  <img
                    src="/brand/agile-labs.svg"
                    alt="Agile Defense Labs"
                    width={56}
                    height={26}
                    className="h-[26px] w-auto"
                  />
                </a>
                <span
                  aria-hidden="true"
                  className="hidden h-5 w-px bg-border sm:block"
                />
                <span className="redsim-meta hidden sm:block">
                  UNCLASSIFIED // OPEN PUBLIC DATA
                </span>
              </div>
              <nav className="flex flex-wrap items-center justify-end gap-x-5 gap-y-1">
                <NavLinks links={NAV_LINKS} />
              </nav>
            </div>
          </header>
          <main
            id="main-content"
            tabIndex={-1}
            className="mx-auto max-w-6xl px-6 py-8"
          >
            {children}
            <footer className="redsim-footer">
              <div className="redsim-meta mb-2">
                REDSIM // ADVERSARIAL ML RED-TEAM SIMULATOR
              </div>
              Proof of concept on open, unclassified public data. Results are
              evidence for human review, not a safety, readiness, or
              certification determination.
            </footer>
          </main>
          <CommandPalette links={NAV_LINKS} />
        </TRPCReactProvider>
      </body>
    </html>
  );
}
