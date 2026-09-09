import "@/styles/globals.css";

import { AppShell } from "@/components/app-shell";
import { FixtureRibbon } from "@/components/fixture-ribbon";
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

/**
 * The app shell.
 *
 * The theme is fixed. `dark` is written into the server markup and nothing on
 * the client ever changes it, so the first paint is the final one and there is
 * no flash. It is a literal class rather than a media query because the shadcn
 * primitives carry `dark:` refinements and `darkMode` is `"class"`.
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <TRPCReactProvider>
          {/* Skip link: first focusable element, visually hidden until
              keyboard-focused, so keyboard and screen-reader users can jump
              past the nav straight to the page content. */}
          <a
            href="#main-content"
            className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
          >
            Skip to content
          </a>
          {/* The banner landmark, ahead of the nav so it is read before it
              and before any page content. */}
          <FixtureRibbon show={showsFixtureRibbon} />
          <AppShell>{children}</AppShell>
        </TRPCReactProvider>
      </body>
    </html>
  );
}
