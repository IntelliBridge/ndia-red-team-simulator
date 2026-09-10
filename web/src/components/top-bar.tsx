"use client";

// TopBar: the banner landmark of the app shell. The fixture ribbon comes
// first inside it, then the product name and the UNCLASSIFIED marker on the
// left with the command-palette button and the account menu on the right,
// and below the md breakpoint a compact row of the same nav links, because
// the sidebar is not rendered there and every route has to stay reachable
// without the palette.

import { NAV_LINKS } from "@/lib/nav";

import { FixtureRibbon } from "./fixture-ribbon";
import { NavLinks } from "./nav-links";
import { UserMenu } from "./user-menu";

export function TopBar() {
  // The palette owns its open state and listens for the chord on the
  // document, so the button replays the chord rather than reaching into it.
  const openPalette = () => {
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true }),
    );
  };

  return (
    <header className="sticky top-0 z-40 shrink-0 border-b border-border bg-navy-deepest/80 backdrop-blur-xl">
      <FixtureRibbon />
      <div className="flex h-14 items-center justify-between gap-4 px-4 md:px-6">
        <div className="flex min-w-0 items-center gap-4">
          {/* Below md the sidebar, and the mark in its head, are not
              rendered, so the mark sits here instead and still links home. */}
          <a
            href="/dashboard"
            className="flex h-[26px] items-center md:hidden"
            data-testid="brand-link-compact"
          >
            <img
              src="/brand/agile-labs.svg"
              alt="Agile Defense Labs"
              width={56}
              height={26}
              className="h-[26px] w-auto"
            />
          </a>
          <span aria-hidden="true" className="hidden h-5 w-px bg-border sm:block md:hidden" />
          <span className="hidden truncate text-sm font-semibold tracking-tight text-white sm:block">
            Adversarial ML Red-Team Simulator
          </span>
          <span aria-hidden="true" className="hidden h-5 w-px bg-border sm:block" />
          <span className="redsim-meta hidden font-semibold text-emerald-600 dark:text-emerald-400 sm:block">
            UNCLASSIFIED
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <button
            type="button"
            onClick={openPalette}
            className="hidden items-center gap-2 rounded-md border border-border bg-muted px-2.5 py-1.5 text-xs text-muted-foreground hover:text-foreground md:flex"
          >
            Go to…
            <kbd className="font-mono text-[10px]">⌘K</kbd>
          </button>
          <UserMenu />
        </div>
      </div>
      <nav
        aria-label="Primary (compact)"
        className="flex flex-wrap items-center gap-x-5 gap-y-1 px-4 pb-3 md:hidden"
      >
        <NavLinks links={NAV_LINKS} />
      </nav>
    </header>
  );
}
