"use client";

import * as React from "react";
import { useRouter } from "next/navigation";

import { Button, CommandIcon } from "@redsim/design-system";

import { logout } from "@/lib/auth";

import { ThemeToggle } from "./theme-toggle";

/**
 * The bar above the page content: palette trigger, theme, sign out.
 *
 * The palette is opened by dispatching the chord it already listens for,
 * rather than lifting its open state into a context, so the button and the
 * keyboard shortcut cannot drift apart.
 */
export function TopBar() {
  const router = useRouter();
  const [signingOut, setSigningOut] = React.useState(false);

  const openPalette = React.useCallback(() => {
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true }),
    );
  }, []);

  const onSignOut = React.useCallback(async () => {
    setSigningOut(true);
    try {
      // logout() settles rather than rejects, so the redirect runs either way
      // and a failed upstream call never strands the user on a signed-in page.
      await logout();
    } finally {
      router.push("/login");
    }
  }, [router]);

  return (
    <div className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-hairline bg-panel px-4">
      <button
        type="button"
        onClick={openPalette}
        className="hidden items-center gap-2 rounded-md border border-hairline bg-panel-2 px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground sm:flex"
      >
        <CommandIcon className="h-3.5 w-3.5" aria-hidden />
        Go to&hellip;
        <kbd className="font-mono text-[10px]">&#8984;K</kbd>
      </button>
      {/* Keeps the right-hand controls right-aligned when the palette
          trigger is hidden at narrow widths. */}
      <div className="sm:hidden" />
      <div className="flex items-center gap-3">
        <ThemeToggle />
        <Button
          variant="outline"
          size="sm"
          onClick={onSignOut}
          disabled={signingOut}
        >
          {signingOut ? "Signing out…" : "Sign out"}
        </Button>
      </div>
    </div>
  );
}
