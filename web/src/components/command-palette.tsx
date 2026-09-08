"use client";

// CommandPalette — a global Cmd/Ctrl-K quick-nav launcher.
//
// Mounted once in app/layout.tsx. Listens for the ⌘K / Ctrl-K chord (and
// Escape to close) and opens the design-system CommandDialog with one item
// per top-level route. Selecting an item navigates via next/navigation and
// closes the dialog. Renders nothing visible while closed, so it is inert in
// the page shell until summoned.

import * as React from "react";
import { useRouter } from "next/navigation";

import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@redsim/design-system";

export interface CommandPaletteLink {
  href: string;
  label: string;
}

export interface CommandPaletteProps {
  links: CommandPaletteLink[];
}

export function CommandPalette({ links }: CommandPaletteProps) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const go = React.useCallback(
    (href: string) => {
      setOpen(false);
      router.push(href);
    },
    [router],
  );

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Jump to…" />
      <CommandList>
        <CommandEmpty>No matching pages.</CommandEmpty>
        <CommandGroup heading="Navigate">
          {links.map((link) => (
            <CommandItem
              key={link.href}
              value={link.label}
              onSelect={() => go(link.href)}
            >
              {link.label}
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
