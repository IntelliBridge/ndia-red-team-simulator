import type { KeyboardEvent, MouseEvent } from "react";

/**
 * Props that make a whole table row (or list item) open `href`.
 *
 * Clicks on the row navigate; clicks that land on a link or a button inside
 * the row are left to that element, so an inline action or the existing
 * anchor keeps working and never navigates twice. Middle-click and modifier
 * clicks open a new tab, as a link would. Keyboard users reach the finding
 * through the anchor inside the row.
 */
export function rowLink(href: string) {
  const interactive = (target: EventTarget | null) =>
    target instanceof Element && target.closest("a, button, input, select, textarea, [role='button']") !== null;
  // No ARIA role on the row: a <tr> or <li> may not carry role="link" (axe
  // aria-allowed-role), and the anchor inside the row is the accessible way
  // in. The row-wide click is a pointer convenience on top of it.
  return {
    "data-href": href,
    className: "cursor-pointer hover:bg-muted/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary",
    onClick: (event: MouseEvent<HTMLElement>) => {
      if (interactive(event.target)) return;
      if (event.metaKey || event.ctrlKey || event.button === 1) {
        window.open(href, "_blank", "noopener");
        return;
      }
      window.location.assign(href);
    },
    onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
      if (event.key === "Enter" && event.target === event.currentTarget) window.location.assign(href);
    },
  };
}
