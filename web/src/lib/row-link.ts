import type { KeyboardEvent, MouseEvent } from "react";

/**
 * Props that make a whole table row (or list item) open `href`.
 *
 * Clicks and Enter on the row navigate; clicks that land on a link or a
 * button inside the row are left to that element, so an inline action or the
 * existing anchor keeps working and never navigates twice. Middle-click and
 * modifier clicks open a new tab, as a link would.
 */
export function rowLink(href: string) {
  const interactive = (target: EventTarget | null) =>
    target instanceof Element && target.closest("a, button, input, select, textarea, [role='button']") !== null;
  return {
    role: "link" as const,
    tabIndex: 0,
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
      if (event.key === "Enter" && !interactive(event.target)) window.location.assign(href);
    },
  };
}
