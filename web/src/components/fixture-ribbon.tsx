// The deep path, not the package barrel: this is a server component, and
// the barrel re-exports components that call useState without their own
// "use client", which fails the build from here.
import { LabelBadge } from "@redsim/design-system/components/label-badge";

export interface FixtureRibbonProps {
  /** Whether this build serves recorded rows in place of API data. */
  show: boolean;
}

/**
 * The marker a fixture build paints on every page.
 *
 * In a tool that reports measured robustness, recorded rows shown with no
 * marker would read as measurements, so this owns the banner landmark and
 * sits ahead of the nav. Nothing in it is focusable, which is what keeps the
 * skip link first in the tab order.
 *
 * The landmark exists only when the ribbon does: an empty banner on every
 * ordinary build would be a stray rule under the top of the page.
 */
export function FixtureRibbon({ show }: FixtureRibbonProps) {
  if (!show) return null;
  return (
    <header className="border-b border-illustrative/40">
      <div
        data-testid="fixture-ribbon"
        className="stripe-warning flex items-center justify-center gap-2 px-4 py-1.5 text-center text-[11px] text-illustrative"
      >
        <LabelBadge variant="illustrative" />
        <span>
          Fixture mode. Every row on these pages is illustrative recorded data,
          not measurements from a run.
        </span>
      </div>
    </header>
  );
}
