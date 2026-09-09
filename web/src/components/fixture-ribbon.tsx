import { env } from "@/env";

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

/**
 * The ribbon a fixture build paints on every page. Rendered first inside the
 * banner landmark, so it is read before the nav and any page content. A
 * fixture build serves recorded rows in place of API data, and a page that
 * showed them with no marker would read as measured.
 */
export function FixtureRibbon() {
  if (!showsFixtureRibbon) return null;
  return (
    <div
      data-testid="fixture-ribbon"
      className="border-b border-border bg-warning px-6 py-2 text-center font-mono text-xs font-medium uppercase tracking-wider text-warning-foreground"
    >
      Fixture mode. Every row on these pages is illustrative recorded data, not
      measurements from a run.
    </div>
  );
}
