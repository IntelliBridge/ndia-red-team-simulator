// Covers the whole of the page's awaited prefetch (KTD4).
//
// The rows reserve the height the table's own rows occupy, so the skeleton
// and the loaded table do not shift the page under each other (R9).

// Deep import rather than the package barrel: this file is a server
// component, and the barrel re-exports components that call useState without
// their own "use client", so importing it here fails the build. The package
// declares ./primitives/* as an export for exactly this case.
import { Skeleton } from "@redsim/design-system/primitives/skeleton";

const SKELETON_ROWS = 5;
const COLUMNS = ["Run", "Model", "Attacks", "Status", "Created"];

export default function RunsLoading() {
  return (
    <div className="space-y-6">
      <h1>Runs</h1>
      <div
        className="overflow-x-auto"
        aria-busy="true"
        aria-label="Loading runs"
      >
        <div className="flex gap-4 border-b border-line-strong px-3 py-3">
          {COLUMNS.map((column) => (
            <Skeleton key={column} className="h-4 w-24" />
          ))}
        </div>
        {Array.from({ length: SKELETON_ROWS }, (_, row) => (
          <div key={row} className="flex gap-4 border-b border-line px-3 py-4 last:border-b-0">
            {COLUMNS.map((column) => (
              <Skeleton key={column} className="h-4 w-24" />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
