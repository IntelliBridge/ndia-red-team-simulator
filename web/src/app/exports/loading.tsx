// Covers the whole of the page's awaited prefetch, in the shape of the table
// it is replaced by, so nothing shifts when the rows arrive.

// Deep import rather than the package barrel: this is a server component and
// the barrel re-exports client-only components.
import { Skeleton } from "@redsim/design-system/primitives/skeleton";

const SKELETON_ROWS = 5;
const COLUMNS = ["Run", "Model", "Status", "Reports", "Dataset", "Created"];

export default function ExportsLoading() {
  return (
    <div className="space-y-6">
      <header>
        <div className="redsim-kicker">evidence out</div>
        <h1 className="text-2xl font-semibold">Exports</h1>
      </header>
      <div
        className="overflow-hidden rounded-md border border-border bg-card"
        aria-busy="true"
        aria-label="Loading exports"
      >
        <div className="flex gap-4 border-b border-border px-4 py-3">
          {COLUMNS.map((column) => (
            <Skeleton key={column} className="h-4 w-20" />
          ))}
        </div>
        {Array.from({ length: SKELETON_ROWS }, (_, row) => (
          <div key={row} className="flex gap-4 border-b border-border px-4 py-4 last:border-b-0">
            {COLUMNS.map((column) => (
              <Skeleton key={column} className="h-4 w-20" />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
