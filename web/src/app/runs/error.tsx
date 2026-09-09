"use client";

// Rendering failures only.
//
// A query that fails is dehydrated with its error and rendered by the leaf as
// an honest state, so this boundary is reached when the render itself throws
// (R9).

export default function RunsError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="space-y-4">
      <h1>Runs</h1>
      <div
        role="alert"
        className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
      >
        <p>The runs page could not be rendered.</p>
        {error.digest ? <p className="mt-1 font-mono text-xs">Digest: {error.digest}</p> : null}
        <button type="button" className="mt-2 underline" onClick={reset}>
          Try again
        </button>
      </div>
    </div>
  );
}
