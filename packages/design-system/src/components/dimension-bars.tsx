export function DimensionBars({ values }: { values: Record<string, number> }) {
  return (
    <div className="space-y-2">
      {Object.entries(values).map(([key, value]) => (
        <div key={key}>
          <div className="mb-1 flex justify-between text-xs">
            <span>{key}</span>
            <span className="font-mono">{value.toFixed(1)}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded bg-muted">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
