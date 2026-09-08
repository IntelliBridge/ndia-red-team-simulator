import { DimensionBars } from "./dimension-bars";

export interface MriScorecardProps {
  score?: {
    mri?: number;
    grade?: string;
    subscores?: Record<string, number | null>;
  } | null;
  familyRows?: Array<{ family: string; accuracy: number; n: number }>;
  measuredDelta?: number | null;
  curve?: unknown[];
  unavailableReason?: string;
}

const dimensions = ["S_acc", "S_asr", "S_eps", "S_conf", "S_expl"];

export function MriScorecard({
  score,
  familyRows,
  measuredDelta,
  curve,
  unavailableReason = "required evidence is incomplete",
}: MriScorecardProps) {
  const ready =
    score?.mri !== undefined &&
    !!score.grade &&
    dimensions.every((key) => score.subscores?.[key] != null) &&
    !!familyRows?.length &&
    !!curve?.length;
  if (!ready)
    return (
      <p className="border border-dashed border-border p-4 text-sm text-muted-foreground">
        Score unavailable: {unavailableReason}
      </p>
    );
  return (
    <div className="space-y-4">
      <div className="flex items-end gap-3">
        <strong className="font-mono text-5xl tracking-tighter">
          {score.mri}
        </strong>
        <span className="mb-2 rounded-sm bg-muted px-2 py-1 text-xs font-semibold">
          {score.grade}
        </span>
        {measuredDelta != null && (
          <span className="mb-2 text-xs text-primary">
            measured ΔMRI {measuredDelta > 0 ? "+" : ""}
            {measuredDelta}
          </span>
        )}
      </div>
      <DimensionBars
        values={Object.fromEntries(
          dimensions.map((key) => [key, score.subscores![key]!]),
        )}
      />
      <table className="w-full text-left text-xs">
        <thead>
          <tr>
            <th>Family</th>
            <th>Accuracy</th>
            <th>n</th>
          </tr>
        </thead>
        <tbody>
          {familyRows!.map((row) => (
            <tr key={row.family} className="border-t border-border">
              <td className="py-2">{row.family}</td>
              <td>
                {row.n === 0 ? "no evidence recorded" : row.accuracy}
              </td>
              <td>{row.n === 0 ? "—" : row.n}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-[11px] text-muted-foreground">
        Per-campaign summary under the recorded attacks and settings. Not a
        readiness or certification statement.
      </p>
    </div>
  );
}
