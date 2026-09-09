// MriScorecard — the per-campaign Model Robustness Index with everything it
// may never be shown without: the subscores, the per-family table with
// denominators, and the caveat. The number is set large in the regular
// weight, the grade beside it as a small bordered mark, the measured delta
// as a plain sentence.

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
      <p className="border border-dashed border-line-strong p-4 text-sm text-ink-3">
        Score unavailable: {unavailableReason}
      </p>
    );
  return (
    <div className="grid gap-6 md:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
      <div className="flex flex-col gap-3">
        <div className="flex items-baseline gap-3">
          <strong className="redsim-numeral text-[4.5rem]">{score.mri}</strong>
          <span className="inline-flex h-6 items-center rounded-[3px] border border-line-strong px-2 text-xs font-semibold text-ink-1">
            {score.grade}
          </span>
        </div>
        <div className="redsim-kicker">Model Robustness Index, this campaign</div>
        {measuredDelta != null && (
          <p className="m-0 text-sm text-ink-2">
            Measured change{" "}
            <span className="tabular-nums text-ink-1">
              {measuredDelta > 0 ? "+" : ""}
              {measuredDelta}
            </span>{" "}
            against the baseline run.
          </p>
        )}
      </div>
      <div className="min-w-0 space-y-5">
        <DimensionBars
          values={Object.fromEntries(
            dimensions.map((key) => [key, score.subscores![key]!]),
          )}
        />
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-line-strong">
              <th className="pb-1.5 font-medium">Family</th>
              <th className="pb-1.5 text-right font-medium">Accuracy</th>
              <th className="pb-1.5 text-right font-medium">n</th>
            </tr>
          </thead>
          <tbody>
            {familyRows!.map((row) => (
              <tr key={row.family} className="border-b border-line last:border-0">
                <td className="py-1.5 text-ink-1">{row.family}</td>
                <td className="py-1.5 text-right tabular-nums">
                  {row.n === 0 ? "no evidence recorded" : row.accuracy}
                </td>
                <td className="py-1.5 text-right tabular-nums text-ink-3">
                  {row.n === 0 ? "—" : row.n}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="m-0 text-xs text-ink-3">
          Per-campaign summary under the recorded attacks and settings. Not a
          readiness or certification statement.
        </p>
      </div>
    </div>
  );
}
