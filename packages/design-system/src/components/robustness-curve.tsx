export type RobustnessPoint = {
  attack_id?: string;
  family: string;
  eps: number;
  accuracy: number;
  n: number;
  n_correct: number;
};
const colors = ["#155e63", "#c66a2b", "#67715d", "#8b4f62", "#526d82"];
export function RobustnessCurve({
  points = [],
}: {
  points?: RobustnessPoint[];
}) {
  if (!points.length)
    return (
      <p className="border border-dashed border-border p-3 text-sm text-muted-foreground">
        Curve unavailable: no evidence recorded
      </p>
    );
  const grouped = points.reduce<Record<string, RobustnessPoint[]>>(
    (out, point) => {
      const key = point.attack_id ?? point.family;
      (out[key] ??= []).push(point);
      return out;
    },
    {},
  );
  const eps = points.map((point) => point.eps);
  const min = Math.min(...eps);
  const max = Math.max(...eps);
  const x = (value: number) =>
    max === min ? 50 : ((value - min) / (max - min)) * 100;
  const y = (value: number) => 96 - value * 92;
  return (
    <figure>
      <svg
        viewBox="0 0 100 100"
        className="h-44 w-full"
        role="img"
        aria-label="Recorded accuracy by epsilon for clean, attack, and control series"
      >
        <path
          d="M0 4H100M0 50H100M0 96H100"
          stroke="currentColor"
          opacity=".12"
        />
        {Object.entries(grouped).map(([key, values], seriesIndex) => {
          const sorted = [...values].sort((a, b) => a.eps - b.eps);
          const measured = sorted.filter((point) => point.n > 0);
          return (
            <g key={key}>
              {measured.length > 0 && (
                <path
                  d={measured
                    .map(
                      (p, i) => `${i ? "L" : "M"} ${x(p.eps)} ${y(p.accuracy)}`,
                    )
                    .join(" ")}
                  fill="none"
                  stroke={colors[seriesIndex % colors.length]}
                  strokeWidth="2"
                />
              )}
              {sorted.map((p) => (
                <circle
                  key={`${key}-${p.eps}`}
                  cx={x(p.eps)}
                  cy={p.n === 0 ? 96 : y(p.accuracy)}
                  r="2.2"
                  fill={colors[seriesIndex % colors.length]}
                  role="img"
                  aria-label={
                    p.n === 0
                      ? `${key}, epsilon ${p.eps}, no evidence recorded`
                      : `${key}, epsilon ${p.eps}, accuracy ${(p.accuracy * 100).toFixed(1)}%, n ${p.n}`
                  }
                >
                  <title>
                    {p.n === 0
                      ? `${key}: ε ${p.eps}, no evidence recorded`
                      : `${key}: ε ${p.eps}, accuracy ${(p.accuracy * 100).toFixed(1)}%, n=${p.n}`}
                  </title>
                </circle>
              ))}
            </g>
          );
        })}
      </svg>
      <figcaption className="flex flex-wrap gap-3 text-[10px] text-muted-foreground">
        {Object.keys(grouped).map((key, i) => (
          <span key={key}>
            <i
              className="mr-1 inline-block h-2 w-2"
              style={{ backgroundColor: colors[i % colors.length] }}
            />
            {key}
          </span>
        ))}
        <span className="ml-auto">
          ε {min}–{max}
        </span>
      </figcaption>
    </figure>
  );
}
