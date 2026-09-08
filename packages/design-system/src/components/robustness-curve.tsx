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
          const color = colors[seriesIndex % colors.length];
          // A point with n === 0 carries no evidence: it has no position on
          // the accuracy axis and it ends the current stroke, so the line
          // never bridges measured neighbours across a missing epsilon.
          const segments: RobustnessPoint[][] = [];
          let segment: RobustnessPoint[] = [];
          for (const point of sorted) {
            if (point.n === 0) {
              if (segment.length) segments.push(segment);
              segment = [];
            } else {
              segment.push(point);
            }
          }
          if (segment.length) segments.push(segment);
          return (
            <g key={key}>
              {segments
                .filter((points) => points.length > 1)
                .map((points) => (
                  <path
                    key={`${key}-segment-${points[0].eps}`}
                    d={points
                      .map(
                        (p, i) =>
                          `${i ? "L" : "M"} ${x(p.eps)} ${y(p.accuracy)}`,
                      )
                      .join(" ")}
                    fill="none"
                    stroke={color}
                    strokeWidth="2"
                  />
                ))}
              {sorted.map((p) =>
                p.n === 0 ? (
                  <line
                    key={`${key}-${p.eps}`}
                    x1={x(p.eps)}
                    x2={x(p.eps)}
                    y1={4}
                    y2={96}
                    stroke={color}
                    strokeWidth="1"
                    strokeDasharray="2 2"
                    opacity=".6"
                    role="img"
                    aria-label={`${key}, epsilon ${p.eps}, no evidence recorded`}
                  >
                    <title>{`${key}: ε ${p.eps}, no evidence recorded`}</title>
                  </line>
                ) : (
                  <circle
                    key={`${key}-${p.eps}`}
                    cx={x(p.eps)}
                    cy={y(p.accuracy)}
                    r="2.2"
                    fill={color}
                    role="img"
                    aria-label={`${key}, epsilon ${p.eps}, accuracy ${(p.accuracy * 100).toFixed(1)}%, n ${p.n}`}
                  >
                    <title>
                      {`${key}: ε ${p.eps}, accuracy ${(p.accuracy * 100).toFixed(1)}%, n=${p.n}`}
                    </title>
                  </circle>
                ),
              )}
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
        {points.some((point) => point.n === 0) && (
          <span>dashed marker: no evidence recorded at that ε</span>
        )}
        <span className="ml-auto">
          ε {min}–{max}
        </span>
      </figcaption>
    </figure>
  );
}
