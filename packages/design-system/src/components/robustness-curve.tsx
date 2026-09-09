// RobustnessCurve — recorded accuracy against epsilon.
//
// Three kinds of series and three marks, the same across the interface:
// the clean baseline as a dashed ink line, each attack in bone (a second
// attack in a darker bone), the benign-noise control in slate. The x axis
// is drawn as a ruler: one tick per epsilon in the grid, labelled beneath,
// so the perturbation budget the campaign swept is readable off the chart.
// The SVG stretches to its box; ticks and labels are laid out in HTML at
// the same percentages so the text never distorts.

export type RobustnessPoint = {
  attack_id?: string;
  family: string;
  eps: number;
  accuracy: number;
  n: number;
  n_correct: number;
};
export type RobustnessSeries = {
  attack_id: string;
  eps_grid: number[];
  clean: Omit<RobustnessPoint, "attack_id" | "family" | "eps">;
  points: Array<Omit<RobustnessPoint, "attack_id" | "family">>;
  control: Array<Omit<RobustnessPoint, "attack_id" | "family">>;
};

function flattenCurve(
  evidence: Array<RobustnessPoint | RobustnessSeries>,
): RobustnessPoint[] {
  return evidence.flatMap((item) => {
    if (!("points" in item)) return [item];
    const clean = item.eps_grid.map((eps) => ({
      ...item.clean,
      attack_id: `${item.attack_id}:clean`,
      family: "clean",
      eps,
    }));
    const attack = item.points.map((point) => ({
      ...point,
      attack_id: item.attack_id,
      family: "evasion",
    }));
    const control = item.control.map((point) => ({
      ...point,
      attack_id: `${item.attack_id}:control`,
      family: "control",
    }));
    return [...clean, ...attack, ...control];
  });
}

const ADV_MARKS = ["#e8dcc4", "#c2a978", "#9d8659", "#efe6d4"];
const CONTROL_MARK = "#7e96b3";
const CLEAN_MARK = "rgba(236, 233, 226, 0.55)";

type Mark = { stroke: string; dash?: string };

function markFor(key: string, values: RobustnessPoint[], advIndex: number): Mark {
  const family = values[0]?.family;
  if (family === "clean" || key.endsWith(":clean")) return { stroke: CLEAN_MARK, dash: "2 2" };
  if (family === "control" || key.endsWith(":control")) return { stroke: CONTROL_MARK };
  return { stroke: ADV_MARKS[advIndex % ADV_MARKS.length]! };
}

export function RobustnessCurve({
  points = [],
}: {
  points?: Array<RobustnessPoint | RobustnessSeries>;
}) {
  if (!points.length)
    return (
      <p className="border border-dashed border-line-strong p-3 text-sm text-ink-3">
        Curve unavailable: no evidence recorded
      </p>
    );
  const normalized = flattenCurve(points);
  const grouped = normalized.reduce<Record<string, RobustnessPoint[]>>(
    (out, point) => {
      const key = point.attack_id ?? point.family;
      (out[key] ??= []).push(point);
      return out;
    },
    {},
  );
  const eps = normalized.map((point) => point.eps);
  const min = Math.min(...eps);
  const max = Math.max(...eps);
  const ticks = [...new Set(eps)].sort((a, b) => a - b);
  const x = (value: number) =>
    max === min ? 50 : ((value - min) / (max - min)) * 100;
  const y = (value: number) => 92 - value * 84;

  // Assign an adversarial mark per attack in first-seen order so the legend
  // and the lines agree.
  const marks: Record<string, Mark> = {};
  let advIndex = 0;
  for (const [key, values] of Object.entries(grouped)) {
    const isAdv = !(key.endsWith(":clean") || key.endsWith(":control") || values[0]?.family === "clean" || values[0]?.family === "control");
    marks[key] = markFor(key, values, advIndex);
    if (isAdv) advIndex += 1;
  }

  return (
    <figure className="m-0">
      <div className="relative">
        <div
          className="pointer-events-none absolute inset-y-0 left-0 flex w-8 flex-col justify-between py-[3%] text-[10px] tabular-nums text-ink-4"
          aria-hidden="true"
        >
          <span>100</span>
          <span>50</span>
          <span>0</span>
        </div>
        <svg
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          className="ml-8 block h-44 w-[calc(100%-2rem)] overflow-visible"
          role="img"
          aria-label="Recorded accuracy by epsilon for clean, attack, and control series"
        >
          <path
            d="M0 8H100M0 50H100M0 92H100"
            stroke="currentColor"
            opacity=".14"
            vectorEffect="non-scaling-stroke"
          />
          {ticks.map((t) => (
            <line
              key={`tick-${t}`}
              x1={x(t)}
              x2={x(t)}
              y1="92"
              y2="97"
              stroke="currentColor"
              opacity=".4"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {Object.entries(grouped).map(([key, values]) => {
            const sorted = [...values].sort((a, b) => a.eps - b.eps);
            const mark = marks[key]!;
            const segments = sorted.reduce<RobustnessPoint[][]>(
              (out, point) => {
                if (point.n <= 0) {
                  if (out.at(-1)?.length) out.push([]);
                } else {
                  (out.at(-1) ?? out[out.push([]) - 1]).push(point);
                }
                return out;
              },
              [[]],
            ).filter((segment) => segment.length);
            return (
              <g key={key}>
                {segments.map((segment, segmentIndex) => (
                  <path
                    key={`${key}-segment-${segmentIndex}`}
                    d={segment
                      .map(
                        (p, i) => `${i ? "L" : "M"} ${x(p.eps)} ${y(p.accuracy)}`,
                      )
                      .join(" ")}
                    fill="none"
                    stroke={mark.stroke}
                    strokeWidth="1.75"
                    strokeDasharray={mark.dash}
                    vectorEffect="non-scaling-stroke"
                  />
                ))}
                {sorted.map((p) =>
                  p.n === 0 ? (
                    <g
                      key={`${key}-${p.eps}`}
                      role="img"
                      aria-label={`${key}, epsilon ${p.eps}, no evidence recorded`}
                    >
                      <line
                        x1={x(p.eps) - 1.5}
                        x2={x(p.eps) + 1.5}
                        y1="98"
                        y2="98"
                        stroke={mark.stroke}
                        strokeWidth="1"
                        vectorEffect="non-scaling-stroke"
                      />
                      <title>{`${key}: ε ${p.eps}, no evidence recorded`}</title>
                    </g>
                  ) : (
                    <circle
                      key={`${key}-${p.eps}`}
                      cx={x(p.eps)}
                      cy={y(p.accuracy)}
                      r="1.4"
                      fill={mark.stroke}
                      role="img"
                      aria-label={
                        `${key}, epsilon ${p.eps}, accuracy ${(p.accuracy * 100).toFixed(1)}%, n ${p.n}`
                      }
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
        {/* The epsilon ruler labels, aligned to the ticks. */}
        <div className="relative ml-8 h-4 w-[calc(100%-2rem)]" aria-hidden="true">
          {ticks.map((t) => (
            <span
              key={`label-${t}`}
              className="absolute top-0 -translate-x-1/2 font-mono text-[10px] tabular-nums text-ink-3"
              style={{ left: `${x(t)}%` }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
      <figcaption className="mt-2 flex flex-wrap items-baseline gap-x-4 gap-y-1 text-[11px] text-ink-3">
        {Object.keys(grouped).map((key) => {
          const mark = marks[key]!;
          return (
            <span key={key} className="inline-flex items-center gap-1.5">
              <i
                className="inline-block h-0 w-4 border-t-2"
                style={{
                  borderColor: mark.stroke,
                  borderTopStyle: mark.dash ? "dashed" : "solid",
                }}
              />
              {key}
            </span>
          );
        })}
        <span className="ml-auto font-mono tabular-nums">
          ε {min} to {max}
        </span>
      </figcaption>
    </figure>
  );
}
