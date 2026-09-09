// MeasurementTable — the per-family measurement rows with their
// denominators. Sentence-case headers on a strong rule, hairlines between
// rows, numbers right-aligned in tabular figures, and the attack id set in
// mono under its family so the two never run together.

export type MeasurementTableRow = {
  id?: string;
  family: string;
  attack_id?: string | null;
  n: number;
  n_correct: number;
  accuracy: number;
  n_flipped_from_clean?: number | null;
  n_clean_correct?: number | null;
  attack_success_rate?: number | null;
  pert_first_success_mean?: number | null;
  pert_first_success_n?: number | null;
  linf_norm_mean?: number | null;
  l2_norm_mean?: number | null;
  wall_time_s?: number;
  notes?: string[];
  per_class?: Record<string, { n: number; n_correct: number }>;
};
const pct = (value?: number | null) =>
  value == null ? "—" : `${(value * 100).toFixed(1)}%`;

const num = "px-2 py-2 text-right tabular-nums";

export function MeasurementTable({
  measurements = [],
}: {
  measurements?: MeasurementTableRow[];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-line-strong">
            <th className="px-2 py-2 font-medium">Family and attack</th>
            <th className="px-2 py-2 text-right font-medium">Evidence</th>
            <th className="px-2 py-2 text-right font-medium">Accuracy</th>
            <th className="px-2 py-2 text-right font-medium">Attack success</th>
            <th className="px-2 py-2 text-right font-medium">First ε</th>
            <th className="px-2 py-2 text-right font-medium">L∞ / L2</th>
            <th className="px-2 py-2 text-right font-medium">Wall</th>
            <th className="px-2 py-2 font-medium">Details</th>
          </tr>
        </thead>
        <tbody>
          {measurements.map((m, i) => (
            <tr key={m.id ?? i} className="border-b border-line align-top last:border-0">
              <td className="px-2 py-2">
                <span className="block font-medium text-ink-1">{m.family}</span>
                {m.attack_id ? (
                  <span className="block font-mono text-[11px] text-ink-3">{m.attack_id}</span>
                ) : null}
              </td>
              <td className={num}>
                {m.n === 0 ? "no evidence recorded" : `${m.n_correct} / ${m.n}`}
              </td>
              <td className={`${num} text-ink-1`}>{m.n === 0 ? "—" : pct(m.accuracy)}</td>
              <td className={num}>
                {m.n === 0 ? "no evidence recorded" : pct(m.attack_success_rate)}
                {m.n > 0 && m.n_clean_correct != null && (
                  <small className="block text-ink-3">
                    denominator n={m.n_clean_correct}
                  </small>
                )}
              </td>
              <td className={num}>
                {m.n === 0 ? "—" : (m.pert_first_success_mean ?? "—")}
                {m.n > 0 && m.pert_first_success_n != null && (
                  <small className="block text-ink-3">n={m.pert_first_success_n}</small>
                )}
              </td>
              <td className={num}>
                {m.linf_norm_mean ?? "—"} / {m.l2_norm_mean ?? "—"}
              </td>
              <td className={num}>
                {m.wall_time_s == null ? "—" : `${m.wall_time_s}s`}
              </td>
              <td className="px-2 py-2">
                <details className="group">
                  <summary className="cursor-pointer text-ink-2 hover:text-ink-1">Details</summary>
                  <div className="mt-1 space-y-1 text-ink-3">
                    {m.notes?.length ? (
                      <ul className="m-0 list-disc pl-4">
                        {m.notes.map((note) => (
                          <li key={note}>{note}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="m-0">No notes recorded.</p>
                    )}
                    {m.per_class &&
                      Object.entries(m.per_class).map(([name, row]) => (
                        <div key={name} className="tabular-nums">
                          {name}: {row.n_correct}/{row.n}
                        </div>
                      ))}
                  </div>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
