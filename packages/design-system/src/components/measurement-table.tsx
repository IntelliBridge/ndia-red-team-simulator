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
export function MeasurementTable({
  measurements = [],
}: {
  measurements?: MeasurementTableRow[];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="bg-muted text-[10px] uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="p-2">Family / attack</th>
            <th className="p-2">Evidence</th>
            <th className="p-2">Accuracy</th>
            <th className="p-2">ASR</th>
            <th className="p-2">First ε</th>
            <th className="p-2">L∞ / L2</th>
            <th className="p-2">Wall</th>
            <th className="p-2">Details</th>
          </tr>
        </thead>
        <tbody>
          {measurements.map((m, i) => (
            <tr key={m.id ?? i} className="border-t border-border align-top">
              <td className="p-2 font-semibold">
                {m.family}
                {m.attack_id ? ` · ${m.attack_id}` : ""}
              </td>
              <td className="p-2">
                {m.n === 0 ? "no evidence recorded" : `${m.n_correct} / ${m.n}`}
              </td>
              <td className="p-2">{m.n === 0 ? "—" : pct(m.accuracy)}</td>
              <td className="p-2">
                {m.n === 0 ? "no evidence recorded" : pct(m.attack_success_rate)}
                {m.n > 0 && m.n_clean_correct != null && (
                  <small className="block text-muted-foreground">
                    denominator n={m.n_clean_correct}
                  </small>
                )}
              </td>
              <td className="p-2">
                {m.n === 0 ? "—" : (m.pert_first_success_mean ?? "—")}
                {m.n > 0 && m.pert_first_success_n != null && (
                  <small className="block">n={m.pert_first_success_n}</small>
                )}
              </td>
              <td className="p-2">
                {m.linf_norm_mean ?? "—"} / {m.l2_norm_mean ?? "—"}
              </td>
              <td className="p-2">
                {m.wall_time_s == null ? "—" : `${m.wall_time_s}s`}
              </td>
              <td className="p-2">
                <details>
                  <summary>Details</summary>
                  {m.notes?.length ? (
                    <ul>
                      {m.notes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>No notes recorded.</p>
                  )}
                  {m.per_class &&
                    Object.entries(m.per_class).map(([name, row]) => (
                      <div key={name}>
                        {name}: {row.n_correct}/{row.n}
                      </div>
                    ))}
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
