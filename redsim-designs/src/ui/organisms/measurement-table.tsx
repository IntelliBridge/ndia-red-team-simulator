"use client"

import { Fragment, useState } from "react"
import { ChevronRight } from "lucide-react"
import type { Measurement, MeasurementRow } from "@/lib/api-types"
import { asr, cn, fraction } from "@/lib/utils"

function familyLabel(r: MeasurementRow) {
  if (r.family === "clean") return "clean"
  if (r.family === "control") return `control · ε=${r.eps}`
  return `${r.attack} · ε=${r.eps}`
}

/**
 * Measurements by family. Accuracy printed as k / n (pct); ASR as
 * n_flipped_from_clean / n_clean_correct. A family with n=0 shows "no evidence
 * recorded", never 0%. Per-class sub-tables are collapsible. [spec §18.3 panel 4]
 */
export function MeasurementTable({ measurement }: { measurement: Measurement }) {
  const [open, setOpen] = useState<Record<number, boolean>>({})
  return (
    <div className="overflow-x-auto rounded-md border border-hairline">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-hairline bg-panel-2 text-[11px] uppercase tracking-wide text-muted">
            <th className="px-3 py-2 text-left">Family</th>
            <th className="px-3 py-2 text-left">Accuracy</th>
            <th className="px-3 py-2 text-left">ASR</th>
            <th className="px-3 py-2 text-right">mean L∞</th>
            <th className="px-3 py-2 text-right">mean L2</th>
            <th className="px-3 py-2 text-right">wall time</th>
          </tr>
        </thead>
        <tbody>
          {measurement.rows.map((r, i) => {
            const empty = r.n <= 0
            const hasClasses = (r.per_class?.length ?? 0) > 0
            return (
              <Fragment key={i}>
                <tr className="border-b border-hairline last:border-0">
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      disabled={!hasClasses}
                      onClick={() => setOpen((s) => ({ ...s, [i]: !s[i] }))}
                      className={cn("inline-flex items-center gap-1 font-mono text-xs", hasClasses ? "text-foreground hover:text-primary" : "text-foreground")}
                    >
                      {hasClasses && <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", open[i] && "rotate-90")} />}
                      {familyLabel(r)}
                    </button>
                  </td>
                  {empty ? (
                    <td className="px-3 py-2 text-xs text-muted" colSpan={5}>
                      no evidence recorded
                    </td>
                  ) : (
                    <>
                      <td className="px-3 py-2 font-mono text-xs tabular">{fraction(r.n_correct, r.n)}</td>
                      <td className="px-3 py-2 font-mono text-xs tabular">
                        {r.family === "clean" ? "—" : asr(r.n_flipped_from_clean, r.n_clean_correct)}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-xs tabular">{r.mean_linf ?? "—"}</td>
                      <td className="px-3 py-2 text-right font-mono text-xs tabular">{r.mean_l2 ?? "—"}</td>
                      <td className="px-3 py-2 text-right font-mono text-xs tabular">{r.wall_time_s != null ? `${r.wall_time_s}s` : "—"}</td>
                    </>
                  )}
                </tr>
                {hasClasses && open[i] && (
                  <tr className="bg-panel-2/40">
                    <td colSpan={6} className="px-3 py-2">
                      <table className="w-full text-xs">
                        <tbody>
                          {r.per_class!.map((c) => (
                            <tr key={c.label}>
                              <td className="py-1 pl-6 font-mono text-muted">{c.label}</td>
                              <td className="py-1 font-mono tabular">{fraction(c.n_correct, c.n)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
