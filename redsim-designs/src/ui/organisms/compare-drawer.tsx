"use client"

import { useState } from "react"
import { useRuns } from "@/lib/hooks"
import { compareRuns, ApiError } from "@/lib/api"
import type { Comparison, Campaign } from "@/lib/api-types"
import { Modal } from "@/ui/molecules/modal"
import { Select } from "@/ui/atoms/select"
import { Button } from "@/ui/atoms/button"
import { Spinner } from "@/ui/atoms/spinner"

/** Compare with another run of the same model. Handles 409 incompatible. [spec §18.3 panel 12] */
export function CompareDrawer({ run, onClose }: { run: Campaign; onClose: () => void }) {
  const { data: runs } = useRuns()
  const [other, setOther] = useState("")
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<Comparison | null>(null)
  const [err, setErr] = useState<ApiError | null>(null)

  const options = (runs ?? [])
    .filter((r) => r.model_id === run.model_id && r.run_id !== run.run_id)
    .map((r) => ({ value: r.run_id, label: `${r.run_id} · ${r.config.attacks.join(",")}` }))

  async function go() {
    setBusy(true)
    setErr(null)
    setResult(null)
    try {
      const c = (await compareRuns(run.run_id, other)) as Comparison
      setResult(c)
    } catch (e) {
      setErr(e instanceof ApiError ? e : new ApiError(0, { code: "unknown", message: String(e) }))
    } finally {
      setBusy(false)
    }
  }

  const incompatible = err?.status === 409 || result?.incompatible

  return (
    <Modal title="Compare runs" onClose={onClose} wide>
      <div className="flex items-end gap-2">
        <label className="flex-1">
          <span className="mb-1 block text-xs text-muted">Other run of {run.model_name}</span>
          <Select options={options} placeholder={options.length ? "Select a run" : "No other runs for this model"} value={other} onChange={(e) => setOther(e.target.value)} />
        </label>
        <Button variant="primary" size="sm" disabled={!other || busy} onClick={go}>Compare</Button>
      </div>

      {busy && <div className="flex justify-center py-8"><Spinner /></div>}

      {incompatible && (
        <div className="mt-4 rounded-md border border-degraded/40 bg-degraded/10 p-3 text-sm text-degraded">
          <p className="font-medium">Incompatible campaigns (409)</p>
          <p className="mt-1 text-xs">Mismatched variables:</p>
          <ul className="mt-1 list-inside list-disc font-mono text-xs">
            {(result?.incompatible?.mismatched ?? err?.detail.reasons ?? []).map((m) => <li key={m}>{m}</li>)}
          </ul>
        </div>
      )}

      {result && !result.incompatible && (
        <div className="mt-4 flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-md border border-hairline bg-panel-2/40 p-3">
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-2">Changed</p>
              <ul className="flex flex-col gap-1 font-mono text-xs">
                {result.changed_variables.map((c) => (
                  <li key={c.name}>{c.name}: <span className="text-critical">{c.a}</span> → <span className="text-robust">{c.b}</span></li>
                ))}
              </ul>
            </div>
            <div className="rounded-md border border-hairline bg-panel-2/40 p-3">
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-2">Unchanged</p>
              <p className="font-mono text-xs text-muted">{result.unchanged_variables.join(", ")}</p>
            </div>
          </div>

          {result.per_dimension_delta && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-2">Per-dimension Δ</p>
              <table className="w-full text-xs">
                <tbody>
                  {result.per_dimension_delta.map((d) => (
                    <tr key={d.key} className="border-t border-hairline">
                      <td className="py-1 font-mono">{d.key}</td>
                      <td className="py-1 font-mono tabular">{d.a} → {d.b}</td>
                      <td className="py-1 font-mono tabular text-measured">{d.delta > 0 ? "+" : ""}{d.delta}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {result.per_family_delta && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-2">Per-family Δ (both n shown)</p>
              <table className="w-full text-xs">
                <tbody>
                  {result.per_family_delta.map((d) => (
                    <tr key={d.family} className="border-t border-hairline">
                      <td className="py-1 font-mono">{d.family}</td>
                      <td className="py-1 font-mono tabular text-muted">a n={d.a_n} · b n={d.b_n}</td>
                      <td className="py-1 font-mono tabular">{d.delta > 0 ? "+" : ""}{d.delta}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Modal>
  )
}
