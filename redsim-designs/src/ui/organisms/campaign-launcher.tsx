"use client"

import { useMemo, useState } from "react"
import { useRouter } from "next/navigation"
import { AlertTriangle, Rocket } from "lucide-react"
import type { AttackInfo, ModelTarget } from "@/lib/api-types"
import { useAttacks, useCapabilities, useDatasets, useDefenses } from "@/lib/hooks"
import { startCampaign, ApiError } from "@/lib/api"
import { roleAtLeast, useSession } from "@/lib/session"
import { PanelSection } from "@/ui/molecules/panel-section"
import { PhaseBControl } from "@/ui/molecules/phase-b-control"
import { Checkbox } from "@/ui/atoms/checkbox"
import { Input } from "@/ui/atoms/input"
import { Select } from "@/ui/atoms/select"
import { Button } from "@/ui/atoms/button"
import { LabelBadge } from "@/ui/atoms/label-badge"

const EPS_OPTIONS = [0.005, 0.01, 0.03, 0.05, 0.1, 0.2]
const DEFAULT_EPS = [0.01, 0.03, 0.1]

export function CampaignLauncher({ model }: { model: ModelTarget }) {
  const router = useRouter()
  const { session } = useSession()
  const { data: attacks } = useAttacks()
  const { data: datasets } = useDatasets()
  const { data: caps } = useCapabilities()
  useDefenses()

  const gradients = model.manifest?.gradients ?? false

  // Disabled-with-reason gate for the whole launcher. [spec §18.2]
  const disabledReason = useMemo(() => {
    if (model.status !== "available") return `Model is ${model.status}${model.refusal_reason ? ` — ${model.refusal_reason}` : ""}.`
    if (caps && !caps.worker_ml_extra) return "The ML worker (worker_ml_extra) is not available."
    if (!roleAtLeast(session?.role, "scanner")) return "Your role is below scanner; the API will also reject this."
    return null
  }, [model, caps, session])

  const [selectedAttacks, setSelectedAttacks] = useState<string[]>(["fgsm", "pgd"])
  const [epsGrid, setEpsGrid] = useState<number[]>(DEFAULT_EPS)
  const [refEps, setRefEps] = useState<number>(0.03)
  const [threshold, setThreshold] = useState(0.2)
  const [datasetId, setDatasetId] = useState(model.dataset_id ?? "")
  const [n, setN] = useState(200)
  const [seed, setSeed] = useState(1337)
  const [control, setControl] = useState(true)
  const [explainK, setExplainK] = useState(6)
  const [narrative, setNarrative] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<ApiError | null>(null)

  const modalityAttacks = (attacks ?? []).filter((a) => a.modality.includes(model.modality as "image" | "tabular") || a.id === "noise_control")
  const phaseA = modalityAttacks.filter((a) => a.phase === "A")
  const phaseB = modalityAttacks.filter((a) => a.phase === "B")

  function attackDisabledReason(a: AttackInfo): string | null {
    if (a.phase === "B") return a.reason ?? "Phase B"
    if (a.requires_gradients && !gradients) return "target has no differentiable estimator"
    return null
  }

  function toggleAttack(id: string) {
    setSelectedAttacks((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))
  }

  function toggleEps(e: number) {
    setEpsGrid((g) => {
      const next = g.includes(e) ? g.filter((x) => x !== e) : [...g, e].sort((a, b) => a - b)
      if (!next.includes(refEps) && next.length) setRefEps(next[0])
      return next
    })
  }

  const llmConfigured = caps?.llm_narrative.configured ?? false
  const weights = caps?.scoring_weights

  async function submit() {
    setBusy(true)
    setErr(null)
    const dataset = datasets?.find((d) => d.id === datasetId)
    try {
      const res = await startCampaign(model.id, {
        attacks: control ? [...selectedAttacks, "noise_control"] : selectedAttacks,
        eps_grid: epsGrid,
        reference_eps: refEps,
        finding_asr_threshold: threshold,
        dataset_id: datasetId,
        dataset_revision: dataset?.revision,
        n,
        seed,
        noise_control: control,
        explain_k: explainK,
        llm_narrative: narrative && llmConfigured,
        scoring_weights: weights,
      })
      router.push(`/runs/${res.run_id}`)
    } catch (e) {
      setErr(e instanceof ApiError ? e : new ApiError(0, { code: "unknown", message: String(e) }))
      setBusy(false)
    }
  }

  return (
    <PanelSection title="Campaign launcher" subtitle="Configure an evasion measurement. Options come from the API, never a hard-coded list.">
      {disabledReason && (
        <div className="mb-4 flex items-center gap-2 rounded-md border border-degraded/40 bg-degraded/10 p-3 text-sm text-degraded">
          <AlertTriangle className="h-4 w-4" /> {disabledReason}
        </div>
      )}

      <fieldset disabled={!!disabledReason || busy} className="flex flex-col gap-5">
        {/* Attacks */}
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-2">Attacks</h3>
          <div className="flex flex-col gap-1.5">
            {phaseA.map((a) => {
              const dr = attackDisabledReason(a)
              return (
                <div key={a.id} className="flex items-start justify-between gap-3 rounded-md border border-hairline bg-panel px-3 py-2">
                  <Checkbox
                    label={
                      <span>
                        <span className="font-mono text-foreground">{a.id}</span>{" "}
                        <span className="text-muted">· {a.description}</span>
                        {dr && <span className="ml-1 text-degraded">— {dr}</span>}
                      </span>
                    }
                    checked={selectedAttacks.includes(a.id)}
                    disabled={!!dr}
                    onChange={() => toggleAttack(a.id)}
                  />
                  <span className="shrink-0 font-mono text-[10px] text-muted-2">{a.box}</span>
                </div>
              )
            })}
            {phaseB.map((a) => (
              <PhaseBControl key={a.id} label={`${a.id} · ${a.description}`} reason={a.reason ?? "Phase B"} />
            ))}
          </div>
        </div>

        {/* eps grid + reference */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-2">ε grid</h3>
            <div className="flex flex-wrap gap-1.5">
              {EPS_OPTIONS.map((e) => (
                <button
                  key={e}
                  type="button"
                  onClick={() => toggleEps(e)}
                  className={`rounded border px-2 py-1 font-mono text-xs ${epsGrid.includes(e) ? "border-primary bg-primary/10 text-primary" : "border-hairline text-muted"}`}
                >
                  {e}
                </button>
              ))}
            </div>
          </div>
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-2">Reference ε</h3>
            <div className="flex flex-wrap gap-3">
              {epsGrid.map((e) => (
                <label key={e} className="inline-flex items-center gap-1.5 font-mono text-xs text-foreground">
                  <input type="radio" name="refeps" checked={refEps === e} onChange={() => setRefEps(e)} className="accent-[var(--primary)]" />
                  {e}
                </label>
              ))}
            </div>
            <p className="mt-1 text-[11px] text-muted-2">Reference ε must be one of the selected grid values.</p>
          </div>
        </div>

        {/* threshold */}
        <div>
          <label className="flex flex-col gap-1 text-xs text-muted">
            finding_asr_threshold
            <Input type="number" step="0.05" min={0} max={1} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} className="w-32" />
          </label>
          <p className="mt-1 text-[11px] text-muted-2">Derived severities are computed relative to this threshold.</p>
        </div>

        {/* dataset */}
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-2">Dataset</h3>
          <Select
            options={(datasets ?? [])
              .filter((d) => d.modality === model.modality)
              .map((d) => ({ value: d.id, label: `${d.name} · ${d.license} · ${d.revision}${d.ci_fixture ? " · CI fixture — not the demo dataset" : ""}` }))}
            placeholder="Select dataset"
            value={datasetId}
            onChange={(e) => setDatasetId(e.target.value)}
          />
        </div>

        {/* sample size / seed / control / explain_k */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <label className="flex flex-col gap-1 text-xs text-muted">
            sample size (50–500)
            <Input type="number" min={50} max={500} value={n} onChange={(e) => setN(Number(e.target.value))} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">
            seed
            <Input type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">
            explain_k
            <Input type="number" min={0} value={explainK} onChange={(e) => setExplainK(Number(e.target.value))} />
          </label>
          <div className="flex flex-col gap-1 text-xs text-muted">
            benign noise control
            <Checkbox label="on" checked={control} onChange={() => setControl((c) => !c)} />
            <span className="text-[11px] text-muted-2">A matched-ε random-noise baseline that separates adversarial effect from noise.</span>
          </div>
        </div>

        {/* LLM narrative */}
        <div>
          {llmConfigured ? (
            <Checkbox
              label={<span>LLM narrative of rule outputs (Pythia <span className="font-mono">{caps?.llm_narrative.model_id}</span>)</span>}
              checked={narrative}
              onChange={() => setNarrative((v) => !v)}
            />
          ) : (
            <p className="text-xs text-muted-2">LLM narrative: Pythia not configured — rule outputs only.</p>
          )}
        </div>

        {/* scoring weights read-only */}
        {weights && (
          <div className="rounded-md border border-hairline bg-panel-2/40 p-3">
            <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-2">Scoring weights (read-only)</p>
            <p className="font-mono text-xs text-muted">
              acc {weights.acc} · asr {weights.asr} · eps {weights.eps} · conf {weights.conf} · expl {weights.expl}
            </p>
          </div>
        )}

        {err && (
          <div className="flex items-start gap-2 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-critical" />
            <div>
              <p className="font-mono text-xs text-critical">{err.status} {err.detail.code}</p>
              <p className="text-xs text-foreground">{err.detail.message}</p>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between gap-3">
          <p className="text-[11px] text-muted-2">
            Selected: {selectedAttacks.length || 0} attack(s){control ? " + control" : ""} · {epsGrid.length} ε value(s)
          </p>
          <Button variant="primary" onClick={submit} disabled={busy || !datasetId || selectedAttacks.length === 0 || epsGrid.length === 0}>
            <Rocket className="h-4 w-4" /> {busy ? "Submitting…" : "Start campaign"}
          </Button>
        </div>
      </fieldset>
    </PanelSection>
  )
}
