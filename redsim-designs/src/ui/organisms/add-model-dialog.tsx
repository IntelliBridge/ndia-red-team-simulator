"use client"

import { useState } from "react"
import { AlertTriangle } from "lucide-react"
import { useDatasets, useCapabilities } from "@/lib/hooks"
import { api, ApiError } from "@/lib/api"
import { useSession } from "@/lib/session"
import type { ModelFormat } from "@/lib/api-types"
import { Modal } from "@/ui/molecules/modal"
import { PhaseBControl } from "@/ui/molecules/phase-b-control"
import { Button } from "@/ui/atoms/button"
import { Input } from "@/ui/atoms/input"
import { Select } from "@/ui/atoms/select"
import { LabelBadge } from "@/ui/atoms/label-badge"

type Tab = "bundled" | "upload" | "endpoint"

const FORMATS: { value: ModelFormat; label: string }[] = [
  { value: "onnx", label: "onnx" },
  { value: "torch_state_dict", label: "torch_state_dict" },
  { value: "safetensors_state_dict", label: "safetensors_state_dict" },
]

const STATE_DICT: ModelFormat[] = ["torch_state_dict", "safetensors_state_dict"]

/** Refusal rules shown BEFORE a file is chosen. [spec §4 add-model, §9] */
const REFUSAL_RULES = [
  "413 model_too_large — artifact exceeds the size limit.",
  "415 unsupported_model_format — only onnx, torch_state_dict, safetensors_state_dict.",
  "415 pickle_refused — serialized pickle artifacts are rejected for safety.",
  "422 architecture_required — a state_dict upload must name its architecture.",
]

export function AddModelDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [tab, setTab] = useState<Tab>("bundled")
  const { data: datasets } = useDatasets()
  const { data: caps } = useCapabilities()
  const { session } = useSession()

  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<ApiError | null>(null)

  const [bundledId, setBundledId] = useState("")
  const [name, setName] = useState("")
  const [modality, setModality] = useState<"image" | "tabular">("image")
  const [format, setFormat] = useState<ModelFormat>("onnx")
  const [architecture, setArchitecture] = useState("")
  const [license, setLicense] = useState("")
  const [datasetId, setDatasetId] = useState("")

  const endpointReason =
    caps?.phase_b_reasons?.endpoint ?? "Phase B: remote model endpoints are not yet supported."

  async function submit(body: unknown) {
    setBusy(true)
    setErr(null)
    try {
      await api("/v1/models", { method: "POST", body, token: session?.dev ? undefined : undefined })
      onCreated()
    } catch (e) {
      if (e instanceof ApiError) setErr(e)
      else setErr(new ApiError(0, { code: "unknown", message: String(e) }))
    } finally {
      setBusy(false)
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "bundled", label: "Bundled sample" },
    { id: "upload", label: "Upload artifact" },
    { id: "endpoint", label: "Connect endpoint" },
  ]

  return (
    <Modal title="Add model" onClose={onClose} wide>
      <div className="mb-4 flex gap-1 border-b border-hairline">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === t.id ? "border-primary text-foreground" : "border-transparent text-muted hover:text-foreground"}`}
          >
            {t.label}
            {t.id === "endpoint" && <LabelBadge variant="phase-b" className="ml-2">Phase B</LabelBadge>}
          </button>
        ))}
      </div>

      {err && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-critical" />
          <div>
            <p className="font-mono text-xs text-critical">{err.status} {err.detail.code}</p>
            <p className="text-xs text-foreground">{err.detail.message}</p>
          </div>
        </div>
      )}

      {tab === "bundled" && (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-muted">Pick a bundled open dataset model served by the API.</p>
          <Select
            options={(datasets ?? []).filter((d) => !d.ci_fixture).map((d) => ({ value: d.id, label: `${d.name} (${d.modality})` }))}
            placeholder="Select a bundled dataset model"
            value={bundledId}
            onChange={(e) => setBundledId(e.target.value)}
          />
          <div className="flex justify-end">
            <Button variant="primary" size="sm" disabled={!bundledId || busy} onClick={() => submit({ source: "bundled", dataset_id: bundledId })}>
              Register
            </Button>
          </div>
        </div>
      )}

      {tab === "upload" && (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            submit({ source: "uploaded", name, modality, declared_format: format, architecture: STATE_DICT.includes(format) ? architecture : undefined, license_statement: license, dataset_id: datasetId })
          }}
        >
          <div className="rounded-md border border-hairline bg-panel-2/40 p-3">
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-2">Refusal rules</p>
            <ul className="flex flex-col gap-1 font-mono text-[11px] text-muted">
              {REFUSAL_RULES.map((r) => <li key={r}>{r}</li>)}
            </ul>
          </div>

          <label className="flex flex-col gap-1 text-xs text-muted">
            file
            <Input type="file" required />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">
            name
            <Input value={name} onChange={(e) => setName(e.target.value)} required placeholder="my-classifier" />
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1 text-xs text-muted">
              modality
              <Select options={[{ value: "image", label: "image" }, { value: "tabular", label: "tabular" }]} value={modality} onChange={(e) => setModality(e.target.value as "image" | "tabular")} />
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted">
              declared_format
              <Select options={FORMATS} value={format} onChange={(e) => setFormat(e.target.value as ModelFormat)} />
            </label>
          </div>
          {STATE_DICT.includes(format) && (
            <label className="flex flex-col gap-1 text-xs text-muted">
              architecture (required for state_dict formats)
              <Input value={architecture} onChange={(e) => setArchitecture(e.target.value)} required placeholder="resnet18" />
            </label>
          )}
          <label className="flex flex-col gap-1 text-xs text-muted">
            license_statement (required)
            <Input value={license} onChange={(e) => setLicense(e.target.value)} required placeholder="CC BY 4.0" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">
            dataset_id (required)
            <Select options={(datasets ?? []).map((d) => ({ value: d.id, label: d.name }))} placeholder="Select dataset" value={datasetId} onChange={(e) => setDatasetId(e.target.value)} />
          </label>
          <div className="flex justify-end">
            <Button type="submit" variant="primary" size="sm" disabled={busy}>Upload &amp; validate</Button>
          </div>
        </form>
      )}

      {tab === "endpoint" && (
        <PhaseBControl label="Connect a remote model endpoint" reason={endpointReason} />
      )}
    </Modal>
  )
}
