"use client"

import { useState } from "react"
import { AlertTriangle } from "lucide-react"
import { useDefenses } from "@/lib/hooks"
import { verifyFinding, ApiError } from "@/lib/api"
import { useSession } from "@/lib/session"
import { Modal } from "@/ui/molecules/modal"
import { PhaseBControl } from "@/ui/molecules/phase-b-control"
import { Select } from "@/ui/atoms/select"
import { Button } from "@/ui/atoms/button"

/** Defense chooser from /v1/defenses backing a Verify fix. [spec §18.3 panel 7, §18.4] */
export function DefenseChooser({
  onClose,
  onVerified,
  triggeredBy,
}: {
  onClose: () => void
  onVerified: () => void
  triggeredBy: string
}) {
  const { data: defenses } = useDefenses()
  const { session } = useSession()
  const [defenseId, setDefenseId] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<ApiError | null>(null)

  const phaseA = (defenses ?? []).filter((d) => d.phase === "A")
  const phaseB = (defenses ?? []).filter((d) => d.phase === "B")

  async function run() {
    setBusy(true)
    setErr(null)
    try {
      await verifyFinding(triggeredBy, defenseId, {}, session?.dev ? undefined : undefined)
      onVerified()
    } catch (e) {
      setErr(e instanceof ApiError ? e : new ApiError(0, { code: "unknown", message: String(e) }))
      setBusy(false)
    }
  }

  return (
    <Modal
      title="Verify fix — choose a defense"
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button variant="primary" size="sm" disabled={!defenseId || busy} onClick={run}>
            {busy ? "Running…" : "Apply & re-measure"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Select
          options={phaseA.map((d) => ({ value: d.id, label: d.name }))}
          placeholder="Select a Phase A defense"
          value={defenseId}
          onChange={(e) => setDefenseId(e.target.value)}
        />
        {phaseB.map((d) => (
          <PhaseBControl key={d.id} label={d.name} reason={d.reason ?? "Phase B"} />
        ))}
        {err && (
          <div className="flex items-start gap-2 rounded-md border border-critical/40 bg-critical/10 p-2 text-xs">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-critical" />
            <span><span className="font-mono">{err.status} {err.detail.code}</span> — {err.detail.message}</span>
          </div>
        )}
      </div>
    </Modal>
  )
}
