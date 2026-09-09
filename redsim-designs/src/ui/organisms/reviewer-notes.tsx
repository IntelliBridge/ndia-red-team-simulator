"use client"

import { useState } from "react"
import { patchReviewerNotes, ApiError } from "@/lib/api"
import { useSession } from "@/lib/session"
import { relativeTime } from "@/lib/utils"
import { Textarea } from "@/ui/atoms/input"
import { Button } from "@/ui/atoms/button"
import { RoleGated } from "@/ui/molecules/role-gated"

/** PATCH /v1/runs/{id}/reviewer-notes (remediator). Shows last author + time. [spec §18.3 panel 10] */
export function ReviewerNotes({ runId, initial, lastAuthor, lastAt }: { runId: string; initial?: string; lastAuthor?: string; lastAt?: string }) {
  const { session } = useSession()
  const [notes, setNotes] = useState(initial ?? "")
  const [busy, setBusy] = useState(false)
  const [saved, setSaved] = useState(false)
  const [err, setErr] = useState<ApiError | null>(null)

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    try {
      await patchReviewerNotes(runId, notes, session?.dev ? undefined : undefined)
      setSaved(true)
    } catch (e) {
      setErr(e instanceof ApiError ? e : new ApiError(0, { code: "unknown", message: String(e) }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-2">
      {(lastAuthor || lastAt) && (
        <p className="text-[11px] text-muted-2">Last edited by {lastAuthor ?? "—"} {lastAt ? relativeTime(lastAt) : ""}</p>
      )}
      <RoleGated min="remediator" fallback={<p className="whitespace-pre-wrap text-sm text-muted">{notes || "No reviewer notes."}</p>}>
        <Textarea rows={4} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Notes for human review…" />
        <div className="flex items-center gap-2">
          <Button variant="primary" size="sm" onClick={save} disabled={busy}>Save notes</Button>
          {saved && <span className="text-xs text-robust">Saved</span>}
          {err && <span className="font-mono text-xs text-critical">{err.status} {err.detail.code}</span>}
        </div>
      </RoleGated>
    </div>
  )
}
