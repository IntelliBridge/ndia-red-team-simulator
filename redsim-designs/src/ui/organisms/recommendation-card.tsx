"use client"

import { useState } from "react"
import { ExternalLink, Wrench } from "lucide-react"
import type { CandidateRecommendation } from "@/lib/api-types"
import { LabelBadge } from "@/ui/atoms/label-badge"
import { Button } from "@/ui/atoms/button"
import { RoleGated } from "@/ui/molecules/role-gated"
import { DefenseChooser } from "./defense-chooser"

/**
 * A candidate recommendation. Badged "candidate · not evaluated" until a verify
 * record exists, then "candidate · measured ΔMRI ±x at these settings". No
 * predicted / expected gain fields. [spec §18.3 panel 7, §16]
 */
export function RecommendationCard({
  rec,
  onVerified,
}: {
  rec: CandidateRecommendation
  onVerified?: () => void
}) {
  const [chooser, setChooser] = useState(false)
  const verified = rec.verify

  return (
    <div className="flex flex-col gap-2 rounded-md border border-hairline border-l-2 border-l-candidate bg-panel p-3">
      <div className="flex flex-wrap items-center gap-2">
        <LabelBadge variant={verified ? "measured" : "candidate"}>candidate</LabelBadge>
        <span className="text-xs text-muted">
          {verified ? (
            <>· measured ΔMRI {verified.delta_mri > 0 ? "+" : ""}{verified.delta_mri} at these settings</>
          ) : (
            <>· not evaluated</>
          )}
        </span>
      </div>
      <h4 className="text-sm font-medium text-foreground">{rec.title}</h4>
      <p className="text-xs text-muted">{rec.detail}</p>

      {verified && (
        <p className="rounded border border-inferred/40 bg-inferred/10 px-2 py-1 text-xs text-inferred">
          {verified.validation_state}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-2">triggered by</span>
        {rec.triggered_by.map((t) => (
          <a key={t} href={`#${t}`} className="font-mono text-primary hover:underline">{t}</a>
        ))}
        {rec.art_link && (
          <a href={rec.art_link} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
            ART defense <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>

      <RoleGated min="remediator">
        <div>
          <Button variant="outline" size="sm" onClick={() => setChooser(true)}>
            <Wrench className="h-3.5 w-3.5" /> Verify fix
          </Button>
        </div>
      </RoleGated>

      {chooser && (
        <DefenseChooser
          onClose={() => setChooser(false)}
          onVerified={() => { setChooser(false); onVerified?.() }}
          triggeredBy={rec.id}
        />
      )}
    </div>
  )
}
