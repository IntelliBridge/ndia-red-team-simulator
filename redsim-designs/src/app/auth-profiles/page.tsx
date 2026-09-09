"use client"

import { useAuthProfiles } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { PanelSection } from "@/ui/molecules/panel-section"
import { TableSkeleton } from "@/ui/molecules/skeletons"
import { ErrorState } from "@/ui/molecules/states"

export default function AuthProfilesPage() {
  const { data, error, isLoading, mutate } = useAuthProfiles()

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Auth Profiles"
        subtitle="Retained. No Phase A feature uses an auth profile."
      />
      {isLoading && <TableSkeleton cols={2} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && (
        <PanelSection title="Profiles">
          <ul className="flex flex-col gap-1.5">
            {data.map((p) => (
              <li key={p.id} className="flex items-center justify-between rounded-md border border-hairline bg-panel px-3 py-2 text-sm">
                <span className="text-foreground">{p.name}</span>
                <span className="font-mono text-xs text-muted">{p.kind}</span>
              </li>
            ))}
          </ul>
        </PanelSection>
      )}
    </div>
  )
}
