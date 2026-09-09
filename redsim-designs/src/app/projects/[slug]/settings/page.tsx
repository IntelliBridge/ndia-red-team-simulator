"use client"

import { useProjects } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { PanelSection } from "@/ui/molecules/panel-section"
import { DetailSkeleton } from "@/ui/molecules/skeletons"
import { EmptyState } from "@/ui/molecules/states"

export default function ProjectSettingsPage({ params }: { params: { slug: string } }) {
  const { slug } = params
  const { data, isLoading } = useProjects()
  const project = data?.find((p) => p.slug === slug)

  if (isLoading) return <DetailSkeleton />
  if (!project) return <EmptyState title="Project not found" actionHref="/projects" actionLabel="Back to Projects" />

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title={project.name} subtitle={project.slug} />
      <PanelSection title="Roster">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[11px] uppercase tracking-wide text-muted-2">
              <th className="py-1 text-left">User</th>
              <th className="py-1 text-left">Role</th>
            </tr>
          </thead>
          <tbody>
            {project.roster.map((m) => (
              <tr key={m.user} className="border-t border-hairline">
                <td className="py-1.5 font-mono text-xs">{m.user}</td>
                <td className="py-1.5 font-mono text-xs text-muted">{m.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </PanelSection>
      <PanelSection title="Daily LLM budget">
        <p className="font-mono text-2xl text-foreground tabular">${project.daily_llm_budget_usd}<span className="text-sm text-muted">/day</span></p>
      </PanelSection>
    </div>
  )
}
