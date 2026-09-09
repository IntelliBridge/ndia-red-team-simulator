"use client"

import Link from "next/link"
import { useProjects } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { Card } from "@/ui/atoms/card"
import { ErrorState } from "@/ui/molecules/states"
import { CardsSkeleton } from "@/ui/molecules/skeletons"

export default function ProjectsPage() {
  const { data, error, isLoading, mutate } = useProjects()

  return (
    <div>
      <PageHeader title="Projects" subtitle="Roster and per-project daily LLM budget." />
      {isLoading && <CardsSkeleton />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {(data ?? []).map((p) => (
          <Link key={p.slug} href={`/projects/${p.slug}/settings`}>
            <Card className="p-4 transition-colors hover:border-primary">
              <h3 className="text-sm font-medium text-foreground">{p.name}</h3>
              <p className="mt-1 font-mono text-xs text-muted">{p.slug}</p>
              <p className="mt-3 text-xs text-muted">{p.roster.length} members · ${p.daily_llm_budget_usd}/day LLM budget</p>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
