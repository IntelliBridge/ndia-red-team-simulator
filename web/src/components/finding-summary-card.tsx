"use client";
import { SeverityChip } from "@redsim/design-system";
import type { Finding } from "@/lib/api";
import { findingLead, findingModel } from "@/lib/finding-description";
import { rowLink } from "@/lib/row-link";

/**
 * One finding as a card: severity, title and status on top, the plain-language
 * account as a wrapped paragraph, then the facts (finding and run ids, the
 * attack or probe, the source). The whole card opens the finding; the title
 * and the id are real links for keyboard and screen-reader users. Shared by
 * /findings and the dashboard so both read the same way.
 */
export function FindingSummaryCard({ finding: f, leadMax = 600 }: { finding: Finding; leadMax?: number }) {
  const lead = findingLead(f.schema_blob.description, leadMax);
  const href = `/findings/${f.id}`;
  const model = findingModel(f.schema_blob);
  return (
    <li {...rowLink(href)} className={`rounded-md border border-border bg-card p-4 ${rowLink("").className}`}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityChip level={f.severity} />
        <a className="text-base font-medium hover:underline" href={href}>
          {f.schema_blob.title ?? "—"}
        </a>
        <span className="ml-auto rounded-sm border border-border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {f.status}
        </span>
      </div>
      {lead && <p className="mt-2 text-sm leading-relaxed text-foreground/90">{lead}</p>}
      {!lead && f.schema_blob.description && (
        <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{f.schema_blob.description}</p>
      )}
      <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-xs">
        <div>
          <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Finding</dt>
          <dd className="whitespace-nowrap font-mono">
            <a className="text-primary underline" href={href}>
              {f.id}
            </a>
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Model</dt>
          <dd className="whitespace-nowrap">
            {model ? (
              model.targetId ? (
                <a className="text-primary underline" href={`/models/${model.targetId}`}>
                  {model.label}
                </a>
              ) : (
                model.label
              )
            ) : (
              "—"
            )}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Run</dt>
          <dd className="whitespace-nowrap font-mono">
            <a className="text-primary underline" href={`/runs/${f.run_id}`}>
              {f.run_id}
            </a>
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Attack or probe</dt>
          <dd>{f.schema_blob.ml?.attack_id ?? f.schema_blob.llm?.probe_id ?? "—"}</dd>
        </div>
        <div>
          <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Source</dt>
          <dd className="text-muted-foreground">{f.source_tool ?? "—"}</dd>
        </div>
      </dl>
    </li>
  );
}
