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
    <li {...rowLink(href)} className={`border-b border-line py-4 last:border-0 ${rowLink("").className}`}>
      <div className="flex flex-wrap items-center gap-3">
        <SeverityChip level={f.severity} />
        <a className="text-base font-medium text-ink-1 hover:underline" href={href}>
          {f.schema_blob.title ?? "—"}
        </a>
        <span className="redsim-chip ml-auto">
          {f.status}
        </span>
      </div>
      {lead && <p className="redsim-prose mt-2 text-[0.9375rem]">{lead}</p>}
      {!lead && f.schema_blob.description && (
        <p className="redsim-prose mt-2 text-[0.9375rem] text-ink-3">{f.schema_blob.description}</p>
      )}
      <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-xs [&_dd]:m-0 [&_dd]:text-ink-1">
        <div>
          <dt className="redsim-kicker">Finding</dt>
          <dd className="whitespace-nowrap font-mono">
            <a className="redsim-link" href={href}>
              {f.id}
            </a>
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">Model</dt>
          <dd className="whitespace-nowrap">
            {model ? (
              model.targetId ? (
                <a className="redsim-link" href={`/models/${model.targetId}`}>
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
          <dt className="redsim-kicker">Run</dt>
          <dd className="whitespace-nowrap font-mono">
            <a className="redsim-link" href={`/runs/${f.run_id}`}>
              {f.run_id}
            </a>
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">Attack or probe</dt>
          <dd>{f.schema_blob.ml?.attack_id ?? f.schema_blob.llm?.probe_id ?? "—"}</dd>
        </div>
        <div>
          <dt className="redsim-kicker">Source</dt>
          <dd className="text-ink-3">{f.source_tool ?? "—"}</dd>
        </div>
      </dl>
    </li>
  );
}
