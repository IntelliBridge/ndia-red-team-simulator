"use client";
// /tests/probes/[id] — one LLM probe from the catalog: what it tries, how it
// is judged, where it is documented, and the findings it has produced.
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { PanelSection } from "@redsim/design-system";
import { FindingSummaryCard } from "@/components/finding-summary-card";
import { useProbeCatalog } from "@/hooks/useLlm";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { api, type Finding } from "@/lib/api";

const findingsFetcher = (path: string) => api<{ findings: Finding[]; count: number }>(path);

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="redsim-kicker">{label}</dt>
      <dd className="m-0 mt-0.5 text-sm text-ink-1">{children}</dd>
    </div>
  );
}

export default function ProbeDetailPage() {
  const authed = useRequireAuth();
  const params = useParams<{ id: string }>();
  const probeId = decodeURIComponent(params?.id ?? "");
  const { data: catalog, error, isLoading } = useProbeCatalog(authed);
  const findings = useSWR(authed ? "/v1/findings" : null, findingsFetcher);
  if (!authed) return <p className="text-ink-3">Signing in…</p>;

  const probe = catalog?.probes.find((p) => p.id === probeId);
  const related = (findings.data?.findings ?? []).filter((f) => f.schema_blob.llm?.probe_id === probeId);

  return (
    <div className="space-y-6">
      <div className="text-xs">
        <Link className="redsim-link" href="/tests">
          ← All tests
        </Link>
      </div>
      {isLoading && <p className="text-ink-3">Loading…</p>}
      {error && (
        <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load the probe catalog: {String(error)}
        </p>
      )}
      {catalog && !probe && (
        <p className="text-ink-3">
          No probe <span className="font-mono">{probeId}</span> in the catalog.
        </p>
      )}
      {probe && (
        <>
          <header>
            <div className="redsim-kicker">LLM probe · {probe.family}</div>
            <h1 className="text-2xl font-semibold">{probe.short_id}</h1>
            <div className="mt-1 font-mono text-xs text-ink-3">{probe.id}</div>
          </header>
          <PanelSection title="What this test does" eyebrow="goal">
            <p className="redsim-prose m-0">
              Sends the model prompts written to <strong>{probe.goal}</strong>. A detector then judges each
              reply; a reply that goes along with the attempt counts as a hit. redsim reports a finding when the
              hit rate crosses the threshold set on the run.
            </p>
          </PanelSection>
          <PanelSection title="Details" eyebrow="catalog">
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Status">
                {probe.status ?? "offline"}
                {probe.reason ? <span className="text-ink-3"> · {probe.reason}</span> : null}
              </Fact>
              <Fact label="Tier">{probe.tier ?? "—"}</Fact>
              <Fact label="Module">
                <span className="font-mono">{probe.module}</span>
              </Fact>
              <Fact label="Primary detector">
                <span className="font-mono">{probe.primary_detector}</span>
                {probe.detector_offline ? " (runs offline)" : " (needs the extended detectors)"}
              </Fact>
              <Fact label="Extended detectors">
                {probe.extended_detectors.length ? (
                  <span className="font-mono">{probe.extended_detectors.join(", ")}</span>
                ) : (
                  "—"
                )}
              </Fact>
              <Fact label="In sets">
                {probe.sets.length ? (
                  <span className="flex flex-wrap gap-1">
                    {probe.sets.map((s) => (
                      <span key={s} className="redsim-chip font-mono">{s}</span>
                    ))}
                  </span>
                ) : (
                  "—"
                )}
              </Fact>
              {probe.data_files.length > 0 && (
                <Fact label="Prompt data files">
                  <span className="font-mono">{probe.data_files.join(", ")}</span>
                </Fact>
              )}
              {probe.upstream_licence_note && <Fact label="Upstream licence">{probe.upstream_licence_note}</Fact>}
            </dl>
          </PanelSection>
          <PanelSection title="Findings from this test" eyebrow={`${related.length} recorded`}>
            {findings.error && <p className="text-sm text-destructive">Failed to load findings.</p>}
            {!findings.error && related.length === 0 && (
              <p className="text-sm text-ink-3">No finding recorded from this probe yet.</p>
            )}
            {related.length > 0 && (
              <ul className="space-y-3">
                {related.map((f) => (
                  <FindingSummaryCard key={f.id} finding={f} leadMax={320} />
                ))}
              </ul>
            )}
          </PanelSection>
        </>
      )}
    </div>
  );
}
