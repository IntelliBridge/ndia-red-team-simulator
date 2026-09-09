"use client";
// /tests/attacks/[id] — one adversarial-ML attack from the catalog: what it
// does, its parameters and bounds, the ATLAS techniques it maps to, and the
// findings it has produced.
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { PanelSection } from "@redsim/design-system";
import { FindingSummaryCard } from "@/components/finding-summary-card";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { api, type AttackInfo, type Finding } from "@/lib/api";

type AtlasTechnique = { id: string; name: string; url?: string };
type AttackRow = AttackInfo & {
  atlas_technique?: AtlasTechnique | null;
  atlas_techniques?: AtlasTechnique[];
  atlas_reason?: string | null;
  capabilities?: string[];
};
type AttacksResponse = { attacks: AttackRow[]; count?: number };

const attacksFetcher = (path: string) => api<AttacksResponse>(path);
const findingsFetcher = (path: string) => api<{ findings: Finding[]; count: number }>(path);

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 text-sm">{children}</dd>
    </div>
  );
}

export default function AttackDetailPage() {
  const authed = useRequireAuth();
  const params = useParams<{ id: string }>();
  const attackId = decodeURIComponent(params?.id ?? "");
  const { data, error, isLoading } = useSWR(authed ? "/v1/attacks" : null, attacksFetcher);
  const findings = useSWR(authed ? "/v1/findings" : null, findingsFetcher);
  if (!authed) return <p className="text-muted-foreground">Signing in…</p>;

  const attack = data?.attacks.find((a) => a.id === attackId);
  const techniques = attack?.atlas_techniques ?? (attack?.atlas_technique ? [attack.atlas_technique] : []);
  const related = (findings.data?.findings ?? []).filter((f) => f.schema_blob.ml?.attack_id === attackId);

  return (
    <div className="space-y-6">
      <div className="text-xs">
        <Link className="text-primary underline" href="/tests">
          ← All tests
        </Link>
      </div>
      {isLoading && <p className="text-muted-foreground">Loading…</p>}
      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load the attack catalog: {String(error)}
        </p>
      )}
      {data && !attack && (
        <p className="text-muted-foreground">
          No attack <span className="font-mono">{attackId}</span> in the catalog.
        </p>
      )}
      {attack && (
        <>
          <header>
            <div className="redsim-kicker">
              adversarial-ML attack · {attack.domain} · {attack.family}
            </div>
            <h1 className="text-2xl font-semibold">{attack.name}</h1>
            <div className="mt-1 font-mono text-xs text-muted-foreground">{attack.id}</div>
          </header>
          <PanelSection title="What this test does" eyebrow="description">
            <p className="text-sm leading-relaxed">{attack.description || "No description in the catalog."}</p>
          </PanelSection>
          <PanelSection title="Details" eyebrow="catalog">
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Status">
                {attack.status}
                {attack.reason ? <span className="text-muted-foreground"> · {attack.reason}</span> : null}
              </Fact>
              <Fact label="Access">{attack.access}</Fact>
              <Fact label="Needs model gradients">{attack.requires_gradients ? "yes (white-box)" : "no"}</Fact>
              <Fact label="Phase">{attack.phase}</Fact>
              <Fact label="ATLAS techniques">
                {techniques.length ? (
                  <ul className="space-y-0.5">
                    {techniques.map((t) => (
                      <li key={t.id}>
                        <span className="font-mono">{t.id}</span> {t.name}
                      </li>
                    ))}
                  </ul>
                ) : (
                  attack.atlas_reason ?? "—"
                )}
              </Fact>
              {attack.references.length > 0 && (
                <Fact label="References">
                  <ul className="space-y-0.5 break-all">
                    {attack.references.map((r) => (
                      <li key={r}>
                        {/^https?:\/\//.test(r) ? (
                          <a className="text-primary underline" href={r} target="_blank" rel="noreferrer">
                            {r}
                          </a>
                        ) : (
                          r
                        )}
                      </li>
                    ))}
                  </ul>
                </Fact>
              )}
            </dl>
          </PanelSection>
          <PanelSection title="Parameters" eyebrow={`${attack.params_schema.length} settings`}>
            {attack.params_schema.length === 0 ? (
              <p className="text-sm text-muted-foreground">This attack takes no parameters beyond the ε grid.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <tr>
                      <th className="py-1 pr-4">Name</th>
                      <th className="py-1 pr-4">Type</th>
                      <th className="py-1 pr-4">Default</th>
                      <th className="py-1 pr-4">Bounds</th>
                      <th className="py-1">Meaning</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attack.params_schema.map((p) => (
                      <tr key={p.name} className="border-t border-border align-top">
                        <td className="py-1 pr-4 font-mono">{p.name}</td>
                        <td className="py-1 pr-4">{p.type}</td>
                        <td className="py-1 pr-4 font-mono">{String(p.default)}</td>
                        <td className="py-1 pr-4 font-mono">
                          {p.min !== undefined || p.max !== undefined ? `${p.min ?? "…"} to ${p.max ?? "…"}` : "—"}
                        </td>
                        <td className="py-1 text-muted-foreground">{p.description ?? ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </PanelSection>
          <PanelSection title="Findings from this test" eyebrow={`${related.length} recorded`}>
            {findings.error && <p className="text-sm text-destructive">Failed to load findings.</p>}
            {!findings.error && related.length === 0 && (
              <p className="text-sm text-muted-foreground">No finding recorded from this attack yet.</p>
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
