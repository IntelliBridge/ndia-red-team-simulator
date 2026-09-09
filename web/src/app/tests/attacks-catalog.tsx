"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { LabelBadge, PanelSection } from "@redsim/design-system";
import {
  api,
  type AttackInfo,
  type DefenseInfo,
  type ModelTarget,
} from "@/lib/api";
import { useModels } from "@/hooks/useModels";
import { rowLink } from "@/lib/row-link";
import { useRoles } from "@/hooks/useRoles";

/**
 * Adversarial-ML attack and defense catalogue (second tab of /tests).
 *
 * Self-contained: fetches GET /v1/attacks, GET /v1/defenses and the model
 * registry itself. The useMlCatalog hooks are not reused here because they
 * discard the response envelope (the ATLAS citation lives there) and this tab
 * needs the full row shape (domains, atlas_*), so the SWR keys below are
 * deliberately distinct from the hooks' keys to keep the caches apart.
 *
 * "Run on…" hands off to the model page with `?attacks=a,b,c`; that page
 * preselects the ids in its campaign launcher.
 */

type AtlasTechnique = {
  id: string;
  name: string;
  family?: string | null;
  parent?: string | null;
  atlas_version?: string;
};
type CatalogAttack = AttackInfo & {
  domains?: string[];
  atlas_technique?: AtlasTechnique | null;
  atlas_techniques?: AtlasTechnique[];
  atlas_reason?: string | null;
  capabilities?: string[];
};
type AtlasCitation = {
  release?: string;
  version?: string;
  published?: string;
  attribution?: string;
  license?: string;
};
type AttacksResponse = {
  attacks?: CatalogAttack[];
  items?: CatalogAttack[];
  count?: number;
  plugins?: { enabled: boolean };
  atlas?: AtlasCitation | null;
};
type CatalogDefense = DefenseInfo & {
  kind?: string;
  description?: string;
  modalities?: string[];
};
type DefensesResponse = {
  defenses?: CatalogDefense[];
  items?: CatalogDefense[];
  count?: number;
};
type ModelRow = ModelTarget & {
  registered?: boolean;
  available_attacks?: string[] | null;
};

const FAMILY_ORDER = ["evasion", "control"];
const FAMILY_BLURB: Record<string, string> = {
  evasion:
    "Perturb inputs at inference time so the model misclassifies or misses them.",
  control:
    "Benign noise at the same budgets: the baseline an evasion result is judged against.",
};

const domainsOf = (a: CatalogAttack): string[] =>
  a.domains && a.domains.length > 0 ? a.domains : a.domain ? [a.domain] : [];

const isRunnable = (m: ModelRow) =>
  m.registered !== false && m.status === "available" && m.modality !== "llm";

const compatible = (a: CatalogAttack, m: ModelRow) =>
  domainsOf(a).includes(m.modality) ||
  (Array.isArray(m.available_attacks) && m.available_attacks.includes(a.id));

const runHref = (modelId: string, attackIds: string[]) =>
  `/models/${encodeURIComponent(modelId)}?attacks=${attackIds
    .map(encodeURIComponent)
    .join(",")}`;

const Chip = ({ children }: { children: React.ReactNode }) => (
  <span className="redsim-chip">
    {children}
  </span>
);

const selectClass = "redsim-input py-1 text-xs";

export function AttacksCatalog() {
  const router = useRouter();
  const { roles } = useRoles();
  const projectId = Object.keys(roles)[0] ?? "default";
  const {
    data: attacksResp,
    error: attacksError,
    isLoading: attacksLoading,
  } = useSWR(["/v1/attacks", "catalog"], () =>
    api<AttacksResponse>("/v1/attacks"),
  );
  const { data: defensesResp, error: defensesError } = useSWR(
    ["/v1/defenses", "catalog"],
    () => api<DefensesResponse>("/v1/defenses"),
  );
  const { data: modelRows = [], error: modelsError } = useModels(projectId);

  const attacks: CatalogAttack[] = useMemo(
    () => attacksResp?.attacks ?? attacksResp?.items ?? [],
    [attacksResp],
  );
  const defenses: CatalogDefense[] =
    defensesResp?.defenses ?? defensesResp?.items ?? [];
  const models = (modelRows as ModelRow[]).filter(isRunnable);

  const [search, setSearch] = useState("");
  const [modality, setModality] = useState("");
  const [family, setFamily] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [rowModel, setRowModel] = useState<Record<string, string>>({});
  const [bulkModel, setBulkModel] = useState("");
  const [bulkNote, setBulkNote] = useState("");

  const families = useMemo(() => {
    const seen = new Set(attacks.map((a) => a.family as string));
    return [
      ...FAMILY_ORDER.filter((f) => seen.has(f)),
      ...[...seen].filter((f) => !FAMILY_ORDER.includes(f)).sort(),
    ];
  }, [attacks]);
  const modalities = useMemo(
    () => [...new Set(attacks.flatMap(domainsOf))].sort(),
    [attacks],
  );
  const availableCount = attacks.filter((a) => a.status === "available").length;

  const q = search.trim().toLowerCase();
  const visible = attacks.filter((a) => {
    if (modality && !domainsOf(a).includes(modality)) return false;
    if (family && a.family !== family) return false;
    if (!q) return true;
    const hay = [
      a.id,
      a.name,
      a.description,
      a.atlas_technique?.id,
      ...(a.atlas_techniques ?? []).map((t) => `${t.id} ${t.name}`),
      ...(a.capabilities ?? []),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
  const byFamily = families
    .map((f) => ({ family: f, rows: visible.filter((a) => a.family === f) }))
    .filter((g) => g.rows.length > 0);

  const toggle = (id: string, on: boolean) =>
    setSelected((s) => (on ? [...new Set([...s, id])] : s.filter((x) => x !== id)));

  const selectedAttacks = attacks.filter((a) => selected.includes(a.id));
  const bulkTarget = models.find((m) => m.id === bulkModel);
  const bulkCompatible = bulkTarget
    ? selectedAttacks.filter((a) => compatible(a, bulkTarget))
    : [];
  const bulkSkipped = bulkTarget
    ? selectedAttacks.filter((a) => !compatible(a, bulkTarget))
    : [];
  const runBulk = () => {
    if (!bulkTarget) return;
    if (bulkCompatible.length === 0) {
      setBulkNote(
        `None of the selected attacks apply to ${bulkTarget.name} (${bulkTarget.modality}).`,
      );
      return;
    }
    router.push(
      runHref(
        bulkTarget.id,
        bulkCompatible.map((a) => a.id),
      ),
    );
  };

  const atlas = attacksResp?.atlas ?? null;
  const catalogError = attacksError ?? defensesError;

  return (
    <div className="space-y-6">
      <PanelSection title="What the platform can run" eyebrow="summary">
        {attacksLoading && !attacksResp ? (
          <p className="text-sm text-ink-3">Loading attack catalog…</p>
        ) : catalogError ? (
          <p className="text-sm text-destructive">
            Attack catalog unavailable. Retry after the catalog service is
            restored.
          </p>
        ) : (
          <dl className="m-0 grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
            <div className="redsim-stat">
              <dt className="redsim-kicker">attacks available</dt>
              <dd className="redsim-numeral m-0 text-3xl">
                {availableCount}
                {attacks.length !== availableCount ? (
                  <span className="ml-1 text-xs font-normal tracking-normal text-ink-3">
                    of {attacks.length}
                  </span>
                ) : null}
              </dd>
            </div>
            <div className="redsim-stat">
              <dt className="redsim-kicker">families</dt>
              <dd className="m-0 mt-1 flex flex-wrap gap-1">
                {families.map((f) => (
                  <Chip key={f}>{f}</Chip>
                ))}
              </dd>
            </div>
            <div className="redsim-stat">
              <dt className="redsim-kicker">modalities covered</dt>
              <dd className="m-0 mt-1 flex flex-wrap gap-1">
                {modalities.map((m) => (
                  <Chip key={m}>{m}</Chip>
                ))}
              </dd>
            </div>
            <div className="redsim-stat">
              <dt className="redsim-kicker">runnable targets</dt>
              <dd className="redsim-numeral m-0 text-3xl">
                {models.length}
                <span className="ml-1 text-xs font-normal tracking-normal text-ink-3">
                  registered · available
                </span>
              </dd>
            </div>
          </dl>
        )}
        {atlas ? (
          <p className="mt-4 border-t border-line pt-3 text-xs text-ink-3">
            Technique ids follow MITRE ATLAS
            {atlas.release ? ` ${atlas.release}` : ""}
            {atlas.published ? ` (published ${atlas.published})` : ""}.{" "}
            {atlas.attribution ?? ""}
          </p>
        ) : null}
        {attacksResp?.plugins?.enabled ? (
          <p className="mt-2 text-xs text-ink-3">
            Attack plugins are enabled in this deployment.
          </p>
        ) : null}
        {modelsError ? (
          <p className="mt-2 text-xs text-destructive">
            Model registry unavailable; attacks can be browsed but not launched
            from here.
          </p>
        ) : null}
      </PanelSection>

      <PanelSection
        title="Adversarial-ML attacks"
        eyebrow="catalogue · run against a registered model"
      >
        <div className="mb-4 flex flex-wrap items-end gap-3 text-xs">
          <label className="flex-1 min-w-[12rem]">
            <span className="redsim-kicker">search</span>
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="name, id, ATLAS technique, capability…"
              className="redsim-input mt-1"
            />
          </label>
          <label>
            <span className="redsim-kicker">modality</span>
            <select
              value={modality}
              onChange={(e) => setModality(e.target.value)}
              className={`mt-1 block ${selectClass}`}
            >
              <option value="">all</option>
              {modalities.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="redsim-kicker">family</span>
            <select
              value={family}
              onChange={(e) => setFamily(e.target.value)}
              className={`mt-1 block ${selectClass}`}
            >
              <option value="">all</option>
              {families.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </label>
          <span className="pb-1 text-ink-3">
            {visible.length} of {attacks.length} shown
            {selected.length > 0 ? ` · ${selected.length} selected` : ""}
          </span>
        </div>

        {byFamily.length === 0 && attacks.length > 0 ? (
          <p className="text-sm text-ink-3">
            No attacks match the current filters.
          </p>
        ) : null}

        <div className="space-y-6">
          {byFamily.map(({ family: f, rows }) => (
            <div key={f}>
              <div className="mb-2 flex items-baseline gap-3">
                <div className="redsim-kicker">{f}</div>
                <span className="text-xs text-ink-3">
                  {FAMILY_BLURB[f] ?? ""}
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-line-strong">
                      <th className="w-6 p-2">
                        <input
                          type="checkbox"
                          aria-label={`Select all ${f} attacks shown`}
                          checked={rows.every((a) => selected.includes(a.id))}
                          onChange={(e) =>
                            setSelected((s) =>
                              e.target.checked
                                ? [...new Set([...s, ...rows.map((a) => a.id)])]
                                : s.filter((x) => !rows.some((a) => a.id === x)),
                            )
                          }
                        />
                      </th>
                      <th className="p-2">Attack</th>
                      <th className="p-2">Modalities</th>
                      <th className="p-2">Access</th>
                      <th className="p-2">Status</th>
                      <th className="p-2">ATLAS</th>
                      <th className="p-2">Description</th>
                      <th className="p-2">Run on…</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((a) => {
                      const domains = domainsOf(a);
                      const targets = models.filter((m) => compatible(a, m));
                      const chosen =
                        rowModel[a.id] && targets.some((m) => m.id === rowModel[a.id])
                          ? rowModel[a.id]
                          : targets[0]?.id ?? "";
                      const techniques =
                        a.atlas_techniques && a.atlas_techniques.length > 0
                          ? a.atlas_techniques
                          : a.atlas_technique
                            ? [a.atlas_technique]
                            : [];
                      return (
                        <tr
                          key={a.id}
                          {...rowLink(`/tests/attacks/${encodeURIComponent(a.id)}`)}
                          className={`border-b border-line align-top last:border-0 ${rowLink("").className}`}
                        >
                          <td className="p-2">
                            <input
                              type="checkbox"
                              aria-label={`Select ${a.name}`}
                              checked={selected.includes(a.id)}
                              onChange={(e) => toggle(a.id, e.target.checked)}
                            />
                          </td>
                          <td className="p-2">
                            <div className="text-sm font-medium">{a.name}</div>
                            <div className="font-mono text-[11px] text-ink-3">
                              {a.id}
                            </div>
                          </td>
                          <td className="p-2">
                            <div className="flex flex-wrap gap-1">
                              {domains.map((d) => (
                                <Chip key={d}>{d}</Chip>
                              ))}
                            </div>
                          </td>
                          <td className="p-2 whitespace-nowrap">
                            {a.requires_gradients
                              ? "white-box (gradients)"
                              : "black-box"}
                          </td>
                          <td className="p-2">
                            <div className="flex flex-wrap gap-1">
                              <Chip>{a.status}</Chip>
                              {a.phase === "B" ? (
                                <LabelBadge variant="phase-b" />
                              ) : null}
                            </div>
                            {a.reason ? (
                              <div
                                className="mt-1 max-w-[12rem] truncate text-[11px] text-ink-3"
                                title={a.reason}
                              >
                                {a.reason}
                              </div>
                            ) : null}
                          </td>
                          <td className="p-2">
                            {techniques.length === 0 ? (
                              <span className="text-ink-3">—</span>
                            ) : (
                              <div className="flex flex-col gap-0.5">
                                {techniques.map((t) => (
                                  <span
                                    key={t.id}
                                    className="font-mono text-[11px]"
                                    title={
                                      a.atlas_reason
                                        ? `${t.name} — ${a.atlas_reason}`
                                        : t.name
                                    }
                                  >
                                    {t.id}
                                  </span>
                                ))}
                              </div>
                            )}
                          </td>
                          <td className="p-2">
                            <div
                              className="max-w-[22rem] truncate"
                              title={a.description}
                            >
                              {a.description}
                            </div>
                          </td>
                          <td className="p-2">
                            {targets.length === 0 ? (
                              <span className="text-ink-3">
                                No registered model for {domains.join("/") || "this modality"} —{" "}
                                <Link href="/models" className="redsim-link">
                                  register one
                                </Link>
                              </span>
                            ) : (
                              <div className="flex items-center gap-1">
                                <select
                                  aria-label={`Model to run ${a.name} on`}
                                  value={chosen}
                                  onChange={(e) =>
                                    setRowModel((r) => ({
                                      ...r,
                                      [a.id]: e.target.value,
                                    }))
                                  }
                                  className={`${selectClass} max-w-[14rem]`}
                                >
                                  {targets.map((m) => (
                                    <option key={m.id} value={m.id}>
                                      {m.name} · {m.modality}
                                    </option>
                                  ))}
                                </select>
                                <button
                                  type="button"
                                  disabled={!chosen}
                                  onClick={() => router.push(runHref(chosen, [a.id]))}
                                  className="redsim-cta redsim-btn-sm"
                                >
                                  Go
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>

        {selected.length > 0 ? (
          <div className="redsim-panel sticky bottom-2 mt-4 flex flex-wrap items-center gap-3 p-3 text-xs shadow-lg">
            <span className="font-semibold text-ink-1">
              Run {selected.length} selected on
            </span>
            <select
              aria-label="Model to run the selected attacks on"
              value={bulkModel}
              onChange={(e) => {
                setBulkModel(e.target.value);
                setBulkNote("");
              }}
              className={selectClass}
            >
              <option value="">Select a registered model</option>
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name} · {m.modality}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={!bulkTarget || bulkCompatible.length === 0}
              onClick={runBulk}
              className="redsim-cta redsim-btn-sm"
            >
              Go{bulkTarget ? ` (${bulkCompatible.length})` : ""}
            </button>
            <button
              type="button"
              onClick={() => {
                setSelected([]);
                setBulkNote("");
              }}
              className="redsim-ghost redsim-btn-sm"
            >
              Clear
            </button>
            {bulkTarget && bulkSkipped.length > 0 ? (
              <span className="text-ink-3">
                Skipped (not compatible with {bulkTarget.modality}):{" "}
                <span className="font-mono">
                  {bulkSkipped.map((a) => a.id).join(", ")}
                </span>
              </span>
            ) : null}
            {models.length === 0 ? (
              <span className="text-ink-3">
                No registered model is available —{" "}
                <Link href="/models" className="redsim-link">
                  register one
                </Link>
                .
              </span>
            ) : null}
            {bulkNote ? <span className="text-destructive">{bulkNote}</span> : null}
          </div>
        ) : null}
      </PanelSection>

      <PanelSection
        title="Defenses (hardening, applied from a run's candidate actions)"
        eyebrow="catalogue · read only"
      >
        {defensesError ? (
          <p className="text-sm text-destructive">Defense catalog unavailable.</p>
        ) : defenses.length === 0 ? (
          <p className="text-sm text-ink-3">
            {defensesResp ? "No defenses registered." : "Loading defense catalog…"}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-line-strong">
                  <th className="p-2">Defense</th>
                  <th className="p-2">Kind</th>
                  <th className="p-2">Phase</th>
                  <th className="p-2">Modalities</th>
                  <th className="p-2">Status</th>
                  <th className="p-2">Description</th>
                </tr>
              </thead>
              <tbody>
                {defenses.map((d) => (
                  <tr key={d.id} className="border-b border-line align-top last:border-0">
                    <td className="p-2">
                      <div className="text-sm font-medium">{d.name}</div>
                      <div className="font-mono text-[11px] text-ink-3">
                        {d.id}
                      </div>
                    </td>
                    <td className="p-2">{d.kind ?? "—"}</td>
                    <td className="p-2">
                      {d.phase === "B" ? (
                        <LabelBadge variant="phase-b" />
                      ) : (
                        `phase ${d.phase ?? "—"}`
                      )}
                    </td>
                    <td className="p-2">
                      <div className="flex flex-wrap gap-1">
                        {(d.modalities ?? []).map((m) => (
                          <Chip key={m}>{m}</Chip>
                        ))}
                      </div>
                    </td>
                    <td className="p-2">
                      <Chip>{d.status ?? "unknown"}</Chip>
                    </td>
                    <td className="p-2">
                      <div className="max-w-[28rem] truncate" title={d.description}>
                        {d.description ?? "—"}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-ink-3">
          Defenses are not launched from this catalogue. A completed campaign
          proposes them as candidate actions; apply and re-measure from the
          run&apos;s scorecard.
        </p>
      </PanelSection>
    </div>
  );
}
