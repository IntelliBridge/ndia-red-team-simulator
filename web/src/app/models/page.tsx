"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { RoleGated, PanelSection } from "@redsim/design-system";
import {
  ApiError,
  api,
  deleteModel,
  formatCleanAccuracy,
  mlErrorDetail,
  modelDisplayName,
  modelGateway,
  type ModelTarget,
} from "@/lib/api";
import { useModels } from "@/hooks/useModels";
import { rowLink } from "@/lib/row-link";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";
import { useCapabilities } from "@/hooks/useMlCatalog";
import { useDatasets } from "@/hooks/useMlCatalog";
import { isLlmTarget, registerLlmTarget } from "@/lib/llm";
import { EMPTY_LLM_FORM, LlmRegisterForm } from "./llm-register-form";
import {
  DEFAULT_SORT,
  EMPTY_FILTERS,
  SORT_OPTIONS,
  facetValues,
  filterModels,
  hasActiveFilters,
  modelDomain,
  parseSort,
  sortCoverage,
  sortCoverageNote,
  sortModels,
  sortValue,
  type ModelFilters,
  type ModelSort,
  type SortKey,
} from "./model-list";
/** Provider badge for LLM targets: the gateway the model is reached through. */
function GatewayBadge({ host }: { host: string }) {
  const label = /pythia/i.test(host) ? "Pythia" : host;
  return (
    <span
      className="rounded-sm border border-sky-400/50 bg-sky-400/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-sky-200"
      title={`via ${host}`}
    >
      {label}
    </span>
  );
}

/** A list-view column header that sorts on click and announces the order. */
function SortableHeader({
  label,
  column,
  sort,
  onSort,
}: {
  label: string;
  column: SortKey;
  sort: ModelSort;
  onSort: (key: SortKey) => void;
}) {
  const active = sort.key === column;
  const ariaSort = active ? (sort.direction === "asc" ? "ascending" : "descending") : "none";
  return (
    <th scope="col" aria-sort={ariaSort} className="px-3 py-2">
      <button
        type="button"
        onClick={() => onSort(column)}
        className={`inline-flex items-center gap-1 uppercase tracking-wide ${active ? "text-foreground" : ""}`}
      >
        {label}
        <span aria-hidden="true" className="text-[10px]">
          {active ? (sort.direction === "asc" ? "▲" : "▼") : "↕"}
        </span>
      </button>
    </th>
  );
}

const DIMENSION_LABELS: Record<string, string> = {
  S_acc: "Accuracy under attack",
  S_asr: "Resistance to attack success",
  S_eps: "Perturbation budget needed",
  S_conf: "Confidence stability",
  S_expl: "Explanation stability",
};

/**
 * Average score of a model by category, from its own scorecards; nothing when
 * unscored. Collapsed by default: the header line shows the headline number
 * and the count, the per-category bars open on click.
 */
function ScoreSummaryBlock({ summary }: { summary: ModelTarget["score_summary"] }) {
  const [open, setOpen] = useState(false);
  if (!summary) return null;
  const isMri = summary.kind === "mri";
  const dims = isMri
    ? (Object.entries(summary.subscores_mean).filter(([, v]) => v !== null) as [string, number][])
    : [];
  if (isMri && summary.mri_mean === null && dims.length === 0) return null;
  if (!isMri && summary.families.length === 0) return null;
  const headline = isMri
    ? `${summary.mri_mean ?? "—"}`
    : `${summary.families.length} categor${summary.families.length === 1 ? "y" : "ies"}`;
  const count = isMri
    ? `${summary.n_campaigns} campaign${summary.n_campaigns === 1 ? "" : "s"}`
    : `${summary.n_runs} run${summary.n_runs === 1 ? "" : "s"}`;
  return (
    <div className="mt-4 border-t border-border pt-3" data-testid="score-summary">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-3 text-left"
      >
        <span className="redsim-kicker">
          {isMri ? "average robustness index" : "average hit rate by category"}
        </span>
        <span className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">{count}</span>
          <span className="text-sm font-semibold tabular-nums">{headline}</span>
          <span aria-hidden="true" className="text-muted-foreground">
            {open ? "▾" : "▸"}
          </span>
        </span>
      </button>
      {open && isMri && (
        <>
          <ul className="mt-2 space-y-1">
            {dims.map(([key, value]) => (
              <li key={key} className="grid grid-cols-[1fr_6rem_2.5rem] items-center gap-2 text-xs">
                <span className="truncate">{DIMENSION_LABELS[key] ?? key}</span>
                <span className="h-2 rounded-sm bg-muted" aria-hidden="true">
                  <span className="block h-2 rounded-sm bg-primary" style={{ width: `${Math.max(2, Math.min(100, value))}%` }} />
                </span>
                <span className="text-right tabular-nums">{value}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-muted-foreground" title={summary.note}>
            Mean over this model&apos;s scored campaigns; each scorecard keeps its denominators.
          </p>
        </>
      )}
      {open && !isMri && (
        <>
          <ul className="mt-2 space-y-1">
            {summary.families.map((f) => (
              <li key={f.family} className="grid grid-cols-[1fr_6rem_3.5rem] items-center gap-2 text-xs">
                <span className="truncate">{f.family}</span>
                <span className="h-2 rounded-sm bg-muted" aria-hidden="true">
                  <span className="block h-2 rounded-sm bg-orange-500" style={{ width: `${Math.max(2, Math.round(f.hit_rate * 100))}%` }} />
                </span>
                <span className="text-right tabular-nums">{Math.round(f.hit_rate * 100)}%</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-muted-foreground" title={summary.note}>
            Hits over evaluated replies, pooled across runs; a hit is the detector&apos;s judgement.
          </p>
        </>
      )}
    </div>
  );
}

export default function ModelsPage() {
  const authed = useRequireAuth();
  const router = useRouter();
  const { roles } = useRoles();
  const projectId = Object.keys(roles)[0] ?? null;
  const {
    data: models = [],
    error,
    isLoading,
    mutate,
  } = useModels(authed ? projectId : null);
  const { data: capabilities } = useCapabilities(authed);
  const { data: datasets = [] } = useDatasets(authed);
  const catalogError =
    error instanceof ApiError
      ? ({
          403: "Unauthorized for this project.",
          404: "Model catalog not_implemented: GET /v1/models is not mounted in this deployment.",
          501: "Model catalog not_implemented: the server reports the catalog as not implemented.",
          503: "Model service unavailable. Retry when the service is restored.",
        }[error.status] ?? `Model catalog refused (${error.status}).`)
      : "Model catalog unavailable. Retry.";
  // Cards or a compact list; the choice is remembered per browser.
  const [view, setView] = useState<"cards" | "list">("cards");
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(VIEW_KEY);
      if (saved === "list" || saved === "cards") setView(saved);
    } catch {
      // storage unavailable: keep the default
    }
  }, []);
  const chooseView = (next: "cards" | "list") => {
    setView(next);
    try {
      window.localStorage.setItem(VIEW_KEY, next);
    } catch {
      // storage unavailable: the choice lasts for this page only
    }
  };
  // Filters live for the page; the sort order is remembered per browser.
  const [filters, setFilters] = useState<ModelFilters>(EMPTY_FILTERS);
  const [sort, setSort] = useState<ModelSort>(DEFAULT_SORT);
  useEffect(() => {
    try {
      setSort(parseSort(window.localStorage.getItem(SORT_KEY)));
    } catch {
      // storage unavailable: keep the default
    }
  }, []);
  const chooseSort = (next: ModelSort) => {
    setSort(next);
    try {
      window.localStorage.setItem(SORT_KEY, sortValue(next));
    } catch {
      // storage unavailable: the choice lasts for this page only
    }
  };
  // A column header click sorts by that column, a second click flips it.
  const sortByColumn = (key: SortKey) =>
    chooseSort({
      key,
      direction: sort.key === key && sort.direction === "asc" ? "desc" : "asc",
    });
  const setFilter = (patch: Partial<ModelFilters>) =>
    setFilters((f) => ({ ...f, ...patch }));
  const domains = facetValues(models, modelDomain);
  const statuses = facetValues(models, (m) => m.status);
  const sources = facetValues(models, (m) => m.source);
  const shown = sortModels(filterModels(models, filters), sort);
  const filtering = hasActiveFilters(filters);
  // A numeric sort over rows that mostly lack the metric cannot visibly reorder; say so.
  const coverageNote = sortCoverageNote(sortCoverage(shown, sort));
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [name, setName] = useState("");
  const [source, setSource] = useState("bundled");
  const [file, setFile] = useState<File | null>(null);
  const [architecture, setArchitecture] = useState("");
  const [license, setLicense] = useState("");
  const [bundledId, setBundledId] = useState("");
  const [datasetId, setDatasetId] = useState("");
  const [llm, setLlm] = useState(EMPTY_LLM_FORM);
  const endpointAvailable =
    capabilities?.endpoint_connector?.status === "available";
  if (!authed) return <p>Signing in…</p>;
  const add = async () => {
    setBusy(true);
    setErr("");
    try {
      if (source === "upload") {
        if (!file) {
          setErr(
            "upload_missing_file: choose an ONNX or state_dict artifact before registering.",
          );
          return;
        }
        const body = new FormData();
        body.append("file", file);
        body.append("name", name);
        body.append("project_id", projectId ?? "");
        body.append("architecture_id", architecture);
        body.append("license_statement", license);
        const declaredFormat = file.name.endsWith(".onnx")
          ? "onnx"
          : file.name.endsWith(".safetensors")
            ? "safetensors_state_dict"
            : "torch_state_dict";
        body.append("declared_format", declaredFormat);
        body.append("modality", "image");
        body.append("dataset_id", datasetId);
        await api("/v1/models", { method: "POST", body });
      } else if (source === "llm") {
        const out = await registerLlmTarget({
          source: "endpoint",
          endpoint_kind: "llm",
          project_id: projectId ?? "",
          model_id: llm.modelId.trim(),
          persona: llm.persona.trim(),
          guardrail_mode: llm.guardrailMode,
          auth_profile_id: llm.authProfileId,
          ...(name.trim() ? { name: name.trim() } : {}),
        });
        setOpen(false);
        setName("");
        mutate();
        router.push(`/models/${out.id}`);
        return;
      } else {
        await api("/v1/models", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source: "bundled",
            project_id: projectId,
            bundled_id: bundledId,
          }),
        });
      }
      setOpen(false);
      setName("");
      mutate();
    } catch (e) {
      const d = mlErrorDetail(e) as ReturnType<typeof mlErrorDetail> & {
        reason?: string;
      };
      const where = [d.field, d.reason].filter(Boolean).join(" · ");
      setErr(
        `${d.code ?? "model_refused"}: ${d.message ?? "The model was not accepted."}${where ? ` (${where})` : ""}${d.reasons?.length ? ` — ${d.reasons.join(", ")}` : ""}`,
      );
    } finally {
      setBusy(false);
    }
  };
  const remove = async (id: string) => {
    try {
      await deleteModel(id);
      mutate();
    } catch (e) {
      setErr(
        `${mlErrorDetail(e).message ?? "Delete refused"} — an in-flight campaign may be using this model.`,
      );
    }
  };
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Model targets</h1>
        </div>
        <div className="flex items-center gap-2">
          <div className="inline-flex rounded-sm border border-border text-xs" role="group" aria-label="View">
            <button
              type="button"
              aria-pressed={view === "cards"}
              onClick={() => chooseView("cards")}
              className={`px-3 py-1.5 ${view === "cards" ? "bg-muted font-semibold" : "text-muted-foreground"}`}
            >
              Cards
            </button>
            <button
              type="button"
              aria-pressed={view === "list"}
              onClick={() => chooseView("list")}
              className={`border-l border-border px-3 py-1.5 ${view === "list" ? "bg-muted font-semibold" : "text-muted-foreground"}`}
            >
              List
            </button>
          </div>
        {!error && <RoleGated
          minRole="remediator"
          callerRole={projectId ? roles[projectId] : undefined}
        >
          <button
            className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"
            onClick={() => setOpen(true)}
          >
            Add model
          </button>
        </RoleGated>}
        </div>
      </header>
      {error && (
        <div className="border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {catalogError}
        </div>
      )}
      {err && (
        <div className="border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </div>
      )}
      {isLoading && (
        <div className="grid gap-3 md:grid-cols-2">
          <div className="h-28 animate-pulse bg-muted" />
          <div className="h-28 animate-pulse bg-muted" />
        </div>
      )}{" "}
      {!isLoading && !error && models.length > 0 && (
        <div
          className="flex flex-wrap items-end gap-3 rounded-sm border border-border bg-card p-3 text-sm"
          role="search"
          aria-label="Filter and sort models"
        >
          <label className="flex min-w-[12rem] flex-1 flex-col gap-1">
            <span className="redsim-kicker">search</span>
            <input
              type="search"
              value={filters.query}
              onChange={(e) => setFilter({ query: e.target.value })}
              placeholder="name, id or model id"
              className="rounded-sm border border-input bg-background px-3 py-1.5"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="redsim-kicker">domain</span>
            <select
              value={filters.domain}
              onChange={(e) => setFilter({ domain: e.target.value })}
              className="rounded-sm border border-input bg-background px-3 py-1.5"
            >
              <option value="">All</option>
              {domains.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="redsim-kicker">status</span>
            <select
              value={filters.status}
              onChange={(e) => setFilter({ status: e.target.value })}
              className="rounded-sm border border-input bg-background px-3 py-1.5"
            >
              <option value="">All</option>
              {statuses.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="redsim-kicker">source</span>
            <select
              value={filters.source}
              onChange={(e) => setFilter({ source: e.target.value })}
              className="rounded-sm border border-input bg-background px-3 py-1.5"
            >
              <option value="">All</option>
              {sources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="redsim-kicker">sort</span>
            <select
              value={sortValue(sort)}
              onChange={(e) => chooseSort(parseSort(e.target.value))}
              className="rounded-sm border border-input bg-background px-3 py-1.5"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <div className="flex flex-wrap items-center gap-3 pb-1.5 text-xs text-muted-foreground">
            <span aria-live="polite" data-testid="models-count">
              {filtering ? `${shown.length} of ${models.length}` : models.length} model
              {models.length === 1 ? "" : "s"}
            </span>
            {filtering && (
              <button
                type="button"
                className="redsim-ghost px-2 py-1"
                onClick={() => setFilters(EMPTY_FILTERS)}
              >
                Clear filters
              </button>
            )}
          </div>
          {coverageNote && (
            <p className="basis-full text-xs text-muted-foreground" role="status" data-testid="sort-coverage">
              {coverageNote}
            </p>
          )}
        </div>
      )}
      {!isLoading && !error && models.length === 0 && (
        <PanelSection title="No registered models" eyebrow="catalog empty">
          <p className="text-sm text-muted-foreground">
            Add a bundled sample or a supported artifact to begin a campaign.
          </p>
        </PanelSection>
      )}
      {!isLoading && !error && models.length > 0 && shown.length === 0 && (
        <PanelSection title="No models match" eyebrow="filtered">
          <p className="text-sm text-muted-foreground">
            No registered model matches these filters. Clear a filter to widen the list.
          </p>
        </PanelSection>
      )}
      {view === "list" && shown.length > 0 && (
        <div className="overflow-x-auto rounded-sm border border-border bg-card">
          <table className="w-full text-sm">
            <caption className="sr-only">Registered model targets</caption>
            <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <SortableHeader label="Name" column="name" sort={sort} onSort={sortByColumn} />
                <th scope="col" className="px-3 py-2">ID</th>
                <SortableHeader label="Domain" column="domain" sort={sort} onSort={sortByColumn} />
                <SortableHeader label="Status" column="status" sort={sort} onSort={sortByColumn} />
                <SortableHeader label="Source" column="source" sort={sort} onSort={sortByColumn} />
                <SortableHeader
                  label="Clean accuracy / model"
                  column="clean_accuracy"
                  sort={sort}
                  onSort={sortByColumn}
                />
                <th scope="col" className="px-3 py-2">Digest / persona</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((m: ModelTarget) => (
                <tr key={m.id} {...rowLink(`/models/${m.id}`)} className={`border-t border-border ${rowLink("").className}`}>
                  <td className="px-3 py-2 font-medium">
                    <a className="text-primary underline" href={`/models/${m.id}`}>
                      {modelDisplayName(m)}
                    </a>
                    {modelGateway(m) && <GatewayBadge host={modelGateway(m)!} />}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{m.id}</td>
                  <td className="px-3 py-2">{isLlmTarget(m) ? "llm" : m.modality}</td>
                  <td className="px-3 py-2">
                    <span className="rounded-sm border border-border bg-muted px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider">
                      {m.status}
                    </span>
                  </td>
                  <td className="px-3 py-2">{m.source}</td>
                  <td className="px-3 py-2">
                    {isLlmTarget(m)
                      ? (typeof m.manifest.model_id === "string" ? m.manifest.model_id : "—")
                      : formatCleanAccuracy(m.manifest.clean_accuracy, m.manifest.clean_n)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {isLlmTarget(m)
                      ? (typeof m.manifest.persona === "string" ? m.manifest.persona : "—")
                      : String(m.sha256 ?? "—").slice(0, 12)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {view === "cards" && (
      <div className="grid gap-3 md:grid-cols-2">
        {shown.map((m: ModelTarget) => (
          <article key={m.id} className="redsim-panel rounded-sm p-4">
            <button
              className="w-full text-left transition-transform hover:-translate-y-0.5"
              onClick={() => router.push(`/models/${m.id}`)}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-lg font-semibold">{modelDisplayName(m)}</span>
                    {modelGateway(m) && <GatewayBadge host={modelGateway(m)!} />}
                  </div>
                  <div className="mt-1 font-mono text-xs text-muted-foreground">
                    {m.id}
                  </div>
                </div>
                <span className="rounded-sm border border-border bg-muted px-2 py-1 text-[10px] font-semibold uppercase tracking-wider">
                  {m.status}
                </span>
              </div>
              <div className="mt-5 grid grid-cols-3 gap-3 text-xs">
                <div>
                  <div className="redsim-kicker">domain</div>
                  {isLlmTarget(m) ? (
                    <span className="rounded-sm border border-border bg-muted px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider">
                      llm
                    </span>
                  ) : (
                    m.modality
                  )}
                </div>
                {isLlmTarget(m) ? (
                  <>
                    <div>
                      <div className="redsim-kicker">model</div>
                      <span className="font-mono">
                        {typeof m.manifest.model_id === "string"
                          ? m.manifest.model_id
                          : "—"}
                      </span>
                    </div>
                    <div>
                      <div className="redsim-kicker">persona</div>
                      {typeof m.manifest.persona === "string"
                        ? m.manifest.persona
                        : "—"}
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <div className="redsim-kicker">sha256</div>
                      {String(m.sha256 ?? "—").slice(0, 12)}
                    </div>
                    <div>
                      <div className="redsim-kicker">clean accuracy</div>
                      {formatCleanAccuracy(m.manifest.clean_accuracy, m.manifest.clean_n)}
                    </div>
                  </>
                )}
              </div>
              {m.reason && (
                <p className="mt-3 border-t border-border pt-3 text-xs text-muted-foreground">
                  {m.reason}
                </p>
              )}
            </button>
            <ScoreSummaryBlock summary={m.score_summary} />
            <RoleGated minRole="admin" callerRole={roles[m.project_id]}>
              <button
                className="mt-3 border border-destructive/30 px-3 py-1 text-xs text-destructive"
                onClick={() => remove(m.id)}
              >
                Delete model
              </button>
            </RoleGated>
          </article>
        ))}
      </div>
      )}
      {open && (
        <div className="fixed inset-0 z-40 grid place-items-center bg-foreground/30 p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-model-title"
            className="redsim-panel w-full max-w-lg rounded-sm p-5"
          >
            <div className="redsim-kicker">register model</div>
            <h2 id="add-model-title" className="mt-1 text-xl font-semibold">
              Add model target
            </h2>
            <div className="mt-5 flex gap-2">
              <button
                aria-pressed={source === "bundled"}
                className={`border px-3 py-2 text-sm ${source === "bundled" ? "border-primary bg-primary/10" : "border-border"}`}
                onClick={() => setSource("bundled")}
              >
                Bundled sample
              </button>
              <button
                aria-pressed={source === "upload"}
                className={`border px-3 py-2 text-sm ${source === "upload" ? "border-primary bg-primary/10" : "border-border"}`}
                onClick={() => setSource("upload")}
              >
                Upload artifact
              </button>
              {endpointAvailable ? (
                <button
                  aria-pressed={source === "llm"}
                  className={`border px-3 py-2 text-sm ${source === "llm" ? "border-primary bg-primary/10" : "border-border"}`}
                  onClick={() => setSource("llm")}
                >
                  Connect endpoint
                </button>
              ) : (
                <button
                  disabled
                  className="border border-border px-3 py-2 text-sm text-muted-foreground"
                  title={
                    capabilities?.endpoint_connector?.reason ??
                    "Endpoint connector is unavailable in Phase B"
                  }
                >
                  Connect endpoint ·{" "}
                  {capabilities?.endpoint_connector?.reason ?? "Phase B"}
                </button>
              )}
            </div>
            {source === "llm" && (
              <LlmRegisterForm
                projectId={projectId}
                value={llm}
                onChange={setLlm}
              />
            )}
            {source === "bundled" && (
              <label className="mt-4 block text-sm">
                Bundled sample
                <select
                  value={bundledId}
                  onChange={(event) => setBundledId(event.target.value)}
                  className="mt-1 w-full rounded-sm border border-input bg-background px-3 py-2"
                >
                  <option value="">
                    Select a server-registered bundled model
                  </option>
                  {(capabilities?.bundled_models ?? []).map((model) => (
                    <option key={model.id} value={model.id}>
                      {modelDisplayName(model)} · {model.modality}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {source === "upload" && (
              <>
                <label className="mt-4 block text-sm">
                  Artifact
                  <input
                    type="file"
                    accept=".onnx,.pth,.safetensors"
                    onChange={(event) =>
                      setFile(event.target.files?.[0] ?? null)
                    }
                    className="mt-1 block w-full rounded-sm border border-input bg-background px-3 py-2"
                  />
                </label>
                <label className="mt-3 block text-sm">
                  Architecture
                  <select
                    value={architecture}
                    onChange={(event) => setArchitecture(event.target.value)}
                    className="mt-1 w-full rounded-sm border border-input bg-background px-3 py-2"
                  >
                    <option value="">Select an allowlisted architecture</option>
                    {(capabilities?.architectures ?? []).map((item) => {
                      const id = typeof item === "string" ? item : item.id;
                      const label = typeof item === "string" ? item : item.name;
                      return (
                        <option key={id} value={id}>
                          {label}
                        </option>
                      );
                    })}
                  </select>
                </label>
                <label className="mt-3 block text-sm">
                  Evaluation dataset
                  <select
                    value={datasetId}
                    onChange={(event) => setDatasetId(event.target.value)}
                    className="mt-1 w-full rounded-sm border border-input bg-background px-3 py-2"
                  >
                    <option value="">Select a compatible dataset</option>
                    {datasets
                      .filter((dataset) =>
                        dataset.compatible_modalities.includes("image"),
                      )
                      .map((dataset) => (
                      <option key={dataset.id} value={dataset.id}>
                        {dataset.name} · {dataset.revision}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="mt-3 block text-sm">
                  License statement
                  <input
                    value={license}
                    onChange={(event) => setLicense(event.target.value)}
                    className="mt-1 w-full rounded-sm border border-input bg-background px-3 py-2"
                  />
                </label>
                <p className="mt-3 bg-muted p-3 text-xs text-muted-foreground">
                  ONNX or state_dict with an explicit architecture. Full pickles
                  are refused. Refusal rules are shown before choosing a file.
                </p>
              </>
            )}
            {err && <p className="mt-3 text-sm text-destructive">{err}</p>}
            <label className="mt-4 block text-sm">
              Model name{source === "llm" ? " (optional)" : ""}
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-1 w-full rounded-sm border border-input bg-background px-3 py-2"
                placeholder={
                  source === "llm"
                    ? "defaults to the model id"
                    : "vehicle-classifier-v1"
                }
              />
            </label>
            <div className="mt-5 flex justify-end gap-2">
              <button
                className="border border-border px-3 py-2 text-sm"
                onClick={() => setOpen(false)}
              >
                Cancel
              </button>
              <button
                disabled={
                  busy ||
                  !projectId ||
                  (source !== "llm" && !name) ||
                  (source === "bundled" && !bundledId) ||
                  (source === "llm" &&
                    (!llm.modelId.trim() ||
                      !llm.persona.trim() ||
                      !llm.authProfileId)) ||
                  (source === "upload" &&
                    (!file ||
                      !datasetId ||
                      !license ||
                      (!file.name.endsWith(".onnx") && !architecture)))
                }
                className="bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
                onClick={add}
              >
                {busy ? "Registering…" : "Register model"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const VIEW_KEY = "redsim_models_view";

const SORT_KEY = "redsim_models_sort";
