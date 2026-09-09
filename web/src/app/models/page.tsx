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
/** Provider badge for LLM targets: the gateway the model is reached through. */
function GatewayBadge({ host }: { host: string }) {
  const label = /pythia/i.test(host) ? "Pythia" : host;
  return (
    <span
      className="redsim-chip border-sky-400/50 text-sky-200"
      title={`via ${host}`}
    >
      {label}
    </span>
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
    <div className="mt-4 border-t border-line pt-3" data-testid="score-summary">
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
          <span className="text-xs text-ink-3">{count}</span>
          <span className="redsim-numeral text-2xl">{headline}</span>
          <span aria-hidden="true" className="text-ink-3">
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
                <span className="relative block h-px bg-line-strong" aria-hidden="true">
                  <span className="absolute left-0 top-1/2 block h-[3px] -translate-y-1/2 bg-data-adv" style={{ width: `${Math.max(2, Math.min(100, value))}%` }} />
                </span>
                <span className="text-right tabular-nums">{value}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-ink-3" title={summary.note}>
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
                <span className="relative block h-px bg-line-strong" aria-hidden="true">
                  <span className="absolute left-0 top-1/2 block h-[3px] -translate-y-1/2 bg-orange-400" style={{ width: `${Math.max(2, Math.round(f.hit_rate * 100))}%` }} />
                </span>
                <span className="text-right tabular-nums">{Math.round(f.hit_rate * 100)}%</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-ink-3" title={summary.note}>
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
          <div className="inline-flex gap-1" role="group" aria-label="View">
            <button
              type="button"
              aria-pressed={view === "cards"}
              onClick={() => chooseView("cards")}
              className={`redsim-ghost redsim-btn-sm ${view === "cards" ? "border-ink-1 bg-surface-3" : "text-ink-3"}`}
            >
              Cards
            </button>
            <button
              type="button"
              aria-pressed={view === "list"}
              onClick={() => chooseView("list")}
              className={`redsim-ghost redsim-btn-sm ${view === "list" ? "border-ink-1 bg-surface-3" : "text-ink-3"}`}
            >
              List
            </button>
          </div>
        {!error && <RoleGated
          minRole="remediator"
          callerRole={projectId ? roles[projectId] : undefined}
        >
          <button
            className="redsim-cta redsim-btn-sm"
            onClick={() => setOpen(true)}
          >
            Add model
          </button>
        </RoleGated>}
        </div>
      </header>
      {error && (
        <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {catalogError}
        </div>
      )}
      {err && (
        <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </div>
      )}
      {isLoading && (
        <div className="grid gap-3 md:grid-cols-2">
          <div className="h-28 animate-pulse rounded-[4px] bg-surface-2" />
          <div className="h-28 animate-pulse rounded-[4px] bg-surface-2" />
        </div>
      )}{" "}
      {!isLoading && !error && models.length === 0 && (
        <PanelSection title="No registered models" eyebrow="catalog empty">
          <p className="text-sm text-ink-3">
            Add a bundled sample or a supported artifact to begin a campaign.
          </p>
        </PanelSection>
      )}
      {view === "list" && models.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">Registered model targets</caption>
            <thead className="text-left">
              <tr className="border-b border-line-strong">
                <th className="px-3 py-2.5">Name</th>
                <th className="px-3 py-2.5">ID</th>
                <th className="px-3 py-2.5">Domain</th>
                <th className="px-3 py-2.5">Status</th>
                <th className="px-3 py-2.5">Source</th>
                <th className="px-3 py-2.5">Clean accuracy / model</th>
                <th className="px-3 py-2.5">Digest / persona</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m: ModelTarget) => (
                <tr key={m.id} {...rowLink(`/models/${m.id}`)} className={`border-b border-line last:border-0 ${rowLink("").className}`}>
                  <td className="px-3 py-2.5 font-medium text-ink-1">
                    <a className="redsim-link" href={`/models/${m.id}`}>
                      {modelDisplayName(m)}
                    </a>{" "}
                    {modelGateway(m) && <GatewayBadge host={modelGateway(m)!} />}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-ink-3">{m.id}</td>
                  <td className="px-3 py-2.5">{isLlmTarget(m) ? "llm" : m.modality}</td>
                  <td className="px-3 py-2.5">
                    <span className="redsim-chip">
                      {m.status}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">{m.source}</td>
                  <td className="px-3 py-2.5 tabular-nums">
                    {isLlmTarget(m)
                      ? (typeof m.manifest.model_id === "string" ? m.manifest.model_id : "—")
                      : formatCleanAccuracy(m.manifest.clean_accuracy, m.manifest.clean_n)}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-ink-3">
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
      <div className="grid gap-x-8 md:grid-cols-2">
        {models.map((m: ModelTarget) => (
          <article key={m.id} className="border-t border-line py-5">
            <button
              className="w-full text-left"
              onClick={() => router.push(`/models/${m.id}`)}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-lg font-semibold text-ink-1">{modelDisplayName(m)}</span>
                    {modelGateway(m) && <GatewayBadge host={modelGateway(m)!} />}
                  </div>
                  <div className="mt-1 font-mono text-xs text-ink-3">
                    {m.id}
                  </div>
                </div>
                <span className="redsim-chip">
                  {m.status}
                </span>
              </div>
              <div className="mt-5 grid grid-cols-3 gap-3 text-xs text-ink-1">
                <div>
                  <div className="redsim-kicker">domain</div>
                  {isLlmTarget(m) ? (
                    <span className="redsim-chip">
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
                <p className="redsim-prose mt-3 border-t border-line pt-3 text-sm">
                  {m.reason}
                </p>
              )}
            </button>
            <ScoreSummaryBlock summary={m.score_summary} />
            <RoleGated minRole="admin" callerRole={roles[m.project_id]}>
              <button
                className="redsim-ghost redsim-btn-sm mt-3 border-destructive/40 text-destructive"
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
        <div className="fixed inset-0 z-40 grid place-items-center bg-ground/70 p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-model-title"
            className="redsim-panel w-full max-w-lg p-5"
          >
            <div className="redsim-kicker">register model</div>
            <h2 id="add-model-title" className="mt-1 text-xl font-semibold text-ink-1">
              Add model target
            </h2>
            <div className="mt-5 flex flex-wrap gap-2">
              <button
                aria-pressed={source === "bundled"}
                className={`redsim-ghost redsim-btn-sm ${source === "bundled" ? "border-ink-1 bg-surface-3" : "text-ink-3"}`}
                onClick={() => setSource("bundled")}
              >
                Bundled sample
              </button>
              <button
                aria-pressed={source === "upload"}
                className={`redsim-ghost redsim-btn-sm ${source === "upload" ? "border-ink-1 bg-surface-3" : "text-ink-3"}`}
                onClick={() => setSource("upload")}
              >
                Upload artifact
              </button>
              {endpointAvailable ? (
                <button
                  aria-pressed={source === "llm"}
                  className={`redsim-ghost redsim-btn-sm ${source === "llm" ? "border-ink-1 bg-surface-3" : "text-ink-3"}`}
                  onClick={() => setSource("llm")}
                >
                  Connect endpoint
                </button>
              ) : (
                <button
                  disabled
                  className="redsim-ghost redsim-btn-sm text-ink-3"
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
              <label className="mt-4 block text-sm text-ink-1">
                Bundled sample
                <select
                  value={bundledId}
                  onChange={(event) => setBundledId(event.target.value)}
                  className="redsim-input mt-1"
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
                <label className="mt-4 block text-sm text-ink-1">
                  Artifact
                  <input
                    type="file"
                    accept=".onnx,.pth,.safetensors"
                    onChange={(event) =>
                      setFile(event.target.files?.[0] ?? null)
                    }
                    className="redsim-input mt-1"
                  />
                </label>
                <label className="mt-3 block text-sm text-ink-1">
                  Architecture
                  <select
                    value={architecture}
                    onChange={(event) => setArchitecture(event.target.value)}
                    className="redsim-input mt-1"
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
                <label className="mt-3 block text-sm text-ink-1">
                  Evaluation dataset
                  <select
                    value={datasetId}
                    onChange={(event) => setDatasetId(event.target.value)}
                    className="redsim-input mt-1"
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
                <label className="mt-3 block text-sm text-ink-1">
                  License statement
                  <input
                    value={license}
                    onChange={(event) => setLicense(event.target.value)}
                    className="redsim-input mt-1"
                  />
                </label>
                <p className="mt-3 rounded-[4px] bg-ground p-3 text-xs text-ink-3">
                  ONNX or state_dict with an explicit architecture. Full pickles
                  are refused. Refusal rules are shown before choosing a file.
                </p>
              </>
            )}
            {err && <p className="mt-3 text-sm text-destructive">{err}</p>}
            <label className="mt-4 block text-sm text-ink-1">
              Model name{source === "llm" ? " (optional)" : ""}
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="redsim-input mt-1"
                placeholder={
                  source === "llm"
                    ? "defaults to the model id"
                    : "vehicle-classifier-v1"
                }
              />
            </label>
            <div className="mt-5 flex justify-end gap-2">
              <button
                className="redsim-ghost"
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
                className="redsim-cta"
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
