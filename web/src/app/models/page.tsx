"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { RoleGated, PanelSection } from "@redsim/design-system";
import {
  ApiError,
  api,
  deleteModel,
  mlErrorDetail,
  type ModelTarget,
} from "@/lib/api";
import { useModels } from "@/hooks/useModels";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";
import { useCapabilities } from "@/hooks/useMlCatalog";
import { useDatasets } from "@/hooks/useMlCatalog";
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
          404: "Model catalog not found.",
          503: "Model service unavailable. Retry when the service is restored.",
        }[error.status] ?? `Model catalog refused (${error.status}).`)
      : "Model catalog unavailable. Retry.";
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
  if (!authed) return <p>Redirecting to sign in…</p>;
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
      const d = mlErrorDetail(e);
      setErr(
        `${d.code ?? "model_refused"}: ${d.message ?? "The model was not accepted."}${d.reasons?.length ? ` — ${d.reasons.join(", ")}` : ""}`,
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
          <div className="redsim-kicker">assurance catalog / phase A</div>
          <h1 className="text-3xl font-semibold tracking-tight">
            Model targets
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Register the exact artifact before measuring it.
          </p>
        </div>
        <RoleGated
          minRole="remediator"
          callerRole={projectId ? roles[projectId] : undefined}
        >
          <button
            className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"
            onClick={() => setOpen(true)}
          >
            Add model
          </button>
        </RoleGated>
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
      {!isLoading && !error && models.length === 0 && (
        <PanelSection title="No registered models" eyebrow="catalog empty">
          <p className="text-sm text-muted-foreground">
            Add a bundled sample or a supported artifact to begin a campaign.
          </p>
        </PanelSection>
      )}
      <div className="grid gap-3 md:grid-cols-2">
        {models.map((m: ModelTarget) => (
          <article key={m.id} className="redsim-panel rounded-sm p-4">
            <button
              className="w-full text-left transition-transform hover:-translate-y-0.5"
              onClick={() => router.push(`/models/${m.id}`)}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-lg font-semibold">{m.name}</div>
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
                  {m.modality}
                </div>
                <div>
                  <div className="redsim-kicker">sha256</div>
                  {String(m.sha256 ?? "—").slice(0, 12)}
                </div>
                <div>
                  <div className="redsim-kicker">clean accuracy</div>
                  {m.manifest.clean_accuracy ?? "—"}{" "}
                  {m.manifest.clean_n ? `(n=${m.manifest.clean_n})` : ""}
                </div>
              </div>
              {m.reason && (
                <p className="mt-3 border-t border-border pt-3 text-xs text-muted-foreground">
                  {m.reason}
                </p>
              )}
            </button>
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
            </div>
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
                      {model.name} · {model.modality}
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
                    {datasets.map((dataset) => (
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
              Model name
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-1 w-full rounded-sm border border-input bg-background px-3 py-2"
                placeholder="vehicle-classifier-v1"
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
                  !name ||
                  (source === "bundled" && !bundledId) ||
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
