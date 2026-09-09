"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { PanelSection, RoleGated, LabelBadge } from "@redsim/design-system";
import {
  formatCleanAccuracy,
  modelDisplayName,
  startCampaign,
  type AttackInfo,
  type CampaignRequest,
  type CampaignHistory,
  type DatasetInfo,
  type DefenseInfo,
} from "@/lib/api";
import { useModel } from "@/hooks/useModel";
import {
  useAttacks,
  useDatasets,
  useDefenses,
  useCapabilities,
} from "@/hooks/useMlCatalog";
import { useRoles } from "@/hooks/useRoles";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { guardrailLabel, isLlmTarget } from "@/lib/llm";
import { pageSearchParam, type RawSearchParams } from "@/lib/page-search-params";
import { ProbeLauncher } from "./probe-launcher";

/** A probe run row of GET /v1/models/{id}.probe_history (LLM targets only; D9). */
type ProbeHistoryRow = {
  run_id: string;
  kind?: string;
  status: string;
  created_at?: string | null;
  completed_at?: string | null;
  probe_set?: string | null;
  probe_ids?: string[];
  scorecard_url?: string | null;
  status_url?: string;
};
const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() ? value : null;
export default function ModelPage({
  params,
  searchParams,
}: {
  params: { id: string };
  searchParams?: RawSearchParams;
}) {
  const authed = useRequireAuth();
  const router = useRouter();
  const { data: model, error: modelError } = useModel(
    authed ? params.id : null,
  );
  const history = model?.campaign_history ?? [];
  const llmTarget = !!model && isLlmTarget(model);
  const llmRow = model as
    | (typeof model & {
        probe_history?: ProbeHistoryRow[];
        endpoint?: { host?: string | null };
        validation?: {
          entitlement?: string;
          n_entitled?: number | null;
        } | null;
      })
    | undefined;
  const probeHistory: ProbeHistoryRow[] = llmRow?.probe_history ?? [];
  const { data: attacks = [], error: attacksError } = useAttacks(
    model?.modality,
    authed,
  );
  const { data: datasets = [], error: datasetsError } = useDatasets(authed);
  const { data: defenses = [], error: defensesError } = useDefenses(authed);
  const { data: capabilities, error: capabilitiesError } =
    useCapabilities(authed);
  const { roles } = useRoles();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [eps, setEps] = useState("0.03");
  const [samples, setSamples] = useState("200");
  const [seed, setSeed] = useState("0");
  const [explainK, setExplainK] = useState("8");
  const [llm, setLlm] = useState(false);
  const [epsGrid, setEpsGrid] = useState<number[]>([0.01, 0.03, 0.1]);
  const [datasetId, setDatasetId] = useState("");
  const [control, setControl] = useState(true);
  const [threshold, setThreshold] = useState("0.2");
  // `/models/{id}?attacks=a,b,c` from the Tests catalog: preselect once the
  // attack list has loaded (non-LLM targets only), one time per page load.
  const requestedAttacks = pageSearchParam(searchParams, "attacks");
  const preselectDone = useRef(false);
  const [preselect, setPreselect] = useState<{
    honoured: string[];
    skipped: string[];
  } | null>(null);
  useEffect(() => {
    if (
      preselectDone.current ||
      !requestedAttacks ||
      !model ||
      llmTarget ||
      attacks.length === 0
    )
      return;
    preselectDone.current = true;
    const wanted = [
      ...new Set(
        requestedAttacks
          .split(",")
          .map((id) => id.trim())
          .filter(Boolean),
      ),
    ];
    const honoured: string[] = [];
    const skipped: string[] = [];
    for (const id of wanted) {
      const a = attacks.find((x: AttackInfo) => x.id === id);
      const ok =
        !!a &&
        a.phase !== "B" &&
        a.status === "available" &&
        !(a.requires_gradients === true && model.manifest.gradients === false);
      (ok ? honoured : skipped).push(id);
    }
    if (honoured.length > 0) {
      setSelected((s: string[]) => [...new Set([...s, ...honoured])]);
    }
    setPreselect({ honoured, skipped });
  }, [requestedAttacks, model, llmTarget, attacks]);
  if (!authed) return <p>Signing in…</p>;
  const catalogError =
    modelError ??
    attacksError ??
    datasetsError ??
    defensesError ??
    capabilitiesError;
  const available =
    model?.status === "available" &&
    capabilities?.worker_ml_extra === true &&
    capabilities.sandbox_enabled === true;
  const referenceEps = Number(eps);
  const sampleCount = Number(samples);
  const selectedDataset = datasets.find(
    (dataset: DatasetInfo) => dataset.id === datasetId,
  );
  const modelDataset = datasets.find(
    (dataset: DatasetInfo) => dataset.id === model?.manifest.dataset_id,
  );
  const configIsValid =
    selected.length > 0 &&
    epsGrid.length > 0 &&
    epsGrid.includes(referenceEps) &&
    Boolean(
      selectedDataset &&
      model &&
      selectedDataset.compatible_modalities.includes(model.modality),
    ) &&
    sampleCount >= 50 &&
    sampleCount <= 500 &&
    Number(threshold) >= 0 &&
    Number(threshold) <= 1;
  const launch = async () => {
    if (!available || !configIsValid || !selectedDataset) return;
    setBusy(true);
    setErr("");
    const config: CampaignRequest = {
      attack_ids: selected,
      norm: "linf",
      eps_grid: epsGrid,
      reference_eps: referenceEps,
      dataset_id: selectedDataset.id,
      dataset_revision: selectedDataset.revision,
      n_samples: sampleCount,
      seed: Number(seed),
      include_control: control,
      finding_asr_threshold: Number(threshold),
      explain_k: Number(explainK),
      auto_recommend: true,
      llm_narrative: llm,
    };
    try {
      const out = await startCampaign(params.id, config);
      router.push(`/runs/${out.run_id}`);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-6">
      <header>
        <div className="redsim-kicker">model target / {params.id}</div>
        <h1 className="text-2xl font-semibold">
          {model ? modelDisplayName(model) : "Model detail"}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {model?.reason ??
            (llmTarget
              ? "Registered Pythia target, probe launcher, and recorded probe runs. Attack campaigns and the MRI never apply (D9)."
              : "Manifest, compatibility, and recorded campaign history.")}
        </p>
      </header>
      <div className="gap-4 lg:grid-cols-[1fr_1.3fr] grid">
        {llmTarget ? (
          <PanelSection title="LLM target" eyebrow="identity">
            <dl className="gap-4 text-sm grid grid-cols-2">
              <div>
                <dt className="redsim-kicker">target id</dt>
                <dd className="break-all">{model?.id ?? params.id}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">status</dt>
                <dd>{model?.status ?? "loading"}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">model id</dt>
                <dd className="font-mono break-all">
                  {text(model?.manifest.model_id) ?? "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">persona</dt>
                <dd>{text(model?.manifest.persona) ?? "not recorded"}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">guardrail mode</dt>
                <dd>
                  {text(model?.manifest.guardrail_mode)
                    ? `${guardrailLabel(String(model?.manifest.guardrail_mode))} (${String(model?.manifest.guardrail_mode)})`
                    : "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">gateway host</dt>
                <dd className="break-all">
                  {text(model?.manifest.gateway_host) ??
                    text(llmRow?.endpoint?.host) ??
                    "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">probe key (auth profile)</dt>
                <dd className="break-all">
                  {text(model?.manifest.auth_profile_id) ?? "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">garak version expected</dt>
                <dd>
                  {text(model?.manifest.garak_version_expected) ??
                    "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">entitlement</dt>
                <dd>
                  {llmRow?.validation?.entitlement ?? "not recorded"}
                  {typeof llmRow?.validation?.n_entitled === "number"
                    ? ` · ${llmRow.validation.n_entitled} models entitled`
                    : ""}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">domain</dt>
                <dd>{model?.modality ?? "—"}</dd>
              </div>
            </dl>
            {model?.refusal_reason && (
              <p className="mt-3 text-xs text-destructive">
                {model.refusal_reason}
              </p>
            )}
          </PanelSection>
        ) : (
          <PanelSection title="Manifest" eyebrow="identity">
            <dl className="gap-4 text-sm grid grid-cols-2">
              <div>
                <dt className="redsim-kicker">model id</dt>
                <dd className="break-all">{model?.id ?? params.id}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">status</dt>
                <dd>{model?.status ?? "loading"}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">domain</dt>
                <dd>{model?.modality ?? "—"}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">dataset</dt>
                <dd>{model?.manifest.dataset_id ?? "—"}</dd>
              </div>
              <div>
                <dt className="redsim-kicker">dataset revision</dt>
                <dd className="break-all">
                  {model?.manifest.dataset_revision ?? "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">dataset license</dt>
                <dd>
                  {modelDataset?.license ??
                    String(model?.manifest.license ?? "not recorded")}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">dataset compatibility</dt>
                <dd>
                  {modelDataset
                    ? modelDataset.compatible_modalities.includes(
                        model?.modality ?? "image",
                      )
                      ? "compatible"
                      : "incompatible"
                    : "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">clean accuracy</dt>
                <dd>
                  {formatCleanAccuracy(
                    model?.manifest.clean_accuracy,
                    model?.manifest.clean_n,
                  )}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">validation</dt>
                <dd>
                  {model?.validation?.detected_format ??
                    model?.status ??
                    "not recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">validation refusal</dt>
                <dd>
                  {model?.validation?.refusal_reason ??
                    model?.refusal_reason ??
                    "none recorded"}
                </dd>
              </div>
              <div>
                <dt className="redsim-kicker">ingest job</dt>
                <dd>{model?.validation?.ingest_job_id ?? "not recorded"}</dd>
              </div>
            </dl>
            {modelDataset?.role === "ci_fixture" && (
              <p className="mt-3 text-xs text-muted-foreground">
                {modelDataset.name} is a CI fixture — not the demo dataset.
              </p>
            )}
          </PanelSection>
        )}
        {llmTarget ? (
          <PanelSection title="Probe launcher" eyebrow="declare settings">
            <ProbeLauncher
              modelId={params.id}
              enabled={authed}
              available={model?.status === "available"}
              unavailableReason={model?.refusal_reason ?? model?.reason ?? null}
              callerRole={roles[model?.project_id ?? ""]}
              onStarted={(runId) => router.push(`/runs/${runId}`)}
            />
          </PanelSection>
        ) : (
          <PanelSection title="Campaign launcher" eyebrow="declare settings">
            <p className="mb-4 text-xs text-muted-foreground">
              Settings are recorded with this campaign and remain the comparison
              boundary.
            </p>
            {preselect && (
              <p className="mb-4 text-xs text-muted-foreground">
                Preselected from the Tests catalog:{" "}
                <span className="font-mono">
                  {preselect.honoured.join(", ") || "none"}
                </span>
                {preselect.skipped.length > 0
                  ? ` · skipped (unknown or not runnable on this target): ${preselect.skipped.join(", ")}`
                  : ""}
              </p>
            )}
            <div className="space-y-4">
              {(["A", "B"] as const).map((phase) => (
                <div key={phase}>
                  <div className="redsim-kicker">phase {phase}</div>
                  {attacks
                    .filter((a: AttackInfo) => a.phase === phase)
                    .map((a: AttackInfo) =>
                      (() => {
                        const blocked =
                          phase === "B" ||
                          a.status !== "available" ||
                          (a.requires_gradients === true &&
                            model?.manifest.gradients === false);
                        const reason =
                          a.reason ??
                          (a.requires_gradients &&
                          model?.manifest.gradients === false
                            ? "target has no differentiable estimator"
                            : undefined);
                        return (
                          <label
                            key={a.id}
                            className="gap-3 border-border py-2 text-sm flex items-center border-b"
                          >
                            <input
                              type="checkbox"
                              checked={selected.includes(a.id)}
                              disabled={blocked}
                              onChange={(e) =>
                                setSelected((s: string[]) =>
                                  e.target.checked
                                    ? [...s, a.id]
                                    : s.filter((x: string) => x !== a.id),
                                )
                              }
                            />{" "}
                            <span>{a.name}</span>
                            {phase === "B" && <LabelBadge variant="phase-b" />}
                            <span className="text-xs text-muted-foreground ml-auto">
                              {reason ?? a.family}
                            </span>
                          </label>
                        );
                      })(),
                    )}
                </div>
              ))}
              <div className="gap-3 text-sm grid grid-cols-2">
                <label className="col-span-2">
                  Dataset
                  <select
                    value={datasetId}
                    onChange={(e) => setDatasetId(e.target.value)}
                    className="mt-1 border-input bg-background px-2 py-1 w-full border"
                  >
                    <option value="">Select server dataset</option>
                    {datasets.map((dataset: DatasetInfo) => (
                      <option
                        key={dataset.id}
                        value={dataset.id}
                        disabled={
                          !!model &&
                          !dataset.compatible_modalities.includes(
                            model.modality,
                          )
                        }
                      >
                        {dataset.name} · {dataset.revision}
                        {model &&
                        !dataset.compatible_modalities.includes(model.modality)
                          ? ` · not compatible with ${model.modality} targets`
                          : ""}
                        {dataset.role === "ci_fixture"
                          ? " · CI fixture — not the demo dataset"
                          : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <fieldset className="col-span-2">
                  <legend className="redsim-kicker">ε grid</legend>
                  <div className="mt-1 gap-4 flex">
                    {[0.01, 0.03, 0.1].map((value) => (
                      <label key={value} className="gap-1 flex">
                        <input
                          type="checkbox"
                          checked={epsGrid.includes(value)}
                          onChange={(e) =>
                            setEpsGrid((current: number[]) => {
                              const next = e.target.checked
                                ? [...current, value].sort((a, b) => a - b)
                                : current.filter((item) => item !== value);
                              if (!next.includes(referenceEps) && next[0]) {
                                setEps(String(next[0]));
                              }
                              return next;
                            })
                          }
                        />
                        {value}
                      </label>
                    ))}
                  </div>
                </fieldset>
                <label>
                  Reference ε
                  <select
                    value={eps}
                    onChange={(e) => setEps(e.target.value)}
                    className="mt-1 border-input bg-background px-2 py-1 w-full border"
                  >
                    {epsGrid.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Samples
                  <input
                    type="number"
                    min="50"
                    max="500"
                    value={samples}
                    onChange={(e) => setSamples(e.target.value)}
                    className="mt-1 border-input bg-background px-2 py-1 w-full border"
                  />
                </label>
                <label>
                  Seed
                  <input
                    type="number"
                    value={seed}
                    onChange={(e) => setSeed(e.target.value)}
                    className="mt-1 border-input bg-background px-2 py-1 w-full border"
                  />
                </label>
                <label>
                  Explain k
                  <input
                    type="number"
                    min="0"
                    max="32"
                    value={explainK}
                    onChange={(e) => setExplainK(e.target.value)}
                    className="mt-1 border-input bg-background px-2 py-1 w-full border"
                  />
                </label>
                <label>
                  ASR threshold
                  <input
                    type="number"
                    min="0"
                    max="1"
                    step="0.01"
                    value={threshold}
                    onChange={(e) => setThreshold(e.target.value)}
                    className="mt-1 border-input bg-background px-2 py-1 w-full border"
                  />
                </label>
              </div>
              <label className="gap-2 text-sm flex">
                <input
                  type="checkbox"
                  checked={control}
                  onChange={(e) => setControl(e.target.checked)}
                />{" "}
                Include benign noise control
              </label>
              <div className="border-border bg-muted p-3 text-xs text-muted-foreground border">
                <div className="redsim-kicker">Scoring weights · read only</div>
                {capabilities?.scoring_weights
                  ? Object.entries(capabilities.scoring_weights)
                      .map(([name, value]) => `${name}=${value}`)
                      .join(" · ")
                  : "The deployment scoring policy is copied and snapshotted when the API admits this campaign."}{" "}
                Per-project scoring overrides are Phase B and cannot be edited
                here.
              </div>
              <label className="gap-2 text-sm flex">
                <input
                  type="checkbox"
                  checked={llm}
                  onChange={(e) => setLlm(e.target.checked)}
                  disabled={!capabilities?.llm_narrative?.configured}
                />{" "}
                LLM narrative{" "}
                {capabilities?.llm_narrative?.configured
                  ? ""
                  : "(unavailable: capability not configured)"}
              </label>
              <RoleGated
                minRole="scanner"
                callerRole={roles[model?.project_id ?? ""]}
              >
                <button
                  disabled={!available || busy || !configIsValid}
                  onClick={launch}
                  className="bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground w-full disabled:opacity-40"
                >
                  {busy ? "Starting campaign…" : "Start campaign"}
                </button>
              </RoleGated>
              {!available && (
                <p className="text-xs text-muted-foreground">
                  {model?.status !== "available"
                    ? "Launcher unavailable: " +
                      (model?.reason ?? "target status is not available.")
                    : "Launcher unavailable: worker ML capability is unavailable."}
                </p>
              )}
              {catalogError && (
                <p className="text-sm text-destructive">
                  Launcher dependencies are unavailable. Retry after the catalog
                  service is restored.
                </p>
              )}
              {!selectedDataset && datasets.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  Select a compatible dataset before launching.
                </p>
              )}
              {selectedDataset &&
                model &&
                !selectedDataset.compatible_modalities.includes(
                  model.modality,
                ) && (
                  <p className="text-xs text-destructive" role="alert">
                    {selectedDataset.name} does not support {model.modality}{" "}
                    targets. Choose a dataset whose compatible modalities
                    include {model.modality}.
                  </p>
                )}
              {defenses.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  Verify defenses available:{" "}
                  {defenses.map((d: DefenseInfo) => d.name).join(", ")}
                </p>
              )}
              {err && <p className="text-sm text-destructive">{err}</p>}
            </div>
          </PanelSection>
        )}
      </div>
      {llmTarget ? (
        <PanelSection title="Probe run history" eyebrow="recorded runs">
          {probeHistory.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No probe runs recorded for this target.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="text-xs w-full text-left">
                <thead>
                  <tr className="border-border border-b">
                    <th className="p-2">Run</th>
                    <th className="p-2">Probes</th>
                    <th className="p-2">Started</th>
                    <th className="p-2">Status</th>
                    <th className="p-2">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {probeHistory.map((run) => {
                    const ids = run.probe_ids ?? [];
                    return (
                      <tr key={run.run_id} className="border-border border-b">
                        <td className="p-2">
                          <a
                            className="text-primary underline"
                            href={`/runs/${run.run_id}`}
                          >
                            {run.run_id}
                          </a>
                        </td>
                        <td className="p-2">
                          {run.probe_set ? (
                            <span className="font-mono">{run.probe_set}</span>
                          ) : null}
                          {run.probe_set && ids.length ? " · " : ""}
                          {ids.length
                            ? `${ids.length} probe${ids.length === 1 ? "" : "s"}: ${ids
                                .slice(0, 6)
                                .join(", ")}${ids.length > 6 ? ", …" : ""}`
                            : run.probe_set
                              ? ""
                              : "not recorded"}
                        </td>
                        <td className="p-2 font-mono">
                          {run.created_at ?? "—"}
                        </td>
                        <td className="p-2">{run.status}</td>
                        <td className="p-2">
                          {run.scorecard_url ? (
                            <a
                              className="text-primary underline"
                              href={`/runs/${run.run_id}`}
                            >
                              scorecard
                            </a>
                          ) : (
                            "unavailable"
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </PanelSection>
      ) : (
        <PanelSection title="Campaign history" eyebrow="measured runs">
          {history.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No campaigns recorded for this model.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="text-xs w-full text-left">
                <thead>
                  <tr className="border-border border-b">
                    <th className="p-2">Run</th>
                    <th className="p-2">Attacks</th>
                    <th className="p-2">Reference ε</th>
                    <th className="p-2">Status</th>
                    <th className="p-2">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((run: CampaignHistory) => (
                    <tr key={run.run_id} className="border-border border-b">
                      <td className="p-2">
                        <a
                          className="text-primary underline"
                          href={`/runs/${run.run_id}`}
                        >
                          {run.run_id}
                        </a>
                      </td>
                      <td className="p-2">{run.attacks.join(", ")}</td>
                      <td className="p-2 font-mono">{run.reference_eps}</td>
                      <td className="p-2">{run.status}</td>
                      <td className="p-2">
                        {run.scorecard_available ? (
                          <a
                            className="text-primary underline"
                            href={`/runs/${run.run_id}`}
                          >
                            scorecard
                          </a>
                        ) : (
                          "unavailable"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </PanelSection>
      )}
    </div>
  );
}
