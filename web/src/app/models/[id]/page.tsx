"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { PanelSection, RoleGated, LabelBadge } from "@redsim/design-system";
import {
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
export default function ModelPage({ params }: { params: { id: string } }) {
  const authed = useRequireAuth();
  const router = useRouter();
  const { data: model, error: modelError } = useModel(
    authed ? params.id : null,
  );
  const history = model?.campaign_history ?? [];
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
  if (!authed) return <p>Redirecting to sign in…</p>;
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
        <h1 className="text-3xl font-semibold">
          {model?.name ?? "Model detail"}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {model?.reason ??
            "Manifest, compatibility, and recorded campaign history."}
        </p>
      </header>
      <div className="grid gap-4 lg:grid-cols-[1fr_1.3fr]">
        <PanelSection title="Manifest" eyebrow="identity">
          <dl className="grid grid-cols-2 gap-4 text-sm">
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
                {model?.manifest.clean_accuracy ?? "—"}{" "}
                {model?.manifest.clean_n ? `(n=${model.manifest.clean_n})` : ""}
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
              <dd>
                {model?.validation?.ingest_job_id ?? "not recorded"}
              </dd>
            </div>
          </dl>
          {modelDataset?.role === "ci_fixture" && (
            <p className="mt-3 text-xs text-muted-foreground">
              {modelDataset.name} is a CI fixture — not the demo dataset.
            </p>
          )}
        </PanelSection>
        <PanelSection title="Campaign launcher" eyebrow="declare settings">
          <p className="mb-4 text-xs text-muted-foreground">
            Settings are recorded with this campaign and remain the comparison
            boundary.
          </p>
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
                          className="flex items-center gap-3 border-b border-border py-2 text-sm"
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
                          <span className="ml-auto text-xs text-muted-foreground">
                            {reason ?? a.family}
                          </span>
                        </label>
                      );
                    })(),
                  )}
              </div>
            ))}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <label className="col-span-2">
                Dataset
                <select
                  value={datasetId}
                  onChange={(e) => setDatasetId(e.target.value)}
                  className="mt-1 w-full border border-input bg-background px-2 py-1"
                >
                  <option value="">Select server dataset</option>
                  {datasets.map((dataset: DatasetInfo) => (
                    <option
                      key={dataset.id}
                      value={dataset.id}
                      disabled={
                        !!model &&
                        !dataset.compatible_modalities.includes(model.modality)
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
                <div className="mt-1 flex gap-4">
                  {[0.01, 0.03, 0.1].map((value) => (
                    <label key={value} className="flex gap-1">
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
                  className="mt-1 w-full border border-input bg-background px-2 py-1"
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
                  className="mt-1 w-full border border-input bg-background px-2 py-1"
                />
              </label>
              <label>
                Seed
                <input
                  type="number"
                  value={seed}
                  onChange={(e) => setSeed(e.target.value)}
                  className="mt-1 w-full border border-input bg-background px-2 py-1"
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
                  className="mt-1 w-full border border-input bg-background px-2 py-1"
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
                  className="mt-1 w-full border border-input bg-background px-2 py-1"
                />
              </label>
            </div>
            <label className="flex gap-2 text-sm">
              <input
                type="checkbox"
                checked={control}
                onChange={(e) => setControl(e.target.checked)}
              />{" "}
              Include benign noise control
            </label>
            <div className="border border-border bg-muted p-3 text-xs text-muted-foreground">
              <div className="redsim-kicker">Scoring weights · read only</div>
              {capabilities?.scoring_weights
                ? Object.entries(capabilities.scoring_weights)
                    .map(([name, value]) => `${name}=${value}`)
                    .join(" · ")
                : "The deployment scoring policy is copied and snapshotted when the API admits this campaign."}{" "}
              Per-project scoring overrides are Phase B and cannot be edited
              here.
            </div>
            <label className="flex gap-2 text-sm">
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
                disabled={
                  !available ||
                  busy ||
                  !configIsValid
                }
                onClick={launch}
                className="w-full bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-40"
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
              !selectedDataset.compatible_modalities.includes(model.modality) && (
                <p className="text-xs text-destructive" role="alert">
                  {selectedDataset.name} does not support {model.modality} targets. Choose a
                  dataset whose compatible modalities include {model.modality}.
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
      </div>
      <PanelSection title="Campaign history" eyebrow="measured runs">
        {history.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No campaigns recorded for this model.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border">
                  <th className="p-2">Run</th>
                  <th className="p-2">Attacks</th>
                  <th className="p-2">Reference ε</th>
                  <th className="p-2">Status</th>
                  <th className="p-2">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {history.map((run: CampaignHistory) => (
                  <tr key={run.run_id} className="border-b border-border">
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
    </div>
  );
}
