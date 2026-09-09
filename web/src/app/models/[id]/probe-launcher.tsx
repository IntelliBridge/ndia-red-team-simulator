"use client";
// ProbeLauncher — the garak probe form for an LLM target (spec 17.4,
// POST /v1/models/{id}/probes). Replaces the adversarial-ML campaign
// launcher on /models/[id] when isLlmTarget(model) holds: no attacks, no ε,
// no dataset, no MRI (D9). Exactly one of probe_set / probe_ids is sent.
import { useMemo, useState } from "react";
import { RoleGated } from "@redsim/design-system";
import { ApiError, mlErrorDetail } from "@/lib/api";
import {
  startProbeRun,
  type ProbeInfo,
  type StartProbeRunBody,
} from "@/lib/llm";
import { useProbeCatalog } from "@/hooks/useLlm";

export type ProbeLauncherProps = {
  modelId: string;
  /** Auth resolved; catalog fetch may start. */
  enabled: boolean;
  /** Target status is "available"; launching is otherwise refused server side. */
  available: boolean;
  unavailableReason?: string | null;
  callerRole: string | undefined;
  onStarted: (runId: string) => void;
};

const inputClass = "mt-1 w-full border border-input bg-background px-2 py-1";

function describeError(e: unknown): string {
  const d = mlErrorDetail(e);
  const status = e instanceof ApiError ? `HTTP ${e.status}` : null;
  const head = [status, d.code].filter(Boolean).join(" ");
  const parts = [head ? `${head}: ` : "", d.message ?? String(e)];
  if (d.field) parts.push(` (field: ${d.field})`);
  if (d.reasons?.length) parts.push(` — ${d.reasons.join("; ")}`);
  return parts.join("");
}

export function ProbeLauncher({
  modelId,
  enabled,
  available,
  unavailableReason,
  callerRole,
  onStarted,
}: ProbeLauncherProps) {
  const {
    data: catalog,
    error: catalogError,
    isLoading,
  } = useProbeCatalog(enabled);
  const [mode, setMode] = useState<"set" | "pick">("set");
  const [probeSetChoice, setProbeSetChoice] = useState<string | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [maxPrompts, setMaxPrompts] = useState("5");
  const [seed, setSeed] = useState("0");
  const [detectorMode, setDetectorMode] = useState<"offline" | "hf">("offline");
  const [threshold, setThreshold] = useState("0.2");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const hf = catalog?.hf_detectors_enabled === true;
  const effectiveDetector: "offline" | "hf" = hf ? detectorMode : "offline";
  const maxAllowed = catalog?.max_prompts_per_probe ?? 64;
  const probeSet =
    probeSetChoice ?? catalog?.default_probe_set ?? catalog?.sets[0]?.id ?? "";
  const selectedSet = catalog?.sets.find((s) => s.id === probeSet);

  const families = useMemo(() => {
    const groups = new Map<string, ProbeInfo[]>();
    for (const probe of catalog?.probes ?? []) {
      const list = groups.get(probe.family) ?? [];
      list.push(probe);
      groups.set(probe.family, list);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [catalog]);

  const probeDisabled = (p: ProbeInfo): string | null => {
    if (p.status === "excluded") return p.reason ?? "excluded by the catalog";
    if (p.status === "extended" && effectiveDetector !== "hf") {
      return hf
        ? "needs detector_mode=hf"
        : "needs a Hugging Face detector; HF detectors are not enabled";
    }
    return null;
  };

  const maxPromptsN = Number(maxPrompts);
  const thresholdN = Number(threshold);
  const nProbes =
    mode === "set"
      ? selectedSet
        ? effectiveDetector === "hf"
          ? selectedSet.n_probes
          : selectedSet.n_offline
        : 0
      : picked.length;
  const estimate = nProbes * (Number.isFinite(maxPromptsN) ? maxPromptsN : 0);

  const configIsValid =
    !!catalog &&
    (mode === "set" ? !!selectedSet : picked.length > 0) &&
    Number.isInteger(maxPromptsN) &&
    maxPromptsN >= 1 &&
    maxPromptsN <= maxAllowed &&
    Number.isInteger(Number(seed)) &&
    Number(seed) >= 0 &&
    thresholdN > 0 &&
    thresholdN <= 1;

  const launch = async () => {
    if (!available || !configIsValid || busy) return;
    setBusy(true);
    setErr("");
    const body: StartProbeRunBody = {
      max_prompts_per_probe: maxPromptsN,
      seed: Number(seed),
      detector_mode: effectiveDetector,
      finding_hit_threshold: thresholdN,
      ...(mode === "set" ? { probe_set: probeSet } : { probe_ids: picked }),
    };
    try {
      const out = await startProbeRun(modelId, body);
      onStarted(out.run_id);
    } catch (e) {
      setErr(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        garak {catalog?.garak_version ?? "…"} probes run through the Pythia
        gateway against the registered persona. Probe set, prompt cap, seed and
        detector mode are recorded with the run; no MRI or grade is derived
        (D9).
      </p>

      <fieldset className="text-sm">
        <legend className="redsim-kicker">probes</legend>
        <div className="mt-1 gap-4 flex">
          {(
            [
              ["set", "Probe set"],
              ["pick", "Pick probes"],
            ] as const
          ).map(([value, label]) => (
            <label key={value} className="gap-1 flex">
              <input
                type="radio"
                name="probe-mode"
                value={value}
                checked={mode === value}
                onChange={() => setMode(value)}
              />
              {label}
            </label>
          ))}
        </div>
      </fieldset>

      {mode === "set" ? (
        <label className="text-sm block">
          Probe set
          <select
            value={probeSet}
            onChange={(e) => setProbeSetChoice(e.target.value)}
            disabled={!catalog}
            className={inputClass}
          >
            {!catalog && <option value="">Loading catalog…</option>}
            {catalog?.sets.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} · {s.n_probes} probes · {s.n_offline} offline
                {s.n_excluded ? ` · ${s.n_excluded} excluded` : ""}
              </option>
            ))}
          </select>
          {selectedSet &&
            effectiveDetector === "offline" &&
            selectedSet.n_offline < selectedSet.n_probes && (
              <span className="mt-1 text-xs text-muted-foreground block">
                {selectedSet.n_probes - selectedSet.n_offline} extended probes
                in this set need detector_mode=hf and will not run.
              </span>
            )}
        </label>
      ) : (
        <div className="max-h-96 space-y-3 border-border p-2 text-sm overflow-y-auto border">
          {!catalog && (
            <p className="text-xs text-muted-foreground">Loading catalog…</p>
          )}
          {families.map(([family, probes]) => (
            <div key={family}>
              <div className="redsim-kicker">{family}</div>
              {probes.map((p) => {
                const blocked = probeDisabled(p);
                return (
                  <label
                    key={p.id}
                    className="gap-3 border-border py-2 flex items-start border-b"
                  >
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={picked.includes(p.id)}
                      disabled={blocked !== null}
                      onChange={(e) =>
                        setPicked((s) =>
                          e.target.checked
                            ? [...s, p.id]
                            : s.filter((x) => x !== p.id),
                        )
                      }
                    />
                    <span className="flex-1">
                      <span className="font-mono text-xs">{p.short_id}</span>
                      <span className="text-xs text-muted-foreground block">
                        {p.goal}
                      </span>
                    </span>
                    <span className="text-xs text-muted-foreground ml-auto max-w-[40%] text-right">
                      {blocked ??
                        `${p.status ?? "offline"} · ${p.tier === null || p.tier === 9 ? "unranked" : `tier ${p.tier}`}`}
                    </span>
                  </label>
                );
              })}
            </div>
          ))}
        </div>
      )}

      <div className="gap-3 text-sm grid grid-cols-2">
        <label>
          Max prompts per probe
          <input
            type="number"
            min="1"
            max={maxAllowed}
            step="1"
            value={maxPrompts}
            onChange={(e) => setMaxPrompts(e.target.value)}
            className={inputClass}
          />
          <span className="mt-1 text-xs text-muted-foreground block">
            1 to {maxAllowed}
          </span>
        </label>
        <label>
          Seed
          <input
            type="number"
            min="0"
            step="1"
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
            className={inputClass}
          />
        </label>
        <label>
          Detector mode
          {hf ? (
            <select
              value={detectorMode}
              onChange={(e) =>
                setDetectorMode(e.target.value === "hf" ? "hf" : "offline")
              }
              className={inputClass}
            >
              <option value="offline">offline</option>
              <option value="hf">hf</option>
            </select>
          ) : (
            <input
              type="text"
              value="offline"
              readOnly
              disabled
              className={inputClass}
            />
          )}
          <span className="mt-1 text-xs text-muted-foreground block">
            {hf
              ? catalog?.statuses.extended
              : "HF detectors are not enabled on this API"}
          </span>
        </label>
        <label>
          Finding hit threshold
          <input
            type="number"
            min="0.01"
            max="1"
            step="0.01"
            value={threshold}
            onChange={(e) => setThreshold(e.target.value)}
            className={inputClass}
          />
          <span className="mt-1 text-xs text-muted-foreground block">
            above 0, at most 1
          </span>
        </label>
      </div>

      <div className="border-border bg-muted p-3 text-xs text-muted-foreground border">
        <div className="redsim-kicker">Prompt estimate</div>
        {nProbes} probes × {Number.isFinite(maxPromptsN) ? maxPromptsN : 0}{" "}
        prompts ≈ <span className="font-mono">{estimate}</span> prompts at most;
        each probe corpus may be smaller than the cap.
      </div>

      <RoleGated minRole="remediator" callerRole={callerRole}>
        <button
          disabled={!available || busy || !configIsValid}
          onClick={launch}
          className="bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground w-full disabled:opacity-40"
        >
          {busy ? "Starting probe run…" : "Start probe run"}
        </button>
      </RoleGated>

      {!available && (
        <p className="text-xs text-muted-foreground">
          Launcher unavailable:{" "}
          {unavailableReason ?? "target status is not available."}
        </p>
      )}
      {mode === "pick" && catalog && picked.length === 0 && (
        <p className="text-xs text-muted-foreground">
          Pick at least one probe before launching.
        </p>
      )}
      {isLoading && (
        <p className="text-xs text-muted-foreground">Loading probe catalog…</p>
      )}
      {catalogError && (
        <p className="text-sm text-destructive">
          Probe catalog unavailable: {describeError(catalogError)}
        </p>
      )}
      {err && (
        <p className="text-sm text-destructive" role="alert">
          {err}
        </p>
      )}
      {catalog?.limitations?.length ? (
        <details className="text-xs text-muted-foreground">
          <summary>Standing limitations ({catalog.limitations.length})</summary>
          <ul className="mt-1 space-y-1 pl-4 list-disc">
            {catalog.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}
