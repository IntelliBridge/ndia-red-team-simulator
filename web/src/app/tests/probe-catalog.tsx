"use client";
// ProbeCatalog — the garak-via-Pythia half of /tests. Catalogues every LLM
// probe the platform can run (GET /v1/llm/probes) and launches a run against
// a registered LLM target right here (POST /v1/models/{id}/probes). Exactly
// one of probe_set / probe_ids is sent per request; no other keys. Results
// are k/n hits per probe and detector; no MRI or grade is derived (D9).
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { PanelSection, RoleGated } from "@redsim/design-system";
import { ApiError, mlErrorDetail, type ModelTarget } from "@/lib/api";
import {
  isLlmTarget,
  startProbeRun,
  type DetectorMode,
  type ProbeInfo,
  type ProbeStatus,
  type StartProbeRunBody,
} from "@/lib/llm";
import { useProbeCatalog } from "@/hooks/useLlm";
import { rowLink } from "@/lib/row-link";
import { useModels } from "@/hooks/useModels";
import { useRoles } from "@/hooks/useRoles";

const TARGET_KEY = "redsim.tests.llmTarget";
const inputClass = "redsim-input mt-1";
const chipClass = "redsim-chip";
const smallButton = "redsim-ghost redsim-btn-sm";

function describeError(e: unknown): string {
  const d = mlErrorDetail(e);
  const status = e instanceof ApiError ? `HTTP ${e.status}` : null;
  const head = [status, d.code].filter(Boolean).join(" ");
  const parts = [head ? `${head}: ` : "", d.message ?? String(e)];
  if (d.field) parts.push(` (field: ${d.field})`);
  if (d.reasons?.length) parts.push(` — ${d.reasons.join("; ")}`);
  return parts.join("");
}

function targetLabel(m: ModelTarget): string {
  const modelId = m.manifest?.model_id;
  const persona = m.manifest?.persona;
  if (typeof modelId === "string") {
    return typeof persona === "string" ? `${modelId} · ${persona}` : modelId;
  }
  return m.name;
}

function tierLabel(tier: number | null): string {
  return tier === null || tier === 9 ? "unranked" : `tier ${tier}`;
}

function StatusBadge({ probe, hf }: { probe: ProbeInfo; hf: boolean }) {
  const status: ProbeStatus = probe.status ?? "offline";
  if (status === "offline") {
    return (
      <span className={`${chipClass} border-data-adv/60 text-data-adv`}>
        runnable
      </span>
    );
  }
  if (status === "extended") {
    return (
      <span
        className={`${chipClass} ${hf ? "" : "text-ink-3"}`}
        title={
          hf
            ? "runs with detector_mode=hf"
            : "needs a Hugging Face detector; HF detectors are not enabled on this API"
        }
      >
        {hf ? "extended · hf" : "needs HF detectors"}
      </span>
    );
  }
  return (
    <span
      className={`${chipClass} border-destructive/30 text-destructive`}
      title={probe.reason ?? "excluded by the catalog"}
    >
      excluded
    </span>
  );
}

export function ProbeCatalog({ enabled }: { enabled: boolean }) {
  const router = useRouter();
  const { roles } = useRoles();
  const projectId = Object.keys(roles)[0] ?? null;
  const callerRole = projectId ? roles[projectId] : undefined;
  const {
    data: catalog,
    error: catalogError,
    isLoading,
  } = useProbeCatalog(enabled);
  const { data: models = [] } = useModels(enabled ? projectId : null);

  // ── Target ────────────────────────────────────────────────────────
  const llmTargets = useMemo(
    () =>
      models.filter(
        (m) =>
          isLlmTarget(m) &&
          (m as { registered?: boolean }).registered !== false &&
          m.status === "available",
      ),
    [models],
  );
  const [targetChoice, setTargetChoice] = useState<string | null>(null);
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(TARGET_KEY);
      if (saved) setTargetChoice(saved);
    } catch {
      /* storage unavailable */
    }
  }, []);
  const targetId =
    targetChoice && llmTargets.some((m) => m.id === targetChoice)
      ? targetChoice
      : (llmTargets[0]?.id ?? "");
  const target = llmTargets.find((m) => m.id === targetId);
  const chooseTarget = (id: string) => {
    setTargetChoice(id);
    try {
      window.localStorage.setItem(TARGET_KEY, id);
    } catch {
      /* storage unavailable */
    }
  };

  // ── Run controls ──────────────────────────────────────────────────
  const [maxPrompts, setMaxPrompts] = useState("5");
  const [seed, setSeed] = useState("0");
  const [detectorMode, setDetectorMode] = useState<DetectorMode>("offline");
  const [threshold, setThreshold] = useState("0.2");
  const hf = catalog?.hf_detectors_enabled === true;
  const effectiveDetector: DetectorMode = hf ? detectorMode : "offline";
  const maxAllowed = catalog?.max_prompts_per_probe ?? 64;
  const maxPromptsN = Number(maxPrompts);
  const thresholdN = Number(threshold);
  const controlsValid =
    Number.isInteger(maxPromptsN) &&
    maxPromptsN >= 1 &&
    maxPromptsN <= maxAllowed &&
    Number.isInteger(Number(seed)) &&
    Number(seed) >= 0 &&
    thresholdN > 0 &&
    thresholdN <= 1;

  // ── Selection and filters ─────────────────────────────────────────
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | ProbeStatus>("all");
  const [onlySelected, setOnlySelected] = useState(false);

  const runnable = (p: ProbeInfo): boolean => {
    const s = p.status ?? "offline";
    if (s === "offline") return true;
    if (s === "extended") return effectiveDetector === "hf";
    return false;
  };
  const blockedReason = (p: ProbeInfo): string | null => {
    if (p.status === "excluded") return p.reason ?? "excluded by the catalog";
    if (p.status === "extended" && effectiveDetector !== "hf") {
      return hf
        ? "needs detector_mode=hf"
        : "needs a Hugging Face detector; HF detectors are not enabled";
    }
    return null;
  };

  const families = useMemo(() => {
    const groups = new Map<string, ProbeInfo[]>();
    for (const probe of catalog?.probes ?? []) {
      const list = groups.get(probe.family) ?? [];
      list.push(probe);
      groups.set(probe.family, list);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [catalog]);

  const q = query.trim().toLowerCase();
  const matches = (p: ProbeInfo): boolean => {
    if (statusFilter !== "all" && (p.status ?? "offline") !== statusFilter)
      return false;
    if (onlySelected && !selected.has(p.id)) return false;
    if (!q) return true;
    return (
      p.id.toLowerCase().includes(q) ||
      p.goal.toLowerCase().includes(q) ||
      p.family.toLowerCase().includes(q)
    );
  };

  const toggle = (id: string, on: boolean) =>
    setSelected((s) => {
      const next = new Set(s);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  const setMany = (ids: string[], on: boolean) =>
    setSelected((s) => {
      const next = new Set(s);
      for (const id of ids) {
        if (on) next.add(id);
        else next.delete(id);
      }
      return next;
    });

  // Selected ids that are runnable under the current detector mode.
  const selectedRunnable = (catalog?.probes ?? [])
    .filter((p) => selected.has(p.id) && runnable(p))
    .map((p) => p.id);

  // ── Launch ────────────────────────────────────────────────────────
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const controls = (): Pick<
    StartProbeRunBody,
    "max_prompts_per_probe" | "seed" | "detector_mode" | "finding_hit_threshold"
  > => ({
    max_prompts_per_probe: maxPromptsN,
    seed: Number(seed),
    detector_mode: effectiveDetector,
    finding_hit_threshold: thresholdN,
  });
  const launch = async (
    key: string,
    selection: { probe_set: string } | { probe_ids: string[] },
  ) => {
    if (!targetId || !controlsValid || busy) return;
    setBusy(key);
    setErr("");
    const body: StartProbeRunBody = { ...selection, ...controls() };
    try {
      const out = await startProbeRun(targetId, body);
      router.push(`/runs/${out.run_id}`);
    } catch (e) {
      setErr(describeError(e));
      setBusy(null);
    }
  };
  const canLaunch = !!targetId && controlsValid && !busy && !!catalog;

  const coreSet = catalog?.sets.find((s) => s.id === "redsim-core");
  const extendedSet = catalog?.sets.find((s) => s.id === "redsim-extended");

  return (
    <div className="space-y-4">
      {/* ── Summary strip ─────────────────────────────────────────── */}
      <section aria-label="LLM probe summary">
        <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-4">
          <div className="redsim-stat">
            <div className="redsim-kicker">offline · runnable</div>
            <div className="redsim-numeral text-3xl">
              {catalog?.counts.offline ?? "…"}
            </div>
            <div className="redsim-stat-note">
              {catalog?.statuses.offline}
            </div>
          </div>
          <div className="redsim-stat">
            <div className="redsim-kicker">extended</div>
            <div className="redsim-numeral text-3xl">
              {catalog?.counts.extended ?? "…"}
            </div>
            <div className="redsim-stat-note">
              {catalog?.statuses.extended}
            </div>
          </div>
          <div className="redsim-stat">
            <div className="redsim-kicker">excluded</div>
            <div className="redsim-numeral text-3xl">
              {catalog?.counts.excluded ?? "…"}
            </div>
            <div className="redsim-stat-note">
              {catalog?.statuses.excluded}
            </div>
          </div>
          <div className="redsim-stat">
            <div className="redsim-kicker">garak</div>
            <div className="redsim-numeral font-mono text-3xl">
              {catalog?.garak_version ?? "…"}
            </div>
            <div className="redsim-stat-note">
              {catalog?.count ?? "…"} probes ·{" "}
              {hf ? "HF detectors enabled" : "offline detectors only"}
            </div>
          </div>
        </div>
      </section>

      {/* ── Run parameters ─────────────────────────────────────── */}
      <section className="redsim-panel p-5" aria-label="Probe run parameters">
        <div className="grid gap-4 text-sm md:grid-cols-[2fr_1fr_1fr_1fr_1fr]">
          <label className="block text-sm">
            Target
            {llmTargets.length > 0 ? (
              <select
                value={targetId}
                onChange={(e) => chooseTarget(e.target.value)}
                className={inputClass}
              >
                {llmTargets.map((m) => (
                  <option key={m.id} value={m.id}>
                    {targetLabel(m)}
                  </option>
                ))}
              </select>
            ) : (
              <div className="mt-1 text-xs text-ink-3">
                No available LLM target is registered.{" "}
                <Link href="/models" className="redsim-link">
                  Register an LLM target
                </Link>
                .
              </div>
            )}
            {target && (
              <span className="mt-1 block font-mono text-xs text-ink-3">
                {target.id}
              </span>
            )}
          </label>
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
            <span className="mt-1 block text-xs text-ink-3">
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
            <span className="mt-1 block text-xs text-ink-3">
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
            <span className="mt-1 block text-xs text-ink-3">
              above 0, at most 1
            </span>
          </label>
        </div>

        {/* ── Quick actions ───────────────────────────────────────── */}
        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-4">
          <span className="redsim-kicker mr-2">quick actions</span>
          <RoleGated minRole="remediator" callerRole={callerRole}>
            <button
              disabled={!canLaunch || !coreSet}
              onClick={() => launch("core", { probe_set: "redsim-core" })}
              className="redsim-cta redsim-btn-sm"
              title={
                coreSet
                  ? `${coreSet.n_probes} probes · ${coreSet.n_offline} offline`
                  : "redsim-core set not in catalog"
              }
            >
              {busy === "core" ? "Starting…" : "Run redsim-core set"}
              {coreSet ? ` (${coreSet.n_offline})` : ""}
            </button>
            {extendedSet && (
              <button
                disabled={!canLaunch}
                onClick={() =>
                  launch("extended", { probe_set: "redsim-extended" })
                }
                className="redsim-ghost redsim-btn-sm"
                title={`${extendedSet.n_probes} probes · ${extendedSet.n_offline} offline${
                  effectiveDetector === "offline" &&
                  extendedSet.n_offline < extendedSet.n_probes
                    ? ` · ${extendedSet.n_probes - extendedSet.n_offline} extended probes will not run without detector_mode=hf`
                    : ""
                }`}
              >
                {busy === "extended" ? "Starting…" : "Run redsim-extended set"}
                {` (${effectiveDetector === "hf" ? extendedSet.n_probes : extendedSet.n_offline})`}
              </button>
            )}
          </RoleGated>
          {!targetId && (
            <span className="text-xs text-ink-3">
              Choose an available LLM target to run anything.
            </span>
          )}
        </div>
        {isLoading && (
          <p className="mt-3 text-xs text-ink-3">
            Loading probe catalog…
          </p>
        )}
        {catalogError && (
          <p className="mt-3 text-sm text-destructive" role="alert">
            Probe catalog unavailable: {describeError(catalogError)}
          </p>
        )}
      </section>

      {/* ── Filter bar ───────────────────────────────────────────── */}
      <div className="flex flex-wrap items-end gap-3 text-sm">
        <label className="min-w-64 flex-1">
          Filter
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="probe id, goal or family"
            className={inputClass}
          />
        </label>
        <label>
          Status
          <select
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value as "all" | ProbeStatus)
            }
            className={inputClass}
          >
            <option value="all">all</option>
            <option value="offline">offline (runnable)</option>
            <option value="extended">extended</option>
            <option value="excluded">excluded</option>
          </select>
        </label>
        <label className="flex items-center gap-2 pb-2">
          <input
            type="checkbox"
            checked={onlySelected}
            onChange={(e) => setOnlySelected(e.target.checked)}
          />
          only selected
        </label>
        <button
          className={`${smallButton} mb-1`}
          disabled={selected.size === 0}
          onClick={() => setSelected(new Set())}
        >
          Clear selection
        </button>
        <span className="pb-2 text-xs text-ink-3">
          {selected.size} selected · {selectedRunnable.length} runnable
        </span>
      </div>

      {/* ── Catalog table, grouped by family ─────────────────────── */}
      <div className="space-y-2">
        {families.map(([family, probes]) => {
          const visible = probes.filter(matches);
          if (visible.length === 0) return null;
          const runnableIds = probes.filter(runnable).map((p) => p.id);
          const visibleRunnable = visible.filter(runnable).map((p) => p.id);
          const allChecked =
            visibleRunnable.length > 0 &&
            visibleRunnable.every((id) => selected.has(id));
          const someChecked =
            !allChecked && visibleRunnable.some((id) => selected.has(id));
          return (
            <details
              key={family}
              open
              className="border-t border-line-strong py-2"
            >
              <summary className="flex cursor-pointer flex-wrap items-center gap-3 px-3 py-2 text-sm">
                <input
                  type="checkbox"
                  aria-label={`Select all runnable probes in ${family}`}
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked;
                  }}
                  disabled={visibleRunnable.length === 0}
                  onClick={(e) => e.stopPropagation()}
                  onChange={(e) => setMany(visibleRunnable, e.target.checked)}
                />
                <span className="font-mono font-semibold text-ink-1">{family}</span>
                <span className="text-xs text-ink-3">
                  {probes.length} probes · {runnableIds.length} runnable
                  {visible.length !== probes.length
                    ? ` · ${visible.length} shown`
                    : ""}
                </span>
              </summary>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-line">
                      <th className="w-8 px-3 py-2" />
                      <th className="px-3 py-2 font-medium">Probe</th>
                      <th className="px-3 py-2 font-medium">Goal</th>
                      <th className="px-3 py-2 font-medium">Tier</th>
                      <th className="px-3 py-2 font-medium">Status</th>
                      <th className="px-3 py-2 font-medium">Primary detector</th>
                      <th className="px-3 py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((p) => {
                      const blocked = blockedReason(p);
                      const isSelected = selected.has(p.id);
                      return (
                        <tr
                          key={p.id}
                          {...rowLink(`/tests/probes/${encodeURIComponent(p.id)}`)}
                          className={`border-b border-line last:border-0 ${blocked ? "text-ink-3" : ""} ${isSelected ? "bg-surface-2" : ""} ${rowLink("").className}`}
                        >
                          <td className="px-3 py-2 align-top">
                            <input
                              type="checkbox"
                              aria-label={`Select ${p.id}`}
                              checked={isSelected}
                              disabled={blocked !== null}
                              onChange={(e) => toggle(p.id, e.target.checked)}
                            />
                          </td>
                          <td className="px-3 py-2 align-top">
                            <div className="font-mono text-ink-1">{p.short_id}</div>
                            <div className="font-mono text-[11px] text-ink-3">
                              {p.id}
                            </div>
                          </td>
                          <td className="max-w-md px-3 py-2 align-top">
                            {p.goal}
                            {p.status === "excluded" && p.reason && (
                              <div className="mt-1 text-[11px] text-ink-3">
                                {p.reason}
                              </div>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 align-top">
                            {tierLabel(p.tier)}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 align-top">
                            <StatusBadge probe={p} hf={hf} />
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 align-top font-mono">
                            {p.primary_detector}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 align-top text-right">
                            <RoleGated
                              minRole="remediator"
                              callerRole={callerRole}
                            >
                              <button
                                className={smallButton}
                                disabled={!canLaunch || blocked !== null}
                                title={blocked ?? `Run ${p.id} on the selected target`}
                                onClick={() =>
                                  launch(`probe:${p.id}`, { probe_ids: [p.id] })
                                }
                              >
                                {busy === `probe:${p.id}` ? "Starting…" : "Run"}
                              </button>
                            </RoleGated>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </details>
          );
        })}
        {catalog && families.every(([, ps]) => ps.filter(matches).length === 0) && (
          <p className="text-sm text-ink-3">
            No probes match the current filter.
          </p>
        )}
      </div>

      {/* ── Sticky action bar ────────────────────────────────────── */}
      <div className="redsim-panel sticky bottom-2 z-10 flex flex-wrap items-center justify-between gap-3 p-3 shadow-lg">
        <div className="text-xs text-ink-3">
          {selectedRunnable.length} probe{selectedRunnable.length === 1 ? "" : "s"} selected.
          {selected.size > selectedRunnable.length && (
            <span>
              {" "}
              {selected.size - selectedRunnable.length} selected probe(s) are
              not runnable in detector_mode={effectiveDetector} and are
              omitted.
            </span>
          )}
        </div>
        <RoleGated minRole="remediator" callerRole={callerRole}>
          <button
            disabled={!canLaunch || selectedRunnable.length === 0}
            onClick={() => launch("selected", { probe_ids: selectedRunnable })}
            className="redsim-cta"
          >
            {busy === "selected"
              ? "Starting probe run…"
              : `Run ${selectedRunnable.length} selected probe${selectedRunnable.length === 1 ? "" : "s"} on ${
                  target ? targetLabel(target) : "…"
                }`}
          </button>
        </RoleGated>
      </div>
      {err && (
        <p
          className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
          role="alert"
        >
          {err}
        </p>
      )}

      {/* ── Footer ───────────────────────────────────────────────── */}
      <footer className="space-y-2 text-xs text-ink-3">
        {catalog?.limitations?.length ? (
          <details>
            <summary className="cursor-pointer">
              Standing limitations ({catalog.limitations.length})
            </summary>
            <ul className="mt-1 list-disc space-y-1 pl-4">
              {catalog.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </details>
        ) : null}
        <p>
          Results are k/n hits per probe and detector; no MRI or grade is
          derived from LLM probes (D9).
        </p>
      </footer>
    </div>
  );
}
