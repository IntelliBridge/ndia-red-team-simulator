"use client";
import { useEffect, useMemo, useRef } from "react";
import Link from "next/link";
import useSWR from "swr";
import { listAuthProfiles } from "@/lib/api";
import {
  GUARDRAIL_MODES,
  guardrailLabel,
  type GuardrailMode,
} from "@/lib/llm";
import { usePythiaModels } from "@/hooks/useLlm";

export type LlmFormState = {
  modelId: string;
  persona: string;
  guardrailMode: GuardrailMode;
  authProfileId: string;
};

export const EMPTY_LLM_FORM: LlmFormState = {
  modelId: "",
  persona: "",
  guardrailMode: "permission_gate_only",
  authProfileId: "",
};

const inputClass = "redsim-input mt-1";

export function LlmRegisterForm({
  projectId,
  value,
  onChange,
}: {
  projectId: string | null;
  value: LlmFormState;
  onChange: (next: LlmFormState) => void;
}) {
  const { data: pythia, isLoading: pythiaLoading } = usePythiaModels(true);
  const { data: profiles = [] } = useSWR(
    projectId ? ["auth-profiles", projectId] : null,
    ([, id]: [string, string]) => listAuthProfiles(id),
  );
  const bearerProfiles = profiles.filter((p) => p.kind === "bearer");
  const sortedModels = useMemo(
    () =>
      [...(pythia?.models ?? [])].sort((a, b) => a.id.localeCompare(b.id)),
    [pythia],
  );
  const useSelect = Boolean(pythia?.configured) && sortedModels.length > 0;
  const set = (patch: Partial<LlmFormState>) => onChange({ ...value, ...patch });

  // Seed defaults once the gateway answers: default model, persona, sole bearer key.
  const seeded = useRef(false);
  useEffect(() => {
    if (seeded.current || !pythia) return;
    seeded.current = true;
    const patch: Partial<LlmFormState> = {};
    if (!value.modelId) {
      patch.modelId = pythia.default_model ?? sortedModels[0]?.id ?? "";
    }
    if (!value.persona) patch.persona = pythia.persona ?? "default";
    if (Object.keys(patch).length) onChange({ ...value, ...patch });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pythia]);
  useEffect(() => {
    if (!value.authProfileId && bearerProfiles.length === 1) {
      onChange({ ...value, authProfileId: bearerProfiles[0].id });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bearerProfiles.length]);

  return (
    <>
      <label className="mt-4 block text-sm text-ink-1">
        <span className="flex items-baseline justify-between gap-3">
          Model
          {pythia?.gateway_host && (
            <span className="font-mono text-xs text-ink-3">
              {pythia.gateway_host}
            </span>
          )}
        </span>
        {useSelect ? (
          <select
            value={value.modelId}
            onChange={(event) => set({ modelId: event.target.value })}
            className={inputClass}
          >
            <option value="">Select a gateway model</option>
            {sortedModels.map((model) => (
              <option key={model.id} value={model.id}>
                {model.id}
                {model.owned_by ? ` · ${model.owned_by}` : ""}
              </option>
            ))}
          </select>
        ) : (
          <input
            value={value.modelId}
            onChange={(event) => set({ modelId: event.target.value })}
            className={inputClass}
            placeholder="vendor/model"
          />
        )}
        {!useSelect && !pythiaLoading && (
          <span className="mt-1 block text-xs text-ink-3">
            {pythia?.error ??
              "Gateway model list unavailable; enter the canonical <vendor>/<model> id."}
          </span>
        )}
      </label>
      <label className="mt-3 block text-sm text-ink-1">
        Persona
        <input
          value={value.persona}
          onChange={(event) => set({ persona: event.target.value })}
          className={inputClass}
          placeholder="default"
        />
      </label>
      <label className="mt-3 block text-sm text-ink-1">
        Guardrail mode
        <select
          value={value.guardrailMode}
          onChange={(event) =>
            set({ guardrailMode: event.target.value as GuardrailMode })
          }
          className={inputClass}
        >
          {GUARDRAIL_MODES.map((mode) => (
            <option key={mode} value={mode}>
              {guardrailLabel(mode)}
            </option>
          ))}
        </select>
        <span className="mt-1 block text-xs text-ink-3">
          declares what the hit rates measure
        </span>
      </label>
      <div className="mt-3 block text-sm text-ink-1">
        Probe key
        {bearerProfiles.length > 0 ? (
          <select
            aria-label="Probe key"
            value={value.authProfileId}
            onChange={(event) => set({ authProfileId: event.target.value })}
            className={inputClass}
          >
            <option value="">Select a bearer auth profile</option>
            {bearerProfiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.name}
              </option>
            ))}
          </select>
        ) : (
          <p className="mt-1 rounded-[4px] bg-ground p-3 text-xs text-ink-3">
            No bearer profile yet.{" "}
            <Link href="/auth-profiles" className="redsim-link">
              Create one
            </Link>{" "}
            — the Pythia key is stored there, never typed here.
          </p>
        )}
      </div>
    </>
  );
}
