"use client";
import useSWR from "swr";
import {
  api,
  type AttackInfo,
  type DatasetInfo,
  type DefenseInfo,
  type Capabilities,
} from "@/lib/api";
const get = <T>(p: string) =>
  api<T | { items: T[] }>(p).then((x) =>
    Array.isArray(x) ? x : ((x as { items: T[] }).items ?? []),
  );
export const useAttacks = (modality?: string, enabled = true) =>
  useSWR(
    enabled
      ? `/v1/attacks${modality ? `?modality=${encodeURIComponent(modality)}` : ""}`
      : null,
    (p) => get<AttackInfo>(p),
  );
export const useDatasets = (enabled = true) =>
  useSWR(enabled ? "/v1/datasets" : null, (p) => get<DatasetInfo>(p));
export const useDefenses = (enabled = true) =>
  useSWR(enabled ? "/v1/defenses" : null, (p) => get<DefenseInfo>(p));
export const useCapabilities = (enabled = true) =>
  useSWR(enabled ? "/v1/ml/capabilities" : null, (p) => api<Capabilities>(p));
