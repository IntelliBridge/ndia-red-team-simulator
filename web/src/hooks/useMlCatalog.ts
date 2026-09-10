"use client";
import useSWR from "swr";
import {
  api,
  type AttackInfo,
  type DatasetInfo,
  type Capabilities,
} from "@/lib/api";
const get = <T>(p: string) =>
  api<T[] | Record<string, unknown>>(p).then((x) => {
    if (Array.isArray(x)) return x as T[];
    // The API wraps lists under a named key ({ attacks }, { datasets });
    // older shapes used { items }. Take the first array value.
    const named = ["items", "attacks", "datasets"]
      .map((k) => (x as Record<string, unknown>)[k])
      .find(Array.isArray);
    return (named ?? Object.values(x).find(Array.isArray) ?? []) as T[];
  });
export const useAttacks = (modality?: string, enabled = true) =>
  useSWR(
    enabled
      ? `/v1/attacks${modality ? `?modality=${encodeURIComponent(modality)}` : ""}`
      : null,
    (p) => get<AttackInfo>(p),
  );
export const useDatasets = (enabled = true) =>
  useSWR(enabled ? "/v1/datasets" : null, (p) => get<DatasetInfo>(p));
export const useCapabilities = (enabled = true) =>
  useSWR(enabled ? "/v1/ml/capabilities" : null, (p) => api<Capabilities>(p));
