"use client";
import useSWR from "swr";
import { api, type ModelTarget } from "@/lib/api";
const fetcher = (path: string) =>
  api<ModelTarget[] | { models: ModelTarget[] }>(path).then((x) =>
    Array.isArray(x) ? x : (x.models ?? []),
  );
export function useModels(projectId: string | null = "default") {
  return useSWR(projectId ? `/v1/models?project=${encodeURIComponent(projectId)}` : null, fetcher);
}
