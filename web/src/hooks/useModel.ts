"use client";
import useSWR from "swr";
import { api, type ModelTarget } from "@/lib/api";
export function useModel(id: string | null) {
  return useSWR<ModelTarget>(
    id ? `/v1/models/${encodeURIComponent(id)}` : null,
    (p: string) => api<ModelTarget>(p),
  );
}
