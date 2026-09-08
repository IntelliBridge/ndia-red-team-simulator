"use client";
import useSWR from "swr";
import { api, type Campaign } from "@/lib/api";
const terminal = new Set([
  "completed",
  "succeeded",
  "failed",
  "cancelled",
  "refused",
]);
export function useCampaign(id: string) {
  return useSWR<Campaign>(
    id ? `/v1/runs/${encodeURIComponent(id)}/campaign` : null,
    (p: string) => api<Campaign>(p),
    {
      refreshInterval: (data?: Campaign) =>
        data?.status && !terminal.has(data.status) ? 12000 : 0,
    },
  );
}
