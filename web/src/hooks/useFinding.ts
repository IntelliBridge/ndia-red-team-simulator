"use client";
import useSWR from "swr";
import { api, type Finding } from "@/lib/api";
export const useFinding = (id: string | null) =>
  useSWR<Finding>(
    id ? `/v1/findings/${encodeURIComponent(id)}` : null,
    (p: string) => api<Finding>(p),
  );
