import type { ReadonlyURLSearchParams } from "next/navigation";

export const LOG_FILTER_KEYS = ["run", "severity", "service"] as const;

// Serialize the active URL filters into a /v1/logs query string,
// dropping any that are absent or empty.
export function buildLogsQuery(params: ReadonlyURLSearchParams): string {
  const qs = new URLSearchParams();
  for (const key of LOG_FILTER_KEYS) {
    const value = params.get(key);
    if (value) qs.set(key, value);
  }
  return qs.toString();
}
