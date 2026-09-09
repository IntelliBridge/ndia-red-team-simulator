"use client";
import useSWR from "swr";
import {
  getLlmScorecard,
  isScorecardPending,
  listProbeCatalog,
  listPythiaModels,
  type LlmScorecardResponse,
} from "@/lib/llm";

export const usePythiaModels = (enabled = true) =>
  useSWR(enabled ? "/v1/llm/models" : null, () => listPythiaModels());

export const useProbeCatalog = (enabled = true) =>
  useSWR(enabled ? "/v1/llm/probes" : null, () => listProbeCatalog());

// The scorecard route answers 409 score_unavailable until the run completes.
// The fetcher maps that to `null` so SWR keeps polling instead of entering
// error-retry backoff; `ready` is true once a scorecard body has arrived.
const scorecardFetcher = async (
  runId: string,
): Promise<LlmScorecardResponse | null> => {
  try {
    return await getLlmScorecard(runId);
  } catch (err) {
    if (isScorecardPending(err)) return null;
    throw err;
  }
};

export function useLlmScorecard(
  runId: string | null,
  opts: { refreshInterval?: number } = {},
) {
  const interval = opts.refreshInterval ?? 4000;
  const swr = useSWR(
    runId ? (["llm-scorecard", runId] as const) : null,
    ([, id]) => scorecardFetcher(id),
    {
      // Poll while pending; stop once the scorecard is in hand.
      refreshInterval: (data) => (data ? 0 : interval),
      revalidateOnFocus: false,
    },
  );
  const ready = swr.data != null;
  return {
    data: ready ? swr.data : undefined,
    error: swr.error,
    ready,
    isLoading: swr.isLoading,
    mutate: swr.mutate,
  };
}
