// The browser provider's 401 recovery.
//
// TRPCReactProvider is rendered for real here rather than through
// renderWithProviders, which supplies its own QueryClient and never installs
// the onUnauthorized handler this file is about. jsdom, and every case
// re-imports the module graph: both the browser QueryClient and the
// sign-out-in-flight flag are module level, so a case that reused them would be
// asserting on the previous case's state.
//
// The stub answers the first batch and leaves every later batch pending. That
// is the real sequence: the handler clears the cache, the mounted observers
// refetch, and in the browser router.replace navigates away and unmounts them
// before those refetches can answer. Answering them here instead would loop
// against a mocked router that never navigates.

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, useQuery } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { trpcResult, trpcUpstreamError } from "@/test/mock-upstream";

const SIGNOUT_PATH = "/api/auth/signout-redsim";

const replace = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }));

/** One recorded outbound call. */
type Recorded = { url: string; method: string };

/**
 * Install a fetch answering the first tRPC batch and the sign-out post.
 *
 * @param batchAnswers - One envelope per call in the first batch, in call order.
 * @param signout - Whether the sign-out post lands or rejects, as it does offline.
 * @returns The list every call is recorded into, in call order.
 */
function stubFetch(
  batchAnswers: unknown[],
  signout: "lands" | "rejects" = "lands",
): Recorded[] {
  const recorded: Recorded[] = [];
  let batches = 0;
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    recorded.push({ url, method: (init?.method ?? "GET").toUpperCase() });

    if (url.includes(SIGNOUT_PATH)) {
      return signout === "rejects"
        ? Promise.reject(new Error("offline"))
        : Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    }

    batches += 1;
    if (batches > 1) return new Promise<Response>(() => undefined);
    return Promise.resolve(
      new Response(JSON.stringify(batchAnswers), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  return recorded;
}

/** Mount the real provider around a leaf issuing two queries in one batch. */
async function mountWithTwoQueries() {
  vi.resetModules();
  const { TRPCReactProvider, useTRPC } = await import("./client");

  function Leaf() {
    const trpc = useTRPC();
    const first = useQuery(trpc.runs.list.queryOptions({ limit: 1 }));
    const second = useQuery(trpc.runs.list.queryOptions({ limit: 2 }));
    return <p>{`${first.status}:${second.status}`}</p>;
  }

  return render(
    <TRPCReactProvider>
      <Leaf />
    </TRPCReactProvider>,
  );
}

/** Let the batch settle, the handler run, and its promise chain finish. */
async function settle() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

const unauthorized = () => trpcUpstreamError(401);

let clearSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  replace.mockClear();
  clearSpy = vi.spyOn(QueryClient.prototype, "clear");
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the 401 handler", () => {
  it("posts sign-out once for a whole batch that answers 401", async () => {
    // onError fires per errored query, so a batch of up to MAX_BATCH_ITEMS
    // 401s fired that many posts, cache clears and navigations.
    const recorded = stubFetch([unauthorized(), unauthorized()]);

    await mountWithTwoQueries();
    await waitFor(() => expect(replace).toHaveBeenCalled());

    const posts = recorded.filter((call) => call.url.includes(SIGNOUT_PATH));
    expect(posts).toHaveLength(1);
    expect(posts[0]?.method).toBe("POST");
    expect(replace).toHaveBeenCalledTimes(1);
    expect(replace).toHaveBeenCalledWith("/login");
  });

  it("clears the cache, so the next user in the tab sees none of these rows", async () => {
    stubFetch([unauthorized(), unauthorized()]);

    await mountWithTwoQueries();
    await waitFor(() => expect(replace).toHaveBeenCalled());

    expect(clearSpy).toHaveBeenCalledTimes(1);
    // Cleared rather than left errored: the observers are back to pending on
    // the refetch the clear triggered, which the browser unmounts by navigating.
    expect(screen.getByText("pending:pending")).toBeTruthy();
  });

  it("still clears and redirects when the sign-out post never lands", async () => {
    // `finally` re-propagates the original rejection, so without the catch an
    // offline sign-out surfaced as an unhandled rejection. Captured on the
    // process rather than the window: jsdom dispatches no unhandledrejection
    // event, so a window listener would pass either way.
    const rejections: unknown[] = [];
    const onRejection = (reason: unknown) => rejections.push(reason);
    process.on("unhandledRejection", onRejection);
    stubFetch([unauthorized(), unauthorized()], "rejects");

    try {
      await mountWithTwoQueries();
      await waitFor(() => expect(replace).toHaveBeenCalled());
      // A macrotask, which is when node decides a rejection went unhandled.
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(replace).toHaveBeenCalledWith("/login");
      expect(clearSpy).toHaveBeenCalledTimes(1);
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onRejection);
    }
  });

  it("leaves a successful batch alone", async () => {
    const recorded = stubFetch([
      trpcResult({ runs: [], count: 0 }),
      trpcResult({ runs: [], count: 0 }),
    ]);

    await mountWithTwoQueries();
    await waitFor(() => expect(screen.getByText("success:success")).toBeTruthy());

    expect(recorded.filter((call) => call.url.includes(SIGNOUT_PATH))).toEqual([]);
    expect(replace).not.toHaveBeenCalled();
    expect(clearSpy).not.toHaveBeenCalled();
  });
});
