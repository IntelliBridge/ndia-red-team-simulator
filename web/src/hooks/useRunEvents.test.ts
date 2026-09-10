import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// apiWsBase is a value import; the socket carries the cookie session only.
vi.mock("@/lib/api", () => ({
  apiWsBase: "ws://api.test",
}));

// jsdom has no WebSocket: capture each construction so we can drive onmessage,
// assert the url/protocols, and verify close-on-unmount.
const wsInstances: FakeWS[] = [];
class FakeWS {
  onmessage: ((ev: { data: string }) => void) | null = null;
  close = vi.fn();
  url: string;
  protocols?: string | string[];
  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocols = protocols;
    wsInstances.push(this);
  }
}

import { useRunEvents } from "./useRunEvents";

beforeEach(() => {
  wsInstances.length = 0;
  vi.stubGlobal("WebSocket", FakeWS);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("useRunEvents", () => {
  it("opens a socket at the run's events url with no subprotocol: the cookie rides the upgrade", () => {
    renderHook(() => useRunEvents("run-1", vi.fn()));
    expect(wsInstances).toHaveLength(1);
    expect(wsInstances[0].url).toBe("ws://api.test/v1/runs/run-1/events");
    expect(wsInstances[0].protocols).toBeUndefined();
  });

  it("invokes onJob for a job-lifecycle frame with the parsed payload", () => {
    const onJob = vi.fn();
    renderHook(() => useRunEvents("run-1", onJob));

    wsInstances[0].onmessage?.({
      data: JSON.stringify({
        type: "job",
        run_id: "run-1",
        job_id: "j-7",
        status: "succeeded",
      }),
    });

    expect(onJob).toHaveBeenCalledTimes(1);
    expect(onJob).toHaveBeenCalledWith({
      type: "job",
      run_id: "run-1",
      job_id: "j-7",
      status: "succeeded",
    });
  });

  it("ignores heartbeat, other types, and malformed frames", () => {
    const onJob = vi.fn();
    renderHook(() => useRunEvents("run-1", onJob));
    const ws = wsInstances[0];

    ws.onmessage?.({ data: JSON.stringify({ type: "heartbeat" }) });
    ws.onmessage?.({ data: JSON.stringify({ type: "raw", data: "x" }) });
    ws.onmessage?.({ data: JSON.stringify({ name: "recon" }) }); // legacy stage shape
    ws.onmessage?.({ data: "not json" });

    expect(onJob).not.toHaveBeenCalled();
  });

  it("always reads the latest onJob without reopening the socket", () => {
    const first = vi.fn();
    const second = vi.fn();
    const { rerender } = renderHook(({ cb }) => useRunEvents("run-1", cb), {
      initialProps: { cb: first },
    });

    // A new callback identity must not tear down / reopen the live socket.
    rerender({ cb: second });
    expect(wsInstances).toHaveLength(1);

    wsInstances[0].onmessage?.({
      data: JSON.stringify({ type: "job", run_id: "run-1", job_id: "j", status: "running" }),
    });

    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });

  it("closes the socket on unmount", () => {
    const { unmount } = renderHook(() => useRunEvents("run-1", vi.fn()));
    const ws = wsInstances[0];
    unmount();
    expect(ws.close).toHaveBeenCalledTimes(1);
  });

  it("opens no socket when runId is falsy", () => {
    renderHook(() => useRunEvents(null, vi.fn()));
    renderHook(() => useRunEvents(undefined, vi.fn()));
    renderHook(() => useRunEvents("", vi.fn()));
    expect(wsInstances).toHaveLength(0);
  });

  it("no-ops when WebSocket is unavailable (SSR / hardened env)", () => {
    vi.stubGlobal("WebSocket", undefined);
    expect(() => renderHook(() => useRunEvents("run-1", vi.fn()))).not.toThrow();
    expect(wsInstances).toHaveLength(0);
  });

  it("swallows construction errors and falls back silently", () => {
    class ThrowingWS {
      constructor() {
        throw new Error("blocked");
      }
    }
    vi.stubGlobal("WebSocket", ThrowingWS);
    expect(() => renderHook(() => useRunEvents("run-1", vi.fn()))).not.toThrow();
  });
});
