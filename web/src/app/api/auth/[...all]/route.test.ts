// @vitest-environment node
import { describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const authSentinel = vi.hoisted(() => ({ _tag: "auth" }));
const getSentinel = vi.hoisted(() => vi.fn());
const postSentinel = vi.hoisted(() => vi.fn());
const toNextJsHandlerMock = vi.hoisted(() =>
  vi.fn(() => ({ GET: getSentinel, POST: postSentinel })),
);
vi.mock("better-auth/next-js", () => ({ toNextJsHandler: toNextJsHandlerMock }));
vi.mock("@/server/better-auth", () => ({ auth: authSentinel }));

import { GET, POST } from "./route";

describe("[...all] route handler", () => {
  it("builds the handler from the shared Better Auth instance", () => {
    expect(toNextJsHandlerMock).toHaveBeenCalledWith(authSentinel);
  });

  it("exports the adapter's GET and POST", () => {
    expect(GET).toBe(getSentinel);
    expect(POST).toBe(postSentinel);
  });
});
