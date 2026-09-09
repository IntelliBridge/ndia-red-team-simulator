// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const authSentinel = vi.hoisted(() => ({ _tag: "auth" }));
const getSentinel = vi.hoisted(() => vi.fn(async () => new Response("get")));
const postSentinel = vi.hoisted(() => vi.fn(async () => new Response("post")));
const toNextJsHandlerMock = vi.hoisted(() =>
  vi.fn(() => ({ GET: getSentinel, POST: postSentinel })),
);
const getAuthMock = vi.hoisted(() => vi.fn());
const IdentityUnavailableError = vi.hoisted(() => class IdentityUnavailableError extends Error {});
vi.mock("better-auth/next-js", () => ({ toNextJsHandler: toNextJsHandlerMock }));
vi.mock("@/server/better-auth", () => ({
  getAuth: getAuthMock,
  IdentityUnavailableError,
}));

import { GET, POST } from "./route";

describe("[...all] route handler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("resolves the instance per request and dispatches GET and POST to the adapter", async () => {
    getAuthMock.mockResolvedValue(authSentinel);
    const get = new Request("http://localhost:3000/api/auth/get-session");
    const post = new Request("http://localhost:3000/api/auth/sign-in/social", { method: "POST" });

    await GET(get);
    await POST(post);

    expect(toNextJsHandlerMock).toHaveBeenCalledWith(authSentinel);
    expect(getSentinel).toHaveBeenCalledWith(get);
    expect(postSentinel).toHaveBeenCalledWith(post);
  });

  it("answers 503 with Retry-After while the identity provider is unreachable", async () => {
    getAuthMock.mockRejectedValue(new IdentityUnavailableError("discovery fetch failed"));

    const res = await POST(
      new Request("http://localhost:3000/api/auth/sign-in/social", { method: "POST" }),
    );

    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBe("10");
    expect(await res.json()).toEqual({ error: "identity provider unavailable, retry shortly" });
    expect(toNextJsHandlerMock).not.toHaveBeenCalled();
  });

  it("lets other construction failures propagate", async () => {
    getAuthMock.mockRejectedValue(new Error("misconfigured"));
    await expect(GET(new Request("http://localhost:3000/api/auth/get-session"))).rejects.toThrow(
      "misconfigured",
    );
  });
});
