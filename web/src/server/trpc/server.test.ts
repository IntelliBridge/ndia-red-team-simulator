// @vitest-environment node
//
// The one thing worth asserting about server.tsx in isolation: that it will
// not load without React.cache. Everything else about the prefetch path is
// exercised through a real page in src/app/runs/page.test.tsx, which supplies
// cache the way Next's app-router server runtime does.
import { describe, expect, it, vi } from "vitest";

// Stable React 18.3.1 really does export no cache(), so this mock is the
// installed baseline rather than a hypothetical.
vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return { ...actual, cache: undefined };
});

vi.mock("next/headers", () => ({
  cookies: () => ({ get: () => undefined }),
  headers: () => new Headers(),
}));
vi.mock("next/navigation", () => ({ redirect: () => undefined }));

describe("server.tsx without React.cache", () => {
  it("refuses to load rather than dehydrate an empty cache", async () => {
    // The identity fallback this replaced was a live wrong answer: prefetch and
    // HydrateClient each got their own QueryClient, so a page shipped HTML with
    // an empty cache behind it. A module-scoped memo would have made them
    // agree and shared one client across requests, which here means one user's
    // rows reaching another, so failing at import is the safe direction.
    await expect(import("./server")).rejects.toThrow(/React\.cache is required/);
  });
});
