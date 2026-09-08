// @vitest-environment node
import { describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const handlerSentinel = vi.hoisted(() => vi.fn());
const NextAuthMock = vi.hoisted(() => vi.fn(() => handlerSentinel));
vi.mock("next-auth", () => ({ default: NextAuthMock }));
vi.mock("@/server/auth-options", () => ({ authOptions: { _tag: "authOptions" } }));

import { GET, POST } from "./route";

describe("[...nextauth] route handler", () => {
  it("constructs the NextAuth handler with the imported authOptions", () => {
    expect(NextAuthMock).toHaveBeenCalledWith({ _tag: "authOptions" });
  });

  it("exports the same NextAuth handler as both GET and POST", () => {
    expect(GET).toBe(handlerSentinel);
    expect(POST).toBe(handlerSentinel);
    expect(GET).toBe(POST);
  });
});
