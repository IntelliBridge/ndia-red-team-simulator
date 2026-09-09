// @vitest-environment node
//
// The shared rejection table of KTD2. The upload handler of U8 reuses this
// helper, so the verdicts are asserted here once rather than twice.
import { describe, expect, it } from "vitest";

import { checkMutationRequest } from "./mutation-gate";

const TRUSTED = "http://localhost:3000";

function check(over: Partial<Parameters<typeof checkMutationRequest>[0]> = {}) {
  return checkMutationRequest({
    secFetchSite: null,
    origin: null,
    contentType: "application/json",
    acceptedContentType: "application/json",
    trustedOrigin: TRUSTED,
    ...over,
  });
}

describe("checkMutationRequest", () => {
  it("admits a same-origin request", () => {
    expect(check({ secFetchSite: "same-origin" }).ok).toBe(true);
  });

  it("refuses cross-site and, deliberately, same-site too", () => {
    // SameSite=Lax admits a same-site sender, so same-site is refused as well.
    expect(check({ secFetchSite: "cross-site" })).toMatchObject({ ok: false });
    expect(check({ secFetchSite: "same-site" })).toMatchObject({ ok: false });
    expect(check({ secFetchSite: "none" })).toMatchObject({ ok: false });
  });

  it("falls back to Origin when fetch metadata is absent", () => {
    expect(check({ origin: TRUSTED }).ok).toBe(true);
    expect(check({ origin: "https://evil.example" })).toMatchObject({ ok: false });
  });

  it("compares only the origin of the trusted URL, not its path", () => {
    expect(
      checkMutationRequest({
        secFetchSite: null,
        origin: "http://localhost:3000",
        contentType: "application/json",
        acceptedContentType: "application/json",
        trustedOrigin: "http://localhost:3000/some/base/path",
      }).ok,
    ).toBe(true);
  });

  it("admits a request with neither fetch metadata nor an Origin", () => {
    expect(check().ok).toBe(true);
  });

  it("refuses a content type the caller did not accept", () => {
    expect(check({ contentType: "multipart/form-data; boundary=x" })).toMatchObject({ ok: false });
    expect(check({ contentType: null })).toMatchObject({ ok: false });
  });

  it("admits multipart when the upload handler is the caller", () => {
    expect(
      check({
        contentType: "multipart/form-data; boundary=x",
        acceptedContentType: "multipart/form-data",
      }).ok,
    ).toBe(true);
  });

  it("names the reason it refused, so the caller does not parse prose", () => {
    expect(check({ secFetchSite: "cross-site" })).toEqual({
      ok: false,
      reason: "cross_site_request",
    });
    expect(check({ origin: "https://evil.example" })).toEqual({
      ok: false,
      reason: "untrusted_origin",
    });
    expect(check({ contentType: null })).toEqual({
      ok: false,
      reason: "unsupported_content_type",
    });
  });
});
