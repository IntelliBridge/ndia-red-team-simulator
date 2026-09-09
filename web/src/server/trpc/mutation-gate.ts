import "server-only";

/**
 * The rejection rules every mutation passes before any upstream call (KTD2).
 *
 * Shared by the `mutationProcedure` middleware and, from U8, the multipart
 * upload handler, so the handler sits inside the same rules rather than
 * carrying a second copy that can drift.
 */
export type RequestOriginInput = {
  secFetchSite: string | null;
  origin: string | null;
  /** `env.BETTER_AUTH_URL`, the same value Better Auth uses for trustedOrigins. */
  trustedOrigin: string;
};

export type MutationGateInput = RequestOriginInput & {
  contentType: string | null;
  /** What this caller accepts: procedures take JSON, the upload takes multipart. */
  acceptedContentType: string;
};

export type RequestOriginVerdict =
  | { ok: true }
  | { ok: false; reason: "cross_site_request" | "untrusted_origin" };

export type MutationGateVerdict =
  | { ok: true }
  | { ok: false; reason: "cross_site_request" | "untrusted_origin" | "unsupported_content_type" };

/**
 * Refuse a request that did not come from this app, by origin alone.
 *
 * `same-site` is refused as well as `cross-site`, because SameSite=Lax admits
 * a same-site sender and the cookie jar alone is not proof of intent. Older
 * browsers omit the fetch metadata but every browser sends `Origin` on a POST,
 * so the Origin comparison is the fallback rather than a second gate. An
 * unset `trustedOrigin` makes `new URL` throw, which fails the comparison
 * closed.
 *
 * Split out from `checkMutationRequest` for callers that cannot require a
 * content type. The sign-out POST is one: both of its callers send a bare
 * `fetch(url, { method: "POST" })` with no body and therefore no
 * `Content-Type`, so the full gate would refuse the app's own sign-out.
 */
export function checkRequestOrigin(input: RequestOriginInput): RequestOriginVerdict {
  const { secFetchSite, origin, trustedOrigin } = input;

  if (secFetchSite !== null) {
    if (secFetchSite !== "same-origin") return { ok: false, reason: "cross_site_request" };
  } else if (origin !== null) {
    let trusted: string;
    try {
      trusted = new URL(trustedOrigin).origin;
    } catch {
      return { ok: false, reason: "untrusted_origin" };
    }
    if (origin !== trusted) return { ok: false, reason: "untrusted_origin" };
  }

  return { ok: true };
}

/**
 * Refuse a mutation that did not come from this app.
 *
 * The origin legs, then the content type. The accepted type comes from the
 * caller: procedures require JSON, so a cross-site HTML form post cannot reach
 * one at all, and from U8 the upload handler passes multipart.
 */
export function checkMutationRequest(input: MutationGateInput): MutationGateVerdict {
  const verdict = checkRequestOrigin(input);
  if (!verdict.ok) return verdict;

  const media = (input.contentType ?? "").split(";")[0]?.trim().toLowerCase();
  if (media !== input.acceptedContentType) return { ok: false, reason: "unsupported_content_type" };

  return { ok: true };
}
