import "server-only";

/**
 * The rejection rules every mutation passes before any upstream call (KTD2).
 *
 * Shared by the `mutationProcedure` middleware and, from U8, the multipart
 * upload handler, so the handler sits inside the same rules rather than
 * carrying a second copy that can drift.
 */
export type MutationGateInput = {
  secFetchSite: string | null;
  origin: string | null;
  contentType: string | null;
  /** What this caller accepts: procedures take JSON, the upload takes multipart. */
  acceptedContentType: string;
  /** `env.BETTER_AUTH_URL`, the same value Better Auth uses for trustedOrigins. */
  trustedOrigin: string;
};

export type MutationGateVerdict =
  | { ok: true }
  | { ok: false; reason: "cross_site_request" | "untrusted_origin" | "unsupported_content_type" };

/**
 * Refuse a mutation that did not come from this app.
 *
 * `same-site` is refused as well as `cross-site`, because SameSite=Lax admits
 * a same-site sender and the cookie jar alone is not proof of intent. Older
 * browsers omit the fetch metadata but every browser sends `Origin` on a POST,
 * so the Origin comparison is the fallback rather than a second gate.
 *
 * The accepted content type comes from the caller. Procedures require JSON, so
 * a cross-site HTML form post cannot reach one at all.
 */
export function checkMutationRequest(input: MutationGateInput): MutationGateVerdict {
  const { secFetchSite, origin, contentType, acceptedContentType, trustedOrigin } = input;

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

  const media = (contentType ?? "").split(";")[0]?.trim().toLowerCase();
  if (media !== acceptedContentType) return { ok: false, reason: "unsupported_content_type" };

  return { ok: true };
}
