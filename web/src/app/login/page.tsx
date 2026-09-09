"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { env } from "@/env";
import { signIn } from "@/lib/auth-client";

// In prod the dev-token path is disabled server-side (the API rejects
// `dev:*` bearers when REDSIM_ENV=prod), so we also hide it in the UI and
// route everyone through Keycloak/OIDC. REDSIM_ENV is server-only; the
// client reads the NEXT_PUBLIC_ mirror (see lib/api.ts for the same
// convention). Anything other than "prod" keeps the dev path visible.
const isProd = env.NEXT_PUBLIC_REDSIM_ENV === "prod";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@redsim.local");
  const [busy, setBusy] = useState(false);

  const devLogin = () => {
    setBusy(true);
    const token = `dev:${email}`;
    // The API runs in REDSIM_AUTH_MODE=dev (rejected when REDSIM_ENV=prod).
    // Storing the bearer token in localStorage so every SWR call elsewhere
    // can pick it up via api(...).
    localStorage.setItem("redsim_token", token);
    localStorage.setItem("redsim_email", email);
    // The same credential as a cookie, because the tRPC layer runs on the
    // server and never sees localStorage. server/trpc/context.ts turns this
    // one cookie into the upstream bearer, and the middleware gate reads its
    // presence, so without it the dev button lands on a 401 and bounces
    // straight back here. The name is env.js's REDSIM_DEV_TOKEN_COOKIE
    // default, spelled literally because that name is server-only and has no
    // NEXT_PUBLIC mirror. Encoded because the reader decodes: the colon and
    // the at sign would otherwise not survive the round trip.
    document.cookie = `redsim_dev_token=${encodeURIComponent(token)}; path=/; samesite=lax`;
    router.push("/dashboard");
  };

  const oidcLogin = () => {
    setBusy(true);
    // Better Auth runs the Keycloak code flow, and the after-hook on the
    // callback mints the redsim_api_session + redsim_csrf cookies that the
    // api() helper relies on. After the round-trip Better Auth returns here,
    // so send the now-authenticated user on to the dashboard.
    void signIn
      .social({ provider: "keycloak", callbackURL: "/dashboard" })
      .then((result) => {
        // Clear the busy state on a rejected sign-in, or the button stays
        // disabled with no explanation and no navigation.
        if (result?.error) setBusy(false);
      })
      .catch(() => setBusy(false));
  };

  return (
    <div className="mx-auto max-w-xl space-y-8 pt-8">
      <div className="space-y-3">
        <div className="redsim-kicker">Adversarial ML Red-Team Simulator</div>
        <h1 className="text-4xl">Sign in</h1>
        <p className="text-muted-foreground">
          Evaluate and harden ML classifiers under adversarial evasion. Open,
          unclassified public data only.
        </p>
      </div>

      <div className="redsim-panel space-y-4 p-6">
        <div className="redsim-kicker">Organization account</div>
        <p className="text-sm text-muted-foreground">
          Sign in with your organization account via Keycloak / OIDC.
        </p>
        <button
          className="redsim-cta"
          disabled={busy}
          onClick={oidcLogin}
        >
          Continue with Keycloak
        </button>
      </div>

      {!isProd && (
        <div className="redsim-panel space-y-4 p-6">
          <div className="redsim-kicker">Dev auth mode</div>
          <p className="text-sm text-muted-foreground">
            The stack is also running in dev auth mode. Pick the admin email to
            continue as; the API rejects this token whenever{" "}
            <code className="text-foreground/80">REDSIM_ENV=prod</code>.
          </p>
          <label className="block text-sm">
            <span className="redsim-meta mb-1 block">Email</span>
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full max-w-sm rounded border border-input bg-navy-deepest/60 px-3 py-2 font-mono text-sm text-foreground focus-visible:border-ring focus-visible:outline-none"
            />
          </label>
          <button
            className="redsim-ghost"
            disabled={busy}
            onClick={devLogin}
          >
            Continue as dev admin
          </button>
        </div>
      )}
    </div>
  );
}
