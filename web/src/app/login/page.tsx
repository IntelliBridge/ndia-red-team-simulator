"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState } from "react";

// In prod the dev-token path is disabled server-side (the API rejects
// `dev:*` bearers when AEGIS_ENV=prod), so we also hide it in the UI and
// route everyone through Keycloak/OIDC. AEGIS_ENV is server-only; the
// client reads the NEXT_PUBLIC_ mirror (see lib/api.ts for the same
// convention). Anything other than "prod" keeps the dev path visible.
const isProd = (process.env.NEXT_PUBLIC_AEGIS_ENV ?? "dev") === "prod";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@aegis.local");
  const [busy, setBusy] = useState(false);

  const devLogin = () => {
    setBusy(true);
    // The API runs in AEGIS_AUTH_MODE=dev (rejected when AEGIS_ENV=prod).
    // Storing the bearer token in localStorage so every SWR call elsewhere
    // can pick it up via api(...).
    localStorage.setItem("aegis_token", `dev:${email}`);
    localStorage.setItem("aegis_email", email);
    router.push("/dashboard");
  };

  const oidcLogin = () => {
    setBusy(true);
    // NextAuth runs the Keycloak code flow, and the session callback in
    // @/server/auth-options mints the aegis_api_session + aegis_csrf cookies
    // that the api() helper relies on. After the round-trip NextAuth returns
    // here, so send the now-authenticated user on to the dashboard.
    void signIn("keycloak", { callbackUrl: "/dashboard" });
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Sign in</h1>

      <div className="space-y-2">
        <p className="text-muted-foreground">
          Sign in with your organization account via Keycloak / OIDC.
        </p>
        <button
          className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
          disabled={busy}
          onClick={oidcLogin}
        >
          Continue with Keycloak
        </button>
      </div>

      {!isProd && (
        <div className="space-y-3 border-t border-border pt-4">
          <p>
            The stack is also running in dev auth mode. Pick the admin email to
            continue as; the API rejects this token whenever{" "}
            <code>AEGIS_ENV=prod</code>.
          </p>
          <label className="block">
            Email{" "}
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-80 rounded-md border border-input bg-background px-3 py-1.5 text-sm"
            />
          </label>
          <button
            className="rounded-md border border-input bg-background px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
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
