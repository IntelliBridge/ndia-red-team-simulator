"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

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

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Sign in</h1>
      <p className="mb-4">
        The stack is running in dev auth mode. Pick the admin email to
        continue as; the API rejects this token whenever{" "}
        <code>AEGIS_ENV=prod</code>.
      </p>
      <label className="mb-3 block">
        Email{" "}
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-80 rounded-md border border-slate-200 px-3 py-1.5 text-sm"
        />
      </label>
      <button
        className="rounded-md bg-sky-700 px-3 py-1.5 text-sm text-white hover:bg-sky-800 disabled:opacity-50"
        disabled={busy}
        onClick={devLogin}
      >
        Continue as dev admin
      </button>
      <p className="mt-6 text-slate-500">
        Keycloak / OIDC is also live at{" "}
        <code>http://localhost:8080/realms/aegis</code> — wire the NextAuth
        provider config under{" "}
        <code>web/src/app/api/auth/[...nextauth]</code> for the full OIDC flow.
      </p>
    </div>
  );
}
