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
    <div>
      <h1>Sign in</h1>
      <p style={{ marginBottom: "1rem" }}>
        The stack is running in dev auth mode. Pick the admin email to
        continue as; the API rejects this token whenever{" "}
        <code>AEGIS_ENV=prod</code>.
      </p>
      <label style={{ display: "block", marginBottom: "0.75rem" }}>
        Email{" "}
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={{ width: "320px" }}
        />
      </label>
      <button className="primary" disabled={busy} onClick={devLogin}>
        Continue as dev admin
      </button>
      <p style={{ marginTop: "1.5rem", color: "#5a5a5a" }}>
        Keycloak / OIDC is also live at{" "}
        <code>http://localhost:8080/realms/aegis</code> — wire the NextAuth
        provider config under{" "}
        <code>web/src/app/api/auth/[...nextauth]</code> for the full OIDC flow.
      </p>
    </div>
  );
}
