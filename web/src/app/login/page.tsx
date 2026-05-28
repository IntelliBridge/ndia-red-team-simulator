"use client";

import { signIn } from "next-auth/react";

export default function LoginPage() {
  return (
    <div>
      <h1>Sign in</h1>
      <p>Aegis uses your organization's OIDC provider.</p>
      <button className="primary" onClick={() => signIn("keycloak")}>
        Continue with SSO
      </button>
    </div>
  );
}
