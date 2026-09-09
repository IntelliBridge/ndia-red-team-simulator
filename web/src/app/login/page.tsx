"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { DEV_ENVS, env } from "@/env";
import { pageSearchParam, type RawSearchParams } from "@/lib/page-search-params";

// The dev-admin path exists only on a local or test stack. The API refuses a
// `dev:*` bearer whenever REDSIM_ENV=prod, the server gate and the tRPC
// context honour the dev cookie only inside DEV_ENVS, and this is the same
// allowlist read from the client mirror: anything that is not `dev` or
// `test` (prod, staging, a typo) renders no escape hatch at all. Hiding only
// on "prod" would leave it on a staging deployment.
const showsDevAccess = DEV_ENVS.includes(env.NEXT_PUBLIC_REDSIM_ENV);

/** What the sign-in route answers with, keyed by HTTP status and reason. */
function describeRefusal(status: number, reason: string | undefined): string {
  if (status === 401) return "Incorrect username or password.";
  if (status === 403) return "The request was not sent from this app. Reload the page and try again.";
  if (status === 500 && reason === "mint_failed") {
    return "Your credentials were accepted, but this deployment holds no API session key. Ask the operator to set it.";
  }
  if (status === 503 && reason === "identity_misconfigured") {
    return "No identity realm is configured for this deployment.";
  }
  if (status === 503) return "The identity service is unavailable. Try again in a moment.";
  return "Sign-in failed. Try again.";
}

const INPUT_CLASS =
  "w-full rounded border border-input bg-navy-deepest/60 px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none disabled:opacity-60";

const PILLARS: { index: string; label: string; text: string }[] = [
  {
    index: "01",
    label: "Measure",
    text: "Evasion attacks against a benign-noise control across an epsilon sweep, scored per campaign.",
  },
  {
    index: "02",
    label: "Explain",
    text: "SHAP attributions as supporting evidence, kept separate from the measurements.",
  },
  {
    index: "03",
    label: "Harden",
    text: "Candidate defenses, verified by re-running the attack and reporting the measured delta.",
  },
];

export default function LoginPage({ searchParams }: { searchParams?: RawSearchParams }) {
  const router = useRouter();
  const sessionEnded = pageSearchParam(searchParams, "reason") === "rejected";

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  const [devEmail, setDevEmail] = useState("admin@redsim.local");

  const signIn = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => undefined)) as
          | { error?: string }
          | undefined;
        setError(describeRefusal(response.status, body?.error));
        setBusy(false);
        return;
      }
      const body = (await response.json()) as { email?: string };
      // A stale dev bearer in storage would win over the fresh cookie pair in
      // api(), so it goes. The email is what the dashboard header shows.
      localStorage.removeItem("redsim_token");
      if (body.email) localStorage.setItem("redsim_email", body.email);
      router.push("/dashboard");
    } catch {
      setError("The sign-in request could not be sent. Check your connection and try again.");
      setBusy(false);
    }
  };

  const devLogin = () => {
    setBusy(true);
    const token = `dev:${devEmail}`;
    // The API runs in REDSIM_AUTH_MODE=dev (rejected when REDSIM_ENV=prod).
    // Storing the bearer token in localStorage so every SWR call elsewhere
    // can pick it up via api(...).
    localStorage.setItem("redsim_token", token);
    localStorage.setItem("redsim_email", devEmail);
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

  return (
    <div className="grid min-h-[calc(100vh-13rem)] items-center gap-12 py-6 lg:grid-cols-[1.15fr_1fr] lg:gap-20">
      {/* Brand column. */}
      <section aria-labelledby="login-heading" className="space-y-10">
        <div className="space-y-5">
          <img
            src="/brand/agile-labs.svg"
            alt="Agile Defense Labs"
            width={86}
            height={40}
            className="h-10 w-auto"
          />
          <div className="space-y-3">
            <div className="redsim-kicker">Adversarial ML Red-Team Simulator</div>
            <h1 id="login-heading" className="text-5xl sm:text-6xl">
              Sign in
            </h1>
            <p className="max-w-md text-base text-muted-foreground">
              Evaluate and harden ML classifiers under adversarial evasion.
              Open, unclassified public data only.
            </p>
          </div>
        </div>

        <ol className="max-w-md divide-y divide-border border-y border-border">
          {PILLARS.map((pillar) => (
            <li key={pillar.index} className="flex gap-5 py-4">
              <span className="redsim-meta w-14 shrink-0 pt-0.5">
                {pillar.index} //
              </span>
              <div className="space-y-1">
                <div className="font-mono text-xs uppercase tracking-[0.14em] text-foreground">
                  {pillar.label}
                </div>
                <p className="text-sm text-muted-foreground">{pillar.text}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* Form column. */}
      <div className="w-full max-w-md space-y-4 justify-self-center lg:justify-self-end">
        <form
          onSubmit={signIn}
          aria-label="Organization account sign in"
          className="redsim-panel space-y-5 p-7 sm:p-8"
        >
          <div className="space-y-1">
            <div className="redsim-kicker">Organization account</div>
            <p className="text-sm text-muted-foreground">
              Sign in with the credentials your organization issued.
            </p>
          </div>

          {sessionEnded && (
            <p
              role="status"
              className="rounded border border-warning/40 bg-warning/10 px-3 py-2 text-sm text-foreground"
            >
              Your session ended. Sign in again to continue.
            </p>
          )}

          <label className="block">
            <span className="redsim-meta mb-1.5 block">Username or email</span>
            <input
              name="username"
              type="text"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={busy}
              className={INPUT_CLASS}
            />
          </label>

          <label className="block">
            <span className="redsim-meta mb-1.5 block">Password</span>
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
              className={INPUT_CLASS}
            />
          </label>

          {error && (
            <p
              role="alert"
              className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-foreground"
            >
              {error}
            </p>
          )}

          <button type="submit" className="redsim-cta w-full" disabled={busy}>
            {busy ? "Signing in" : "Sign in"}
          </button>

          <p className="redsim-meta text-center">
            UNCLASSIFIED // ACCESS BY INVITATION
          </p>
        </form>

        {showsDevAccess && (
          <details className="redsim-panel group p-5">
            <summary className="cursor-pointer list-none font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-muted-foreground hover:text-foreground">
              Developer access (local stack only)
            </summary>
            <div className="mt-4 space-y-4">
              <p className="text-sm text-muted-foreground">
                The stack is running in dev auth mode. Pick the admin email to
                continue as; the API rejects this token whenever{" "}
                <code className="text-foreground/80">REDSIM_ENV=prod</code>.
              </p>
              <label className="block text-sm">
                <span className="redsim-meta mb-1.5 block">Email</span>
                <input
                  value={devEmail}
                  onChange={(e) => setDevEmail(e.target.value)}
                  className={`${INPUT_CLASS} font-mono`}
                />
              </label>
              <button
                type="button"
                className="redsim-ghost w-full"
                disabled={busy}
                onClick={devLogin}
              >
                Continue as dev admin
              </button>
            </div>
          </details>
        )}
      </div>
    </div>
  );
}
