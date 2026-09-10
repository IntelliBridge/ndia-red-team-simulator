"use client";

import { Suspense, useId, useState, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { signInWithPassword } from "@/lib/auth";
import { loginMessage, reasonMessage, safeNextPath } from "@/lib/login-messages";

/**
 * The sign-in page.
 *
 * One form, email and password, posted to this app's own login route. The
 * route talks to the identity provider and sets the session cookies; the page
 * only shows the outcome. There is no other way in: no dev token, no bypass,
 * and nothing here names the provider behind the form.
 *
 * `useSearchParams` needs a Suspense boundary under static rendering, so the
 * form sits inside one and the fallback is the same form with no parameters.
 */
export default function LoginPage() {
  return (
    <Suspense fallback={<LoginForm next="/dashboard" reason={undefined} />}>
      <LoginFormWithParams />
    </Suspense>
  );
}

function LoginFormWithParams() {
  const params = useSearchParams();
  return (
    <LoginForm
      next={safeNextPath(params?.get("next"))}
      reason={reasonMessage(params?.get("reason"))}
    />
  );
}

function LoginForm({ next, reason }: { next: string; reason: string | undefined }) {
  const router = useRouter();
  const ids = { email: useId(), password: useId(), error: useId() };
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const trimmed = email.trim();
    if (!trimmed || !password) {
      setError(loginMessage("invalid_request"));
      return;
    }
    setBusy(true);
    setError(null);
    const outcome = await signInWithPassword(trimmed, password);
    if (outcome.ok) {
      // Replace, so Back from the dashboard does not return to a filled form.
      router.replace(next);
      return;
    }
    setPassword("");
    setError(loginMessage(outcome.code));
    setBusy(false);
  };

  return (
    <div className="mx-auto flex w-full max-w-md flex-col justify-center py-10 sm:py-16">
      <div className="mb-8 space-y-3">
        <div className="redsim-kicker">Adversarial ML Red-Team Simulator</div>
        <h1 className="text-4xl font-semibold tracking-tight">Sign in</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Evaluate and harden ML classifiers under adversarial evasion. Open,
          unclassified public data only.
        </p>
      </div>

      {reason ? (
        <p
          role="status"
          className="mb-4 rounded border border-info/40 bg-info/10 px-3 py-2 text-sm text-foreground/90"
        >
          {reason}
        </p>
      ) : null}

      <form
        className="redsim-panel space-y-5 p-6 sm:p-7"
        onSubmit={submit}
        noValidate
        aria-busy={busy}
        aria-describedby={error ? ids.error : undefined}
      >
        <div className="space-y-1.5">
          <label htmlFor={ids.email} className="redsim-meta block">
            Email
          </label>
          <input
            id={ids.email}
            name="email"
            type="email"
            inputMode="email"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            required
            disabled={busy}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            aria-invalid={error ? true : undefined}
            className="redsim-input"
          />
        </div>

        <div className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <label htmlFor={ids.password} className="redsim-meta block">
              Password
            </label>
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              aria-pressed={showPassword}
              aria-controls={ids.password}
              className="redsim-meta text-foreground/60 hover:text-foreground focus-visible:outline-none focus-visible:underline"
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
          <input
            id={ids.password}
            name="password"
            type={showPassword ? "text" : "password"}
            autoComplete="current-password"
            required
            disabled={busy}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-invalid={error ? true : undefined}
            className="redsim-input"
          />
        </div>

        {error ? (
          <p
            id={ids.error}
            role="alert"
            className="rounded border border-destructive/60 bg-destructive/10 px-3 py-2 text-sm text-foreground"
          >
            {error}
          </p>
        ) : null}

        <button type="submit" className="redsim-cta w-full py-2.5" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>

      <p className="mt-6 text-center text-xs leading-relaxed text-muted-foreground">
        Access is provisioned by your administrator. Contact them for an
        account or a password reset.
      </p>
    </div>
  );
}
