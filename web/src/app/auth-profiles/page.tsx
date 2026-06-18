"use client";

// DAST authentication profiles (feat/authenticated-dast).
//
// Profiles hold the non-secret config; the secret (password / token /
// header value / cookie value) is write-only — the API never returns it,
// and this page never renders it back.

import { useState } from "react";
import useSWR from "swr";

import { RoleGated } from "@aegis/design-system";
import {
  createAuthProfile,
  deleteAuthProfile,
  listAuthProfiles,
  type AuthProfile,
  type AuthProfileKind,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

// Same project scoping as /targets (single hard-coded project for now).
const PROJECT = "default";

const KINDS: { value: AuthProfileKind; label: string }[] = [
  { value: "form", label: "Form login" },
  { value: "bearer", label: "Bearer token" },
  { value: "header", label: "Header" },
  { value: "cookie", label: "Cookie" },
];

const SECRET_LABEL: Record<AuthProfileKind, string> = {
  form: "Password",
  bearer: "Token",
  header: "Header value",
  cookie: "Cookie value",
};

const fetcher = () => listAuthProfiles(PROJECT);

const inputCls = "rounded-md border border-border bg-background px-2 py-1.5";
const labelCls = "flex flex-col text-sm";

export default function AuthProfilesPage() {
  const authed = useRequireAuth();

  const { data, error, isLoading, mutate } = useSWR(
    authed ? `/v1/auth-profiles?project=${PROJECT}` : null,
    fetcher,
  );
  const { roles } = useRoles();

  const [name, setName] = useState("");
  const [kind, setKind] = useState<AuthProfileKind>("form");
  const [loginUrl, setLoginUrl] = useState("");
  const [usernameField, setUsernameField] = useState("");
  const [passwordField, setPasswordField] = useState("");
  const [username, setUsername] = useState("");
  const [headerName, setHeaderName] = useState("");
  const [cookieName, setCookieName] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;
  if (error) return <p className="text-muted-foreground">Failed to load.</p>;

  const callerRole = roles[PROJECT];
  const profiles = data ?? [];

  const configFor = (k: AuthProfileKind): Record<string, string> => {
    switch (k) {
      case "form":
        return {
          login_url: loginUrl.trim(),
          username_field: usernameField.trim(),
          password_field: passwordField.trim(),
          username: username.trim(),
        };
      case "header":
        return { header_name: headerName.trim() };
      case "cookie":
        return { cookie_name: cookieName.trim() };
      case "bearer":
        return {};
    }
  };

  const create = async () => {
    if (!name.trim() || !secret) return;
    setBusy(true);
    try {
      setErr(null);
      await createAuthProfile({
        project_id: PROJECT,
        name: name.trim(),
        kind,
        config: configFor(kind),
        secret,
      });
      setName("");
      setLoginUrl("");
      setUsernameField("");
      setPasswordField("");
      setUsername("");
      setHeaderName("");
      setCookieName("");
      setSecret("");
      mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (p: AuthProfile) => {
    if (!window.confirm(`Delete auth profile "${p.name}"?`)) return;
    setBusy(true);
    try {
      setErr(null);
      await deleteAuthProfile(p.id);
      mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Auth Profiles</h1>
        <p className="text-sm text-muted-foreground">
          Credentials DAST scanners use to test behind a login. Secrets are
          write-only and never shown again.
        </p>
      </header>

      {err && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}

      <div className="overflow-hidden rounded-md border border-border bg-card">
        <table className="w-full text-sm">
          <caption className="sr-only">DAST authentication profiles</caption>
          <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2">Name</th>
              <th scope="col" className="px-3 py-2">Kind</th>
              <th scope="col" className="px-3 py-2">Config</th>
              <th scope="col" className="px-3 py-2">Created</th>
              <th scope="col" className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {profiles.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-4 text-muted-foreground">
                  No authentication profiles yet.
                </td>
              </tr>
            )}
            {profiles.map((p) => (
              <tr key={p.id} className="border-t border-border">
                <td className="px-3 py-2">{p.name}</td>
                <td className="px-3 py-2">{p.kind}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {Object.entries(p.config ?? {})
                    .map(([k, v]) => `${k}=${v}`)
                    .join(" ") || "—"}
                </td>
                <td className="px-3 py-2 text-muted-foreground">{p.created_at}</td>
                <td className="px-3 py-2">
                  <RoleGated minRole="admin" callerRole={callerRole}>
                    <button
                      className="rounded-md border border-destructive/40 px-3 py-1.5 text-sm text-destructive hover:bg-destructive/10 disabled:opacity-50"
                      disabled={busy}
                      onClick={() => remove(p)}
                    >
                      Delete
                    </button>
                  </RoleGated>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <RoleGated minRole="admin" callerRole={callerRole}>
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Create profile</h2>
          <div className="flex flex-wrap items-end gap-3">
            <label className={labelCls}>
              <span className="mb-1">Name</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="staging-login"
                className={`w-56 ${inputCls}`}
              />
            </label>
            <label className={labelCls}>
              <span className="mb-1">Kind</span>
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value as AuthProfileKind)}
                className={inputCls}
              >
                {KINDS.map((k) => (
                  <option key={k.value} value={k.value}>
                    {k.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {kind === "form" && (
            <div className="flex flex-wrap items-end gap-3">
              <label className={labelCls}>
                <span className="mb-1">Login URL</span>
                <input
                  value={loginUrl}
                  onChange={(e) => setLoginUrl(e.target.value)}
                  placeholder="https://target.example/login"
                  className={`w-72 ${inputCls}`}
                />
              </label>
              <label className={labelCls}>
                <span className="mb-1">Username field</span>
                <input
                  value={usernameField}
                  onChange={(e) => setUsernameField(e.target.value)}
                  placeholder="email"
                  className={`w-40 ${inputCls}`}
                />
              </label>
              <label className={labelCls}>
                <span className="mb-1">Password field</span>
                <input
                  value={passwordField}
                  onChange={(e) => setPasswordField(e.target.value)}
                  placeholder="password"
                  className={`w-40 ${inputCls}`}
                />
              </label>
              <label className={labelCls}>
                <span className="mb-1">Username</span>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="scanner@aegis.local"
                  className={`w-56 ${inputCls}`}
                />
              </label>
            </div>
          )}
          {kind === "header" && (
            <div className="flex flex-wrap items-end gap-3">
              <label className={labelCls}>
                <span className="mb-1">Header name</span>
                <input
                  value={headerName}
                  onChange={(e) => setHeaderName(e.target.value)}
                  placeholder="X-Api-Key"
                  className={`w-56 ${inputCls}`}
                />
              </label>
            </div>
          )}
          {kind === "cookie" && (
            <div className="flex flex-wrap items-end gap-3">
              <label className={labelCls}>
                <span className="mb-1">Cookie name</span>
                <input
                  value={cookieName}
                  onChange={(e) => setCookieName(e.target.value)}
                  placeholder="session"
                  className={`w-56 ${inputCls}`}
                />
              </label>
            </div>
          )}

          <div className="flex flex-wrap items-end gap-3">
            <label className={labelCls}>
              <span className="mb-1">{SECRET_LABEL[kind]}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                className={`w-72 ${inputCls}`}
              />
            </label>
            <button
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              onClick={create}
              disabled={busy}
            >
              Create
            </button>
          </div>
        </section>
      </RoleGated>
    </div>
  );
}
