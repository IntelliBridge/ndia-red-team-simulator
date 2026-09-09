"use client";

// DAST authentication profiles.
//
// Profiles hold the non-secret config; the secret (password / token /
// header value / cookie value) is write-only — the API never returns it,
// and this page never renders it back.

import { useState } from "react";
import useSWR from "swr";

import { RoleGated } from "@redsim/design-system";
import {
  createAuthProfile,
  deleteAuthProfile,
  listAuthProfiles,
  type AuthProfile,
  type AuthProfileKind,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

// Same project scoping as /targets: a single hard-coded project.
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

const inputCls = "redsim-input";
const labelCls = "block text-sm";
const fieldLabelCls = "redsim-kicker mb-1 block";

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
    return <p className="text-ink-3">Signing in…</p>;
  if (isLoading) return <p className="text-ink-3">Loading…</p>;
  if (error) return <p className="text-ink-3">Failed to load.</p>;

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
        <h1>Auth Profiles</h1>
        <p className="mt-1 max-w-[60ch] text-sm text-ink-3">
          Credentials DAST scanners use to test behind a login. Secrets are
          write-only and never shown again.
        </p>
      </header>

      {err && (
        <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <caption className="sr-only">DAST authentication profiles</caption>
          <thead className="text-left">
            <tr className="border-b border-line-strong">
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
                <td colSpan={5} className="px-3 py-4 text-ink-3">
                  No authentication profiles yet.
                </td>
              </tr>
            )}
            {profiles.map((p) => (
              <tr key={p.id} className="border-b border-line last:border-0">
                <td className="px-3 py-2.5 text-ink-1">{p.name}</td>
                <td className="px-3 py-2.5"><span className="redsim-chip">{p.kind}</span></td>
                <td className="px-3 py-2.5 font-mono text-xs text-ink-3">
                  {Object.entries(p.config ?? {})
                    .map(([k, v]) => `${k}=${v}`)
                    .join(" ") || "—"}
                </td>
                <td className="px-3 py-2.5 tabular-nums text-ink-3">{p.created_at}</td>
                <td className="px-3 py-2.5">
                  <RoleGated minRole="admin" callerRole={callerRole}>
                    <button
                      className="redsim-ghost redsim-btn-sm border-destructive/50 text-destructive"
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
        <section className="redsim-sheet">
          <h2 className="redsim-sheet-label">Create profile</h2>
          <div className="redsim-sheet-body redsim-panel space-y-4 p-5">
          <div className="flex flex-wrap items-end gap-3">
            <label className={labelCls}>
              <span className={fieldLabelCls}>Name</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="staging-login"
                className={`w-56 ${inputCls}`}
              />
            </label>
            <label className={labelCls}>
              <span className={fieldLabelCls}>Kind</span>
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
                <span className={fieldLabelCls}>Login URL</span>
                <input
                  value={loginUrl}
                  onChange={(e) => setLoginUrl(e.target.value)}
                  placeholder="https://target.example/login"
                  className={`w-72 ${inputCls}`}
                />
              </label>
              <label className={labelCls}>
                <span className={fieldLabelCls}>Username field</span>
                <input
                  value={usernameField}
                  onChange={(e) => setUsernameField(e.target.value)}
                  placeholder="email"
                  className={`w-40 ${inputCls}`}
                />
              </label>
              <label className={labelCls}>
                <span className={fieldLabelCls}>Password field</span>
                <input
                  value={passwordField}
                  onChange={(e) => setPasswordField(e.target.value)}
                  placeholder="password"
                  className={`w-40 ${inputCls}`}
                />
              </label>
              <label className={labelCls}>
                <span className={fieldLabelCls}>Username</span>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="scanner@redsim.local"
                  className={`w-56 ${inputCls}`}
                />
              </label>
            </div>
          )}
          {kind === "header" && (
            <div className="flex flex-wrap items-end gap-3">
              <label className={labelCls}>
                <span className={fieldLabelCls}>Header name</span>
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
                <span className={fieldLabelCls}>Cookie name</span>
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
              <span className={fieldLabelCls}>{SECRET_LABEL[kind]}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                className={`w-72 ${inputCls}`}
              />
            </label>
            <button
              className="redsim-cta"
              onClick={create}
              disabled={busy}
            >
              Create
            </button>
          </div>
          </div>
        </section>
      </RoleGated>
    </div>
  );
}
