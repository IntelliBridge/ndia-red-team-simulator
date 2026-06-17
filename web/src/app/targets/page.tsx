"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api, listAuthProfiles, startScan, type AuthProfile } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";

type Target = {
  id: string; kind: string; value: string; verified: boolean; project_id: string;
};

const fetcher = (path: string) => api<{ targets: Target[] }>(path);

// Scanners that take a URL target. DAST scanners can additionally scan
// behind a login via an auth profile (feat/authenticated-dast).
const SCANNERS = ["trivy", "zap", "nuclei"] as const;
const DAST_SCANNERS = new Set(["zap", "nuclei"]);

const profilesFetcher = () => listAuthProfiles("default");

export default function TargetsPage() {
  const router = useRouter();
  const authed = useRequireAuth();

  const { data, error, mutate } = useSWR(
    authed ? "/v1/targets?project=default" : null, fetcher,
  );
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [scanner, setScanner] = useState<string>("trivy");
  const [authProfileId, setAuthProfileId] = useState("");

  const isDast = DAST_SCANNERS.has(scanner);
  const { data: profilesData } = useSWR(
    authed && isDast ? "/v1/auth-profiles?project=default" : null,
    profilesFetcher,
  );
  const profiles: AuthProfile[] = Array.isArray(profilesData) ? profilesData : [];

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (error) return <p className="text-slate-600">Failed to load.</p>;

  const create = async () => {
    if (!value) return;
    setBusy(true);
    try {
      setErr(null);
      await api("/v1/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "url", value, project_id: "default" }),
      });
      setValue("");
      mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const launchScan = async (target: Target) => {
    setBusy(true);
    try {
      setErr(null);
      const out = await startScan({
        target: target.value,
        scanner,
        project_id: target.project_id,
        ...(isDast && authProfileId ? { auth_profile_id: authProfileId } : {}),
      });
      router.push(`/runs/${out.run_id}`);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Targets</h1>
      {err && (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          {err}
        </p>
      )}
      <div className="flex flex-wrap items-start gap-3">
        <label className="flex flex-col text-sm">
          <span className="mb-1">Scanner</span>
          <select
            value={scanner}
            onChange={(e) => { setScanner(e.target.value); setAuthProfileId(""); }}
            className="rounded-md border border-slate-200 bg-white px-2 py-1.5"
          >
            {SCANNERS.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        {isDast && (
          <div className="flex flex-col text-sm">
            <label className="flex flex-col">
              <span className="mb-1">Authentication profile (optional)</span>
              <select
                value={authProfileId}
                onChange={(e) => setAuthProfileId(e.target.value)}
                className="w-72 rounded-md border border-slate-200 bg-white px-2 py-1.5"
              >
                <option value="">None</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>{p.name} ({p.kind})</option>
                ))}
              </select>
            </label>
            <span className="mt-1 text-xs text-slate-500">
              Lets DAST scanners test behind a login. Manage profiles under Auth Profiles.
            </span>
          </div>
        )}
      </div>
      <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Kind</th>
              <th className="px-3 py-2">Value</th>
              <th className="px-3 py-2">Verified</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(data?.targets ?? []).map((t) => (
              <tr key={t.id} className="border-t border-slate-100">
                <td className="px-3 py-2">{t.id}</td>
                <td className="px-3 py-2">{t.kind}</td>
                <td className="px-3 py-2">{t.value}</td>
                <td className="px-3 py-2">{t.verified ? "yes" : "no"}</td>
                <td className="px-3 py-2">
                  <button
                    className="rounded-md bg-sky-700 px-3 py-1.5 text-sm text-white hover:bg-sky-800 disabled:opacity-50"
                    disabled={busy}
                    onClick={() => launchScan(t)}
                  >
                    Start scan
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h2 className="text-lg font-semibold">Register target</h2>
      <div className="flex items-center gap-3">
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="https://target.example"
          className="w-80 rounded-md border border-slate-200 px-3 py-1.5 text-sm"
        />
        <button
          className="rounded-md bg-sky-700 px-3 py-1.5 text-sm text-white hover:bg-sky-800 disabled:opacity-50"
          onClick={create}
          disabled={busy}
        >
          Add
        </button>
      </div>
    </div>
  );
}
