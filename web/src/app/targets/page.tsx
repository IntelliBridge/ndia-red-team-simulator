"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
  RoleGated,
} from "@redsim/design-system";
import {
  api,
  deleteTarget,
  listAuthProfiles,
  listScanners,
  startScan,
  type AuthProfile,
  type ScannerInfo,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

type Target = {
  id: string; kind: string; value: string; verified: boolean; project_id: string;
};

const fetcher = (path: string) => api<{ targets: Target[] }>(path);

// The scanner roster is data, not a literal list: it comes from
// GET /v1/scanners (the live adapter registry). The pentest built-ins were
// removed with the pentest domain, so until an ML attack adapter
// (redsim.ml.attacks) or a signed plugin registers, the roster is empty and
// Start scan must be disabled with an explicit notice. POST /v1/scans rejects
// any unregistered name with 400, so offering one would only ever fail.
// Adapters that declare the "dast" capability can additionally scan behind a
// login via an auth profile.
const scannersFetcher = () => listScanners();
const NO_ADAPTER_NOTICE =
  "No attack adapter is registered. Start scan is disabled until an ML attack " +
  "adapter (redsim.ml.attacks) or a signed plugin registers through redsim.scanners.";

const profilesFetcher = () => listAuthProfiles("default");

export default function TargetsPage() {
  const router = useRouter();
  const authed = useRequireAuth();

  const { data, error, mutate } = useSWR(
    authed ? "/v1/targets?project=default" : null, fetcher,
  );
  const { roles } = useRoles();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [scannerChoice, setScannerChoice] = useState<string>("");
  const [authProfileId, setAuthProfileId] = useState("");

  const { data: scannersData, error: scannersError } = useSWR(
    authed ? "/v1/scanners" : null, scannersFetcher,
  );
  const scanners: ScannerInfo[] = Array.isArray(scannersData) ? scannersData : [];
  const noAdapters = scanners.length === 0;
  // Fall back to the first registered adapter until the user picks one; a
  // stale choice (adapter unregistered since) is never sent to the API.
  const scanner = scanners.some((s) => s.name === scannerChoice)
    ? scannerChoice
    : (scanners[0]?.name ?? "");
  const isDast =
    scanners.find((s) => s.name === scanner)?.capabilities.includes("dast") ?? false;
  const { data: profilesData } = useSWR(
    authed && isDast ? "/v1/auth-profiles?project=default" : null,
    profilesFetcher,
  );
  const profiles: AuthProfile[] = Array.isArray(profilesData) ? profilesData : [];

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;
  if (error) return <p className="text-muted-foreground">Failed to load.</p>;

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
    if (!scanner) {
      // Defensive: the button is disabled in this state, but never POST an
      // empty scanner (the API would 400 with "scanner required").
      setErr(NO_ADAPTER_NOTICE);
      return;
    }
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

  const removeTarget = async (target: Target) => {
    setBusy(true);
    try {
      setErr(null);
      await deleteTarget(target.id);
      mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Targets</h1>
      <p className="text-sm text-muted-foreground">
        Adversarial ML model targets are registered in the{" "}
        <a href="/models" className="text-primary underline">
          model catalog
        </a>
        . This page stays available until the catalog API is mounted.
      </p>
      {err && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}
      {noAdapters && (
        <p
          role="status"
          className="rounded-md border border-border bg-muted p-3 text-sm text-muted-foreground"
        >
          {scannersError
            ? "Could not load the attack adapter roster (GET /v1/scanners). Start scan is disabled."
            : scannersData === undefined
              ? "Loading attack adapters…"
              : NO_ADAPTER_NOTICE}
        </p>
      )}
      <div className="flex flex-wrap items-start gap-3">
        <label className="flex flex-col text-sm">
          <span className="mb-1">Scanner</span>
          <select
            value={scanner}
            disabled={noAdapters}
            onChange={(e) => { setScannerChoice(e.target.value); setAuthProfileId(""); }}
            className="rounded-md border border-border bg-background px-2 py-1.5 disabled:opacity-50"
          >
            {noAdapters && <option value="">No attack adapter registered</option>}
            {scanners.map((s) => (
              <option key={s.name} value={s.name}>{s.name}</option>
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
                className="w-72 rounded-md border border-border bg-background px-2 py-1.5"
              >
                <option value="">None</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>{p.name} ({p.kind})</option>
                ))}
              </select>
            </label>
            <span className="mt-1 text-xs text-muted-foreground">
              Lets adapters with the dast capability test behind a login. Manage profiles under Auth Profiles.
            </span>
          </div>
        )}
      </div>
      <div className="overflow-hidden rounded-md border border-border bg-card">
        <table className="w-full text-sm">
          <caption className="sr-only">Registered targets</caption>
          <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2">ID</th>
              <th scope="col" className="px-3 py-2">Kind</th>
              <th scope="col" className="px-3 py-2">Value</th>
              <th scope="col" className="px-3 py-2">Verified</th>
              <th scope="col" className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(data?.targets ?? []).map((t) => (
              <tr key={t.id} className="border-t border-border">
                <td className="px-3 py-2">{t.id}</td>
                <td className="px-3 py-2">{t.kind}</td>
                <td className="px-3 py-2">{t.value}</td>
                <td className="px-3 py-2">{t.verified ? "yes" : "no"}</td>
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <button
                      className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                      disabled={busy || noAdapters}
                      title={noAdapters ? NO_ADAPTER_NOTICE : undefined}
                      onClick={() => launchScan(t)}
                    >
                      Start scan
                    </button>
                    <RoleGated minRole="admin" callerRole={roles[t.project_id]}>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <button
                            className="rounded-md border border-border px-3 py-1.5 text-sm text-destructive hover:bg-muted disabled:opacity-50"
                            disabled={busy}
                          >
                            Delete
                          </button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Delete target?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This permanently removes{" "}
                              <span className="font-mono">{t.value}</span> and is
                              written to the audit chain. It cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              variant="destructive"
                              onClick={() => removeTarget(t)}
                            >
                              Delete target
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </RoleGated>
                  </div>
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
          className="w-80 rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        />
        <button
          className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          onClick={create}
          disabled={busy}
        >
          Add
        </button>
      </div>
    </div>
  );
}
