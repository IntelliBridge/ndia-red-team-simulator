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
} from "@aegis/design-system";
import { api, deleteTarget } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

type Target = {
  id: string; kind: string; value: string; verified: boolean; project_id: string;
};

const fetcher = (path: string) => api<{ targets: Target[] }>(path);

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

  const startScan = async (target: Target) => {
    setBusy(true);
    try {
      setErr(null);
      const out = await api<{ run_id: string }>("/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.value, scanner: "trivy",
          project_id: target.project_id,
        }),
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
      {err && (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          {err}
        </p>
      )}
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
                  <div className="flex items-center gap-2">
                    <button
                      className="rounded-md bg-sky-700 px-3 py-1.5 text-sm text-white hover:bg-sky-800 disabled:opacity-50"
                      disabled={busy}
                      onClick={() => startScan(t)}
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
