"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";

import { FindingCard, RoleGated } from "@aegis/design-system";
import { api, type Finding } from "@/lib/api";
import { requireAuth } from "@/lib/auth";
import { useRoles } from "@/hooks/useRoles";

const fetcher = (path: string) => api<Finding>(path);

export default function FindingPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  const { data, error, isLoading, mutate } = useSWR(
    authed ? `/v1/findings/${params.id}` : null,
    fetcher,
  );
  const { roles } = useRoles();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-slate-500">Loading…</p>;
  if (error || !data)
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
        Failed to load.
      </p>
    );

  const blob = data.schema_blob as {
    title?: string;
    description?: string;
    cve?: string;
    target?: string;
  };

  const callerRole = roles[data.project_id];

  const applyFix = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/v1/findings/${data.id}/fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ strategy: "patch", apply: true, open_pr: true }),
      });
      mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const triggerVerify = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/v1/findings/${data.id}/verify`, { method: "POST" });
      mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <FindingCard
        id={data.id}
        title={blob.title ?? data.id}
        severity={data.severity}
        status={data.status}
        target={blob.target}
        validationState={data.validation_state}
        actions={
          <>
            <RoleGated minRole="remediator" callerRole={callerRole}>
              <button
                onClick={triggerVerify}
                disabled={busy}
                className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm hover:bg-slate-100 disabled:opacity-50"
              >
                Verify
              </button>
            </RoleGated>
            <RoleGated minRole="approver" callerRole={callerRole}>
              <button
                onClick={applyFix}
                disabled={busy}
                className="rounded-md bg-sky-700 px-3 py-1.5 text-sm text-white hover:bg-sky-800 disabled:opacity-50"
              >
                Apply patch + open PR
              </button>
            </RoleGated>
          </>
        }
      >
        {blob.description}
      </FindingCard>
      {err && (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          {err}
        </p>
      )}
    </div>
  );
}
