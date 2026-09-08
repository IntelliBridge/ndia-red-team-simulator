"use client";

import { useState } from "react";
import useSWR from "swr";

import { FindingCard, RoleGated } from "@redsim/design-system";
import { api, type Finding } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

const fetcher = (path: string) => api<Finding>(path);

export default function FindingPage({ params }: { params: { id: string } }) {
  const authed = useRequireAuth();

  const { data, error, isLoading, mutate } = useSWR(
    authed ? `/v1/findings/${params.id}` : null,
    fetcher,
  );
  const { roles } = useRoles();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;
  if (error || !data)
    return (
      <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load.
      </p>
    );

  const blob = data.schema_blob;

  const callerRole = roles[data.project_id];

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
          <RoleGated minRole="remediator" callerRole={callerRole}>
            <button
              onClick={triggerVerify}
              disabled={busy}
              className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
            >
              Verify
            </button>
          </RoleGated>
        }
      >
        {blob.description}
      </FindingCard>
      {err && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}
    </div>
  );
}
