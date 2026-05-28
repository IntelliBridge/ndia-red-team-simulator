"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api, Finding } from "@/lib/api";
import { requireAuth } from "@/lib/auth";

const fetcher = (path: string) => api<Finding>(path);

export default function FindingPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  const { data, error, isLoading, mutate } = useSWR(
    authed ? `/v1/findings/${params.id}` : null, fetcher,
  );
  const [busy, setBusy] = useState(false);

  if (!authed) return <p>Redirecting to sign in…</p>;
  if (isLoading) return <p>Loading…</p>;
  if (error || !data) return <p>Failed to load.</p>;

  const blob = data.schema_blob as {
    title?: string; description?: string; cve?: string;
  };

  const applyFix = async () => {
    setBusy(true);
    try {
      await api(`/v1/findings/${data.id}/fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ strategy: "patch", apply: true, open_pr: true }),
      });
      mutate();
    } finally {
      setBusy(false);
    }
  };

  const triggerVerify = async () => {
    setBusy(true);
    try {
      await api(`/v1/findings/${data.id}/verify`, { method: "POST" });
      mutate();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>{blob.title ?? data.id}</h1>
      <p>
        Severity: <span className={`sev-${data.severity}`}>{data.severity.toUpperCase()}</span>
        {" · "}Status: {data.status}
        {" · "}Validation: <span className={`badge badge-${
          data.validation_state === "poc_passed" ? "verified"
          : data.validation_state === "poc_failed" ? "still_vulnerable"
          : "inconclusive"}`}>{data.validation_state}</span>
      </p>
      <p>{blob.description}</p>
      <div style={{ display: "flex", gap: "0.5rem", marginTop: "1rem" }}>
        <button className="primary" onClick={applyFix} disabled={busy}>
          Apply patch + open PR
        </button>
        <button className="primary" onClick={triggerVerify} disabled={busy}>
          Verify
        </button>
      </div>
    </div>
  );
}
