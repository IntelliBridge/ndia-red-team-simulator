"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";

import { AuditChainBadge } from "@aegis/design-system";
import { api } from "@/lib/api";
import { requireAuth } from "@/lib/auth";

interface ChainStatus {
  chain_id: string;
  verified: boolean;
  event_count: number;
  head_hash: string | null;
}

interface VerifyResponse {
  chains: ChainStatus[];
}

const fetcher = (path: string) => api<VerifyResponse>(path);

export default function AuditPage() {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  // The /v1/audit/verify endpoint walks every chain the writer knows.
  // Admin-only; non-admins get 403 from the API.
  const { data, error, isLoading } = useSWR(
    authed ? "/v1/audit/verify?all=1" : null,
    fetcher,
  );

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-slate-500">Verifying chains…</p>;
  if (error)
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
        Failed to verify: {String(error)}
      </p>
    );

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Audit chains</h1>
          <p className="text-sm text-slate-600">
            Every project + run carries an append-only hash-chained audit.
            Each entry below is one chain.
          </p>
        </div>
      </header>

      <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Chain</th>
              <th className="px-3 py-2">Events</th>
              <th className="px-3 py-2">State</th>
              <th className="px-3 py-2">Head hash</th>
            </tr>
          </thead>
          <tbody>
            {(data?.chains ?? []).map((c) => (
              <tr key={c.chain_id} className="border-t border-slate-100">
                <td className="px-3 py-2 font-mono text-xs">{c.chain_id}</td>
                <td className="px-3 py-2">{c.event_count}</td>
                <td className="px-3 py-2">
                  <AuditChainBadge
                    state={c.verified ? "verified" : "broken"}
                    chainId={c.chain_id}
                    events={c.event_count}
                  />
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-500">
                  {c.head_hash ? c.head_hash.slice(0, 16) + "…" : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
