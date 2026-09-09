import Link from "next/link"
import { ShieldCheck, ShieldAlert } from "lucide-react"
import { cn } from "@/lib/utils"

/** "hash-chained, tamper-evident" wording only. Never "tamper-proof". [spec §18.1] */
export function AuditChainBadge({ chainId, verified, className }: { chainId: string; verified: boolean; className?: string }) {
  return (
    <Link
      href={`/audit?chain=${encodeURIComponent(chainId)}`}
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs",
        verified ? "border-robust/40 bg-robust/10 text-robust" : "border-critical/40 bg-critical/10 text-critical",
        className,
      )}
    >
      {verified ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />}
      <span className="font-mono">{chainId}</span>
      <span className="text-muted">· hash-chained, tamper-evident</span>
    </Link>
  )
}
