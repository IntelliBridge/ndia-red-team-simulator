import Link from "next/link"
import { AlertTriangle, Inbox, RefreshCw } from "lucide-react"
import { ApiError } from "@/lib/api"
import { Button } from "@/ui/atoms/button"

export function EmptyState({ title, hint, actionHref, actionLabel }: { title: string; hint?: string; actionHref?: string; actionLabel?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-hairline bg-panel px-6 py-12 text-center">
      <Inbox className="h-6 w-6 text-muted-2" />
      <p className="text-sm font-medium text-foreground">{title}</p>
      {hint && <p className="max-w-md text-xs text-muted">{hint}</p>}
      {actionHref && actionLabel && (
        <Link href={actionHref} className="mt-1">
          <Button variant="outline" size="sm">{actionLabel}</Button>
        </Link>
      )}
    </div>
  )
}

/**
 * The explicit unavailable state for a 503 (queue/worker down) and other errors.
 * Renders the structured error code + message verbatim; never falls back to an
 * in-process result. [spec §6, §17.3]
 */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const detail = error instanceof ApiError ? error.detail : { code: "unknown", message: String((error as Error)?.message ?? error) }
  const status = error instanceof ApiError ? error.status : undefined
  const unavailable = status === 503
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-hairline bg-panel px-6 py-12 text-center">
      <AlertTriangle className={unavailable ? "h-6 w-6 text-degraded" : "h-6 w-6 text-critical"} />
      <p className="text-sm font-medium text-foreground">
        {unavailable ? "Service unavailable" : "Request failed"}
      </p>
      <p className="font-mono text-xs text-muted">
        {status ? `${status} ` : ""}
        {detail.code}
      </p>
      <p className="max-w-md text-xs text-muted">{detail.message}</p>
      {detail.reasons?.length ? (
        <ul className="mt-1 list-inside list-disc text-left text-xs text-muted">
          {detail.reasons.map((r) => <li key={r}>{r}</li>)}
        </ul>
      ) : null}
      {unavailable && <p className="max-w-md text-xs text-muted-2">Retry once the API is reachable.</p>}
      {onRetry && (
        <Button variant="outline" size="sm" className="mt-1" onClick={onRetry}>
          <RefreshCw className="h-3.5 w-3.5" /> Retry
        </Button>
      )}
    </div>
  )
}
