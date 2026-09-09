"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { KeyRound, ShieldCheck } from "lucide-react"
import { BRAND_LONG, BRAND_SHORT, IS_PROD } from "@/lib/env"
import { useSession } from "@/lib/session"
import { Button } from "@/ui/atoms/button"
import { Card } from "@/ui/atoms/card"

export default function LoginPage() {
  const { session, signInDevAdmin } = useSession()
  const router = useRouter()

  useEffect(() => {
    if (session) router.replace("/dashboard")
  }, [session, router])

  return (
    <div className="mx-auto flex min-h-[70vh] max-w-md flex-col items-center justify-center px-6">
      <Card className="w-full p-6">
        <div className="mb-5 flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-primary text-primary-fg">
            <span className="text-xs font-bold">rs</span>
          </div>
          <div>
            <h1 className="text-sm font-semibold text-foreground">{BRAND_LONG}</h1>
            <p className="font-mono text-[11px] text-muted">{BRAND_SHORT}</p>
          </div>
        </div>

        <Button className="w-full" variant="primary" onClick={() => alert("Keycloak OIDC sign-in requires the platform IdP (KEYCLOAK_* env).")}>
          <ShieldCheck className="h-4 w-4" /> Sign in with Keycloak
        </Button>

        {/* Dev-token path — hidden in prod. [spec §3] */}
        {!IS_PROD && (
          <>
            <div className="my-4 flex items-center gap-3 text-[11px] text-muted-2">
              <span className="h-px flex-1 bg-hairline" /> dev only <span className="h-px flex-1 bg-hairline" />
            </div>
            <Button className="w-full" variant="outline" onClick={signInDevAdmin}>
              <KeyRound className="h-4 w-4" /> Continue as dev admin
            </Button>
          </>
        )}

        <p className="mt-5 text-[11px] leading-relaxed text-muted">
          Server-side RBAC and Postgres row-level security are enforced by the API. Roles are viewer, scanner,
          remediator, approver, admin.
        </p>
      </Card>
    </div>
  )
}
