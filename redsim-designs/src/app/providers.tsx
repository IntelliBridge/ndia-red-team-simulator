"use client"

import type { ReactNode } from "react"
import { SWRConfig } from "swr"
import { SessionProvider } from "@/lib/session"
import type { Session } from "@/lib/session-cookie"
import { swrFetcher } from "@/lib/api"

export function Providers({ initialSession, children }: { initialSession: Session | null; children: ReactNode }) {
  return (
    <SessionProvider initialSession={initialSession}>
      <SWRConfig
        value={{
          fetcher: swrFetcher,
          revalidateOnFocus: false,
          shouldRetryOnError: false,
          // Load once, then update quietly: cached data shows instantly on
          // revisit and while a key changes, revalidating in the background.
          keepPreviousData: true,
          dedupingInterval: 60_000,
        }}
      >
        {children}
      </SWRConfig>
    </SessionProvider>
  )
}
