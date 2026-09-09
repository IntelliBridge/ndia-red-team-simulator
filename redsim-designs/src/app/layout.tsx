import type { Metadata, Viewport } from "next"
import { Inter, JetBrains_Mono } from "next/font/google"
import { cookies } from "next/headers"
import "./globals.css"
import { BRAND_LONG } from "@/lib/env"
import { parseSession, SESSION_COOKIE } from "@/lib/session-cookie"
import { Providers } from "./providers"
import { AppShell } from "@/ui/templates/app-shell"

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" })
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jbmono", display: "swap" })

export const metadata: Metadata = {
  title: `${BRAND_LONG} · redsim`,
  description:
    "Non-operational proof of concept measuring the robustness of image and tabular classifiers under adversarial evasion attacks on open, unclassified public data.",
}

export const viewport: Viewport = {
  themeColor: "#0b0f14",
  colorScheme: "dark",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Read the session on the server so the first paint is already authenticated.
  const initialSession = parseSession(cookies().get(SESSION_COOKIE)?.value)
  return (
    <html lang="en" className={`dark bg-base ${inter.variable} ${mono.variable}`}>
      <body>
        <Providers initialSession={initialSession}>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
