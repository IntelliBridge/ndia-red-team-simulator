import "@/styles/globals.css";

import { AppShell } from "@/components/app-shell";
import { SessionKeepalive } from "@/components/session-keepalive";
import { TRPCReactProvider } from "@/lib/trpc/client";

export const metadata = {
  title: "redsim",
  description: "Adversarial ML Red-Team Simulator",
};

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    // One dark theme, after labs.agiledefense.com. The `dark` class is fixed
    // so the vendored shadcn primitives' `dark:` variants apply; there is no
    // light theme and no toggle.
    <html lang="en" className="dark" suppressHydrationWarning>
      {/* No background on body: globals.css paints the navy ground on the
          root element, and a body fill would sit on top of the login page's
          fixed hero layer, which stacks at z-index -1. */}
      <body className="min-h-screen text-foreground antialiased">
        <TRPCReactProvider>
          <AppShell>{children}</AppShell>
          <SessionKeepalive />
        </TRPCReactProvider>
      </body>
    </html>
  );
}
