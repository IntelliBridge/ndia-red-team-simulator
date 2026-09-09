import "@/styles/globals.css";

import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { CommandPalette } from "@/components/command-palette";
import { TRPCReactProvider } from "@/lib/trpc/client";

export const metadata = {
  title: "redsim",
  description: "Adversarial ML Red-Team Simulator",
};

const NAV_LINKS: { href: string; label: string }[] = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/models", label: "Models" },
  { href: "/runs", label: "Runs" },
  { href: "/projects", label: "Projects" },
  { href: "/auth-profiles", label: "Auth Profiles" },
  { href: "/findings", label: "Findings" },
  { href: "/logs", label: "Logs" },
  { href: "/audit", label: "Audit" },
  { href: "/cost", label: "Cost" },
];

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        {/* Outside ThemeProvider so every page, including the hydration
            boundary a server component renders, sits inside one QueryClient. */}
        <TRPCReactProvider>
        <ThemeProvider>
          {/* Skip link: first focusable element, visually hidden until
              keyboard-focused, so keyboard/screen-reader users can jump
              past the nav straight to the page content. */}
          <a
            href="#main-content"
            className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
          >
            Skip to content
          </a>
           <header className="border-b border-border bg-card">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
              <div className="text-lg font-semibold tracking-tight">
                <a href="/dashboard">redsim</a>
              </div>
              <nav className="flex items-center gap-4 text-sm">
                {NAV_LINKS.map((link) => (
                  <a
                    key={link.href}
                    className="text-muted-foreground hover:text-foreground"
                    href={link.href}
                  >
                    {link.label}
                  </a>
                ))}
                <ThemeToggle />
              </nav>
            </div>
           </header>
          <main
            id="main-content"
            tabIndex={-1}
            className="mx-auto max-w-6xl px-6 py-6"
          >
             {children}
             <footer className="redsim-footer mt-12">Proof of concept on open, unclassified public data. Results are evidence for human review, not a safety, readiness, or certification determination.</footer>
          </main>
          <CommandPalette links={NAV_LINKS} />
        </ThemeProvider>
        </TRPCReactProvider>
      </body>
    </html>
  );
}
