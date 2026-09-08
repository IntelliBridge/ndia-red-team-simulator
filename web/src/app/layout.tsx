import "./globals.css";

import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { CommandPalette } from "@/components/command-palette";

export const metadata = {
  title: "redsim",
  description: "Adversarial ML evaluation simulator (proof of concept)",
};

const NAV_LINKS: { href: string; label: string }[] = [
  { href: "/targets", label: "Targets" },
  { href: "/runs", label: "Runs" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <ThemeProvider>
          <a
            href="#main-content"
            className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
          >
            Skip to content
          </a>
          <header className="border-b border-border bg-card">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
              <div className="text-lg font-semibold tracking-tight">
                <a href="/runs">redsim</a>
              </div>
              <nav className="flex items-center gap-4 text-sm">
                {NAV_LINKS.map((link) => (
                  <a key={link.href} className="text-muted-foreground hover:text-foreground" href={link.href}>
                    {link.label}
                  </a>
                ))}
                <ThemeToggle />
              </nav>
            </div>
          </header>
          <main id="main-content" tabIndex={-1} className="mx-auto max-w-6xl px-6 py-6">
            {children}
          </main>
          <footer className="mx-auto max-w-6xl px-6 py-6 text-xs text-muted-foreground">
            Proof of concept on public data. Results are evidence for human review, not a safety or
            readiness determination.
          </footer>
          <CommandPalette links={NAV_LINKS} />
        </ThemeProvider>
      </body>
    </html>
  );
}
