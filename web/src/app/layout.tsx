import "./globals.css";

import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { CommandPalette } from "@/components/command-palette";

export const metadata = {
  title: "Aegis",
  description: "Aegis security platform",
};

const NAV_LINKS: { href: string; label: string }[] = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/projects", label: "Projects" },
  { href: "/targets", label: "Targets" },
  { href: "/findings", label: "Findings" },
  { href: "/agents", label: "Agents" },
  { href: "/tools", label: "Kali tools" },
  { href: "/logs", label: "Logs" },
  { href: "/audit", label: "Audit" },
];

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <ThemeProvider>
          <header className="border-b border-border bg-card">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
              <div className="text-lg font-semibold tracking-tight">
                <a href="/dashboard">Aegis</a>
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
          <main className="mx-auto max-w-6xl px-6 py-6">{children}</main>
          <CommandPalette links={NAV_LINKS} />
        </ThemeProvider>
      </body>
    </html>
  );
}
