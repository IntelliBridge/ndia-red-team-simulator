import "./globals.css";

export const metadata = {
  title: "Aegis",
  description: "Aegis security platform",
};

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased">
        <header className="border-b border-slate-200 bg-white">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
            <div className="text-lg font-semibold tracking-tight">
              <a href="/dashboard">Aegis</a>
            </div>
            <nav className="flex items-center gap-4 text-sm">
              <a className="hover:text-sky-700" href="/dashboard">Dashboard</a>
              <a className="hover:text-sky-700" href="/projects">Projects</a>
              <a className="hover:text-sky-700" href="/targets">Targets</a>
              <a className="hover:text-sky-700" href="/audit">Audit</a>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-6">{children}</main>
      </body>
    </html>
  );
}
