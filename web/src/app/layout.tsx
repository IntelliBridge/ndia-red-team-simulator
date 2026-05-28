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
      <body>
        <header className="aegis-header">
          <div className="aegis-brand">Aegis</div>
          <nav>
            <a href="/dashboard">Dashboard</a>
            <a href="/targets">Targets</a>
          </nav>
        </header>
        <main className="aegis-main">{children}</main>
      </body>
    </html>
  );
}
