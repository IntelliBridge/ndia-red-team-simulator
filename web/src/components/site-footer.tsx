"use client";

// SiteFooter — the disclaimer line under every page's content. Hidden on the
// login page, where there are no results to qualify and the hero carries the
// bottom of the viewport.

import { usePathname } from "next/navigation";

export function SiteFooter() {
  const pathname = usePathname() ?? "";
  if (pathname === "/login") return null;
  return (
    <footer className="redsim-footer">
      <div className="redsim-meta mb-2">
        REDSIM // ADVERSARIAL ML RED-TEAM SIMULATOR
      </div>
      Proof of concept on open, unclassified public data. Results are
      evidence for human review, not a safety, readiness, or certification
      determination.
    </footer>
  );
}
