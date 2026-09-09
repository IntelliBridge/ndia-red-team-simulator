// PanelSection — one section of the ruled sheet.
//
// A rule above, the title in the left margin column on wide screens with the
// eyebrow as a small note beneath it, and the content beside it. Content
// that is read lives here; content that is acted on lives in a `redsim-panel`.
// The props are unchanged from the earlier boxed version so no caller moves.

import { type ReactNode } from "react";
export interface PanelSectionProps {
  title: string;
  eyebrow?: string;
  children?: ReactNode;
  className?: string;
}
export function PanelSection({
  title,
  eyebrow,
  children,
  className = "",
}: PanelSectionProps) {
  return (
    <section className={`redsim-sheet ${className}`}>
      <header className="redsim-sheet-label">
        <h2 className="m-0 text-sm font-semibold tracking-tight">{title}</h2>
        {eyebrow ? <small className="redsim-sheet-note">{eyebrow}</small> : null}
      </header>
      <div className="redsim-sheet-body">{children}</div>
    </section>
  );
}
