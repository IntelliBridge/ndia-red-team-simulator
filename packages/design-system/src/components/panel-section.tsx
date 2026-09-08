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
    <section className={`redsim-panel overflow-hidden rounded-sm ${className}`}>
      <header className="flex items-baseline justify-between border-b border-border px-4 py-3">
        <div>
          <div className="redsim-kicker">{eyebrow}</div>
          <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
        </div>
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}
