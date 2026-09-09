import { cn } from "@/lib/utils"

/**
 * A titled panel. Measurements / observations / interpretation / candidates each
 * use a distinct `tone` so the four are never visually interleaved. [spec §18.3]
 */
export function PanelSection({
  title,
  subtitle,
  right,
  tone = "default",
  id,
  children,
  className,
}: {
  title: string
  subtitle?: React.ReactNode
  right?: React.ReactNode
  tone?: "default" | "measurement" | "observation" | "interpretation" | "candidate"
  id?: string
  children: React.ReactNode
  className?: string
}) {
  const accent = {
    default: "border-l-hairline",
    measurement: "border-l-primary",
    observation: "border-l-adversarial",
    interpretation: "border-l-inferred",
    candidate: "border-l-candidate",
  }[tone]

  return (
    <section id={id} className={cn("rounded-lg border border-hairline border-l-2 bg-panel", accent, className)}>
      <header className="flex items-center justify-between gap-4 border-b border-hairline px-4 py-2.5">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
        </div>
        {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
      </header>
      <div className="p-4">{children}</div>
    </section>
  )
}
