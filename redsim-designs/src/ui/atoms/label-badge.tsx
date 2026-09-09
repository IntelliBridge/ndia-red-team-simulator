import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

/**
 * Provenance / status labels. The visible text renders the literal API value
 * (candidate, inferred, heuristic, measured, ...) — never a hard-coded synonym.
 * [spec §18.6]
 */
export const labelBadgeVariants = cva(
  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide border",
  {
    variants: {
      variant: {
        candidate: "border-candidate/40 bg-candidate/10 text-candidate",
        inferred: "border-inferred/40 bg-inferred/10 text-inferred",
        heuristic: "border-heuristic/40 bg-heuristic/10 text-heuristic",
        measured: "border-measured/40 bg-measured/10 text-measured",
        illustrative: "border-illustrative/40 bg-illustrative/10 text-illustrative",
        partial: "border-partial/40 bg-partial/10 text-partial",
        "phase-b": "border-phaseb/40 bg-phaseb/10 text-phaseb",
      },
    },
    defaultVariants: { variant: "inferred" },
  },
)

export interface LabelBadgeProps extends VariantProps<typeof labelBadgeVariants> {
  /** Literal text to render. Defaults to the variant name. */
  children?: React.ReactNode
  className?: string
  title?: string
}

export function LabelBadge({ variant, children, className, title }: LabelBadgeProps) {
  return (
    <span className={cn(labelBadgeVariants({ variant }), className)} title={title}>
      {children ?? variant}
    </span>
  )
}
