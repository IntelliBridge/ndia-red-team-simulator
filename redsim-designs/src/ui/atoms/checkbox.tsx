import { forwardRef } from "react"
import { cn } from "@/lib/utils"

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: React.ReactNode
}

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, disabled, ...props }, ref) => (
    <label className={cn("inline-flex items-center gap-2 text-sm", disabled && "opacity-50", className)}>
      <input
        ref={ref}
        type="checkbox"
        disabled={disabled}
        className="h-4 w-4 rounded border-hairline bg-panel text-primary accent-[var(--primary)] focus:outline-none"
        {...props}
      />
      {label && <span className="text-foreground">{label}</span>}
    </label>
  ),
)
Checkbox.displayName = "Checkbox"
