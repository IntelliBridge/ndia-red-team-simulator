import { forwardRef } from "react";

import { cn } from "../lib/utils";

export interface CheckboxProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  /** Text rendered beside the box, inside the same label. */
  label?: React.ReactNode;
}

/**
 * A checkbox and its label as one control.
 *
 * The `<input>` is wrapped in the `<label>` rather than linked by id, so a
 * caller can render several without inventing unique ids for each.
 */
export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, disabled, ...props }, ref) => (
    <label
      className={cn(
        "inline-flex items-center gap-2 text-sm",
        disabled && "opacity-50",
        className,
      )}
    >
      <input
        ref={ref}
        type="checkbox"
        disabled={disabled}
        className="h-4 w-4 rounded border-hairline bg-panel text-primary accent-[hsl(var(--primary))] focus:outline-none"
        {...props}
      />
      {label ? <span className="text-foreground">{label}</span> : null}
    </label>
  ),
);
Checkbox.displayName = "Checkbox";
