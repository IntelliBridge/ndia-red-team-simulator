import { forwardRef } from "react";

import { ChevronDown } from "../icons";
import { cn } from "../lib/utils";

export interface SelectProps
  extends React.SelectHTMLAttributes<HTMLSelectElement> {
  /** The choices, in the order they should be offered. */
  options: { value: string; label: string }[];
  /** Label for an empty leading option, when no choice is made yet. */
  placeholder?: string;
}

/**
 * A native `<select>` with the app's chrome.
 *
 * Native rather than a listbox widget: the platform control keeps keyboard
 * and screen-reader behaviour for free, and nothing here needs a custom
 * option renderer.
 *
 * @example
 * ```tsx
 * <Select options={ROLES} value={role} onChange={(e) => setRole(e.target.value)} />
 * ```
 */
export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, options, placeholder, ...props }, ref) => (
    <div className="relative">
      <select
        ref={ref}
        className={cn(
          "h-8 w-full appearance-none rounded-md border border-hairline bg-panel pl-3 pr-8 text-sm text-foreground",
          "focus:border-primary focus:outline-none disabled:opacity-50",
          className,
        )}
        {...props}
      >
        {placeholder ? <option value="">{placeholder}</option> : null}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
    </div>
  ),
);
Select.displayName = "Select";
