import { Loader2 } from "../icons";
import { cn } from "../lib/utils";

export interface SpinnerProps {
  className?: string;
  size?: "sm" | "md" | "lg";
}

/**
 * A pending indicator for a control that is waiting on a request.
 *
 * Decorative: it carries `aria-hidden`, so the surrounding control owns the
 * announcement (a `disabled` button, or a `role="status"` region). A spinner
 * that announced itself would say only that something is spinning.
 */
export function Spinner({ className, size = "md" }: SpinnerProps) {
  const box = size === "sm" ? "h-4 w-4" : size === "lg" ? "h-7 w-7" : "h-5 w-5";
  return (
    <Loader2
      className={cn("animate-spin text-muted-foreground", box, className)}
      aria-hidden
    />
  );
}
