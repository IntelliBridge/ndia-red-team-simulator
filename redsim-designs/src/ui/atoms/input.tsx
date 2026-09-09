import { forwardRef } from "react"
import { cn } from "@/lib/utils"

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-8 w-full rounded-md border border-hairline bg-panel px-3 text-sm text-foreground placeholder:text-muted-2",
        "focus:border-primary focus:outline-none disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
)
Input.displayName = "Input"

export const Textarea = forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "w-full rounded-md border border-hairline bg-panel px-3 py-2 text-sm text-foreground placeholder:text-muted-2",
        "focus:border-primary focus:outline-none disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
)
Textarea.displayName = "Textarea"
