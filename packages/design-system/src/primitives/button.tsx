import { forwardRef } from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "../lib/utils";

/**
 * Class recipe for {@link Button}.
 *
 * Exported so a element that must not be a `<button>` (a `next/link`
 * anchor, say) can still take the button's shape without nesting one
 * inside the other.
 */
export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors duration-150 disabled:pointer-events-none disabled:opacity-45",
  {
    variants: {
      variant: {
        primary: "bg-primary text-primary-fg hover:brightness-110",
        secondary:
          "bg-panel-2 text-foreground border border-hairline hover:bg-hairline",
        ghost:
          "bg-transparent text-muted-foreground hover:bg-panel-2 hover:text-foreground",
        outline:
          "bg-transparent text-foreground border border-hairline hover:border-primary hover:text-primary",
        danger: "bg-critical text-white hover:brightness-110",
      },
      size: {
        sm: "h-[26px] px-2.5 text-xs",
        md: "h-8 px-3.5 text-sm",
        lg: "h-10 px-5 text-sm",
        icon: "h-8 w-8 p-0",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

/**
 * The app's button.
 *
 * @param variant - Visual weight. `secondary` by default, so an unmarked
 * button never reads as the primary action on a panel.
 * @param size - `icon` is square and drops the padding, for a glyph alone.
 *
 * @example
 * ```tsx
 * <Button variant="primary" onClick={launch}>Launch campaign</Button>
 * ```
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Button.displayName = "Button";
