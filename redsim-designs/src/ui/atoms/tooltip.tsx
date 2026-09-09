"use client"

import { useState, type ReactNode } from "react"
import { cn } from "@/lib/utils"

export function Tooltip({ content, children, className }: { content: ReactNode; children: ReactNode; className?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          className={cn(
            "absolute bottom-full left-1/2 z-50 mb-1.5 -translate-x-1/2 whitespace-pre rounded-md border border-hairline bg-panel-2 px-2 py-1 text-[11px] text-foreground shadow-lg",
            className,
          )}
        >
          {content}
        </span>
      )}
    </span>
  )
}
