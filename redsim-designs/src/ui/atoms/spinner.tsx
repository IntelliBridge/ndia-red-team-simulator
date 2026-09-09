import { Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

export function Spinner({ className, size = "md" }: { className?: string; size?: "sm" | "md" | "lg" }) {
  const s = size === "sm" ? "h-4 w-4" : size === "lg" ? "h-7 w-7" : "h-5 w-5"
  return <Loader2 className={cn("animate-spin text-muted", s, className)} aria-hidden />
}
