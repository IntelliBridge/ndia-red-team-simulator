// ToastList — minimal stack of transient notifications.
//
// Intentionally tiny — Radix toast lands in a follow-up batch; for
// v0.4.0 we just need a non-blocking surface for "scan started",
// "fix applied", "auth refreshed" etc.

import { type ReactNode } from "react";
import { cn } from "../lib/utils";

export type ToastTone = "info" | "success" | "warning" | "error";

export interface Toast {
  id: string;
  tone?: ToastTone;
  title: string;
  description?: ReactNode;
}

export interface ToastListProps {
  toasts: Toast[];
  onDismiss?: (id: string) => void;
  className?: string;
}

// On the panel surface. `error` is orange, not red: red is the brand
// accent in this UI.
const TONE: Record<ToastTone, string> = {
  info: "border-sky-400/40 bg-surface-2 text-sky-200",
  success: "border-emerald-400/40 bg-surface-2 text-emerald-200",
  warning: "border-amber-400/50 bg-surface-2 text-amber-200",
  error: "border-orange-400/50 bg-surface-2 text-orange-200",
};

export function ToastList({ toasts, onDismiss, className }: ToastListProps) {
  if (toasts.length === 0) return null;
  return (
    <ul
      aria-live="polite"
      className={cn(
        "fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2",
        className,
      )}
    >
      {toasts.map((t) => (
        <li
          key={t.id}
          className={cn(
            "rounded-md border px-3 py-2 text-sm shadow-lg",
            TONE[t.tone ?? "info"],
          )}
        >
          <div className="flex items-start justify-between gap-2">
            <strong>{t.title}</strong>
            {onDismiss && (
              <button
                type="button"
                aria-label={`dismiss ${t.title}`}
                onClick={() => onDismiss(t.id)}
                className="text-xs opacity-70 hover:opacity-100"
              >
                ×
              </button>
            )}
          </div>
          {t.description && (
            <div className="mt-1 text-xs opacity-80">{t.description}</div>
          )}
        </li>
      ))}
    </ul>
  );
}
