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

const TONE: Record<ToastTone, string> = {
  info: "bg-sky-50 text-sky-900 border-sky-200",
  success: "bg-emerald-50 text-emerald-900 border-emerald-200",
  warning: "bg-amber-50 text-amber-900 border-amber-200",
  error: "bg-red-50 text-red-900 border-red-200",
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
            "rounded-md border px-3 py-2 text-sm shadow-md",
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
