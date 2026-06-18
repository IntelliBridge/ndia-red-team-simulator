import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge tailwind class strings while keeping the last-wins semantics
 * tailwind-merge gives. Used by every shadcn-style component the
 * design system exports.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
