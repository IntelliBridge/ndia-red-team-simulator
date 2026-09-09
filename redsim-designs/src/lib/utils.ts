import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max)
}

export function formatDateTime(iso: string | number | undefined | null) {
  if (iso == null) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return "—"
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export function relativeTime(iso: string | number | undefined | null) {
  if (iso == null) return "—"
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return "—"
  const diff = Math.round((then - Date.now()) / 1000)
  const abs = Math.abs(diff)
  const rtf = new Intl.RelativeTimeFormat("en-US", { numeric: "auto" })
  if (abs < 60) return rtf.format(Math.round(diff), "second")
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute")
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour")
  return rtf.format(Math.round(diff / 86400), "day")
}

/** Short sha256 for display (first 12 hex chars). */
export function shortSha(sha: string | undefined | null) {
  if (!sha) return "—"
  const clean = sha.replace(/^sha256:/, "")
  return clean.slice(0, 12)
}

/** Accuracy / count rendered as "k / n (pct)". A family with n=0 must NOT call this. [spec §18.3 panel 4] */
export function fraction(k: number, n: number): string {
  if (n <= 0) return "no evidence recorded"
  const pct = ((k / n) * 100).toFixed(1)
  return `${k} / ${n} (${pct}%)`
}

/** ASR rendered as flipped / clean-correct. [spec §18.3 panel 4] */
export function asr(flipped: number, cleanCorrect: number): string {
  if (cleanCorrect <= 0) return "no evidence recorded"
  return `${flipped} / ${cleanCorrect}`
}
