/**
 * A timestamp the server and the client format identically.
 *
 * `toLocaleString()` with no arguments reads the host locale and time zone, so
 * the server HTML and the first client render disagree and React replaces the
 * cell. Pinning both to UTC and en-US, with the zone visible so nobody reads
 * it as local time, is what makes the hydrated markup stable.
 */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "not recorded";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "not recorded";
  return `${parsed.toLocaleString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })} UTC`;
}

/** Bytes as a short human figure, base 1024, one decimal above the unit. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "not recorded";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}
