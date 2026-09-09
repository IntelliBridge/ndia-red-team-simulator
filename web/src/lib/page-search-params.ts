/**
 * Normalize a Next 14 `searchParams` prop.
 *
 * A page passes only route ids and search params down to its client leaves
 * (R7), and this is the one site that reads the raw prop. Next 15 makes
 * `searchParams` a promise. That change lands here and nowhere else.
 */
export type RawSearchParams = Record<string, string | string[] | undefined>;

/** The first value for a name, ignoring repeats and empty strings. */
export function pageSearchParam(
  params: RawSearchParams | undefined,
  name: string,
): string | undefined {
  const value = params?.[name];
  const first = Array.isArray(value) ? value[0] : value;
  return first === undefined || first === "" ? undefined : first;
}

/** The same, parsed as a positive integer, or undefined when it is not one. */
export function pageSearchParamInt(
  params: RawSearchParams | undefined,
  name: string,
): number | undefined {
  const raw = pageSearchParam(params, name);
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}
