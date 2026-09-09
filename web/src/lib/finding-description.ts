/**
 * Break a finding description into labelled sections for the UI.
 *
 * `redsim.services.ml_findings` writes one paragraph per aspect, each opening
 * with a fixed marker ("What happened:", "Measured:", "At the reference
 * budget", ...). The API stores them as one string; this splits that string
 * back into sections so each renders as its own box instead of a wall of
 * text separated by colons. Unknown text stays in a "Details" section, so
 * nothing is lost.
 */
export type DescriptionSection = { key: string; heading: string; text: string; plain: boolean };

const MARKERS: { key: string; heading: string; plain: boolean; starts: RegExp }[] = [
  { key: "what", heading: "What happened", plain: true, starts: /^What happened:\s*/ },
  { key: "measured", heading: "Measured result", plain: false, starts: /^Measured:\s*/ },
  { key: "reference", heading: "At the reference budget", plain: false, starts: /^At the reference budget\s*/ },
  { key: "clean", heading: "Clean accuracy", plain: false, starts: /^Clean accuracy\s*/ },
  { key: "control", heading: "Noise control", plain: false, starts: /^Benign noise control\s*/ },
  { key: "slice", heading: "Test slice and confidence", plain: false, starts: /^Slice:\s*/ },
  { key: "unevaluated", heading: "Not evaluated", plain: false, starts: /^\d+ response\(s\) could not be evaluated/ },
  { key: "severity", heading: "How severity was set", plain: false, starts: /^Severity\s/ },
  { key: "target", heading: "Target and settings", plain: false, starts: /^Target:\s*/ },
  { key: "evidence", heading: "Evidence", plain: false, starts: /^Prompts and responses\s/ },
];

// Sentence boundary before a known marker. Markers always follow ". " in the
// generated text, so splitting there keeps every sentence whole.
const SPLIT = new RegExp(
  `(?<=\\.)\\s+(?=(?:${MARKERS.map((m) => m.starts.source.replace(/^\^/, "").replace(/\\s\*$/, "")).join("|")}))`,
);

export function describeFinding(description: string | null | undefined): DescriptionSection[] {
  if (!description || !description.trim()) return [];
  const chunks = description.trim().split(SPLIT).map((c) => c.trim()).filter(Boolean);
  const sections: DescriptionSection[] = [];
  for (const chunk of chunks) {
    const marker = MARKERS.find((m) => m.starts.test(chunk));
    if (marker) {
      const text = marker.key === "unevaluated" || marker.key === "severity" ? chunk : chunk.replace(marker.starts, "");
      sections.push({ key: marker.key, heading: marker.heading, text, plain: marker.plain });
    } else if (sections.length && !sections[sections.length - 1]!.plain) {
      // A continuation sentence belongs to the section before it.
      sections[sections.length - 1]!.text += ` ${chunk}`;
    } else {
      sections.push({ key: "details", heading: "Details", text: chunk, plain: false });
    }
  }
  return sections;
}

/** The plain-language lead alone, for lists; null when the description has none. */
export function findingLead(description: string | null | undefined, max = 240): string | null {
  const what = describeFinding(description).find((s) => s.key === "what");
  if (!what) return null;
  return what.text.length > max ? `${what.text.slice(0, max - 3).trimEnd()}...` : what.text;
}
