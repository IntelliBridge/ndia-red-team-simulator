import { describe, it, expect } from "vitest"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join } from "node:path"
import * as fixtures from "./fixtures"

/**
 * Banned as status, badge, grade, or generated text anywhere in the UI.
 * [spec §14.7, §15.8 (iii), §2]
 */
const BANNED = [
  "hardened",
  "harden before fielding",
  "deployment-ready",
  "not deployment-ready",
  "certified",
  "fielding",
]

// "safe" is banned as a standalone word (not "safetensors" / "safety, readiness")
const BANNED_WORD_BOUNDARY = ["safe"]

function walk(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".next") continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, acc)
    else if (/\.(tsx?|json)$/.test(entry) && !full.includes("banned-words.test")) acc.push(full)
  }
  return acc
}

describe("banned words", () => {
  it("no banned phrases in fixtures", () => {
    const blob = JSON.stringify(fixtures).toLowerCase()
    for (const w of BANNED) expect(blob, `fixture contains "${w}"`).not.toContain(w)
  })

  it("no banned phrases in rendered UI source", () => {
    const files = walk(join(process.cwd(), "src"))
    for (const f of files) {
      const src = readFileSync(f, "utf8").toLowerCase()
      for (const w of BANNED) {
        // Allow the exact spec footer disclosure which legitimately contains "safety, readiness".
        expect(src.includes(w), `${f} contains banned "${w}"`).toBe(false)
      }
      for (const w of BANNED_WORD_BOUNDARY) {
        const re = new RegExp(`\\b${w}\\b`, "g")
        // Exclude comment lines that discuss the ban itself and the footer disclosure.
        const offending = src
          .split("\n")
          .filter((line) => re.test(line))
          .filter((line) => !line.includes("banned") && !line.includes("not a safety") && !line.includes("safety, readiness"))
        expect(offending, `${f} uses standalone "${w}"`).toHaveLength(0)
      }
    }
  })
})
