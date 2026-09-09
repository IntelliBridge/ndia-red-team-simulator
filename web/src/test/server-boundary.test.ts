// @vitest-environment node
//
// The bundle boundary, checked statically.
//
// `server-only` is the mechanical guard that keeps the server router out of
// the browser bundle, and vitest aliases it to a no-op (see
// server-only-stub.ts), so under the unit lane it proves nothing. The real
// enforcement is the `next build` job, which this repo's CI skips whenever the
// unit lane is red. That leaves the window this file closes: the guard can be
// broken and every gate still green.
//
// The rule it enforces is the one KTD2 already states. A client-reachable
// module may name a module under src/server only through a top-level
// `import type` or `export type ... from`. An inline `{ type X }` specifier
// fails too, and deliberately: verbatimModuleSyntax erases the top-level form
// entirely but leaves the side-effect import behind for the inline one, which
// is what pulls the server module into the browser bundle.

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const SRC = path.resolve(__dirname, "..");
const SERVER_DIR = path.join(SRC, "server");

/**
 * Directories whose modules are reachable from the browser bundle.
 *
 * A file carrying "use client" is included wherever it lives. These three are
 * included whole because a server component may import any of them, and from
 * there a client leaf may too, so a value import of a server module inside one
 * is a bundle risk even with no directive in the file itself.
 */
const CLIENT_REACHABLE_DIRS = ["lib", "components", "hooks"].map((d) => path.join(SRC, d));

/** Extensions worth reading. */
const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs"]);

/**
 * Files that never reach a bundle: the test tree and every test or story.
 *
 * src/test holds the harnesses, and mock-upstream.ts imports the upstream
 * module's status maps on purpose, so a test asserts the codes the layer
 * really emits rather than a copy of them.
 */
function isExcluded(file: string): boolean {
  const relative = path.relative(SRC, file);
  return (
    relative.startsWith(`server${path.sep}`) ||
    relative.startsWith(`test${path.sep}`) ||
    /\.(test|spec|stories)\.[^.]+$/.test(relative)
  );
}

/** Every source file under a directory, recursively. */
function walk(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    const full = path.join(dir, entry);
    if (entry === "node_modules" || entry.startsWith(".")) return [];
    if (statSync(full).isDirectory()) return walk(full);
    return SOURCE_EXTENSIONS.has(path.extname(full)) ? [full] : [];
  });
}

/** The files this rule applies to, with their contents. */
function clientReachableFiles(): Array<{ file: string; source: string }> {
  return walk(SRC)
    .filter((file) => !isExcluded(file))
    .map((file) => ({ file, source: readFileSync(file, "utf8") }))
    .filter(
      ({ file, source }) =>
        /^\s*["']use client["']/m.test(source) ||
        CLIENT_REACHABLE_DIRS.some((dir) => file.startsWith(dir + path.sep)),
    );
}

/** Where a specifier lands, for any of the forms that can reach src/server. */
function resolveSpecifier(fromFile: string, specifier: string): string | null {
  if (specifier.startsWith("@/")) return path.join(SRC, specifier.slice(2));
  if (specifier.startsWith(".")) return path.resolve(path.dirname(fromFile), specifier);
  return null;
}

function namesServerModule(fromFile: string, specifier: string): boolean {
  const resolved = resolveSpecifier(fromFile, specifier);
  return resolved !== null && resolved.startsWith(SERVER_DIR + path.sep);
}

/** One reference to a module under src/server, and the form it took. */
type Reference = { file: string; specifier: string; statement: string; typeOnly: boolean };

/**
 * Every `import`/`export ... from`, dynamic `import()` and bare side-effect
 * `import "..."` naming src/server.
 *
 * A regex rather than a parser: the shapes it has to tell apart are the few
 * this rule is about, and a dependency-free check is one that keeps running.
 * Three passes rather than one, because the three shapes have nothing in
 * common syntactically. The bare side-effect form in particular has no clause
 * and no parenthesis, so neither of the first two can see it, and it is the
 * one form that is always a value import.
 */
function serverReferences(file: string, source: string): Reference[] {
  const found: Reference[] = [];

  const statements = /(?:^|[\n;])[ \t]*(import|export)\b([\s\S]*?)from\s*["']([^"']+)["']/g;
  for (const match of source.matchAll(statements)) {
    const [statement, keyword, clause = "", specifier = ""] = match;
    if (!namesServerModule(file, specifier)) continue;
    found.push({
      file,
      specifier,
      statement: `${keyword}${clause}from "${specifier}"`.replace(/\s+/g, " ").trim(),
      // The whole clause is type-only, as `import type {...}` and
      // `export type {...} from` are. An inline `{ type X }` is not.
      typeOnly: /^\s*type\s/.test(clause),
    });
  }

  // No `from` clause at all: `import "@/server/trpc/upstream";`. Nothing is
  // bound, so there is no type-only variant of it, and the module is
  // evaluated for its side effects, which is exactly what pulls it into the
  // bundle. The quote has to follow the keyword directly, so a clause-bearing
  // import and `import(` both fall outside this pattern.
  const sideEffect = /(?:^|[\n;])[ \t]*import\s*["']([^"']+)["']/g;
  for (const match of source.matchAll(sideEffect)) {
    const specifier = match[1] ?? "";
    if (!namesServerModule(file, specifier)) continue;
    found.push({
      file,
      specifier,
      statement: `import "${specifier}"`,
      typeOnly: false,
    });
  }

  const dynamic = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const match of source.matchAll(dynamic)) {
    const specifier = match[1] ?? "";
    if (!namesServerModule(file, specifier)) continue;
    found.push({
      file,
      specifier,
      statement: `import("${specifier}")`,
      // A dynamic import is a value import however it is typed.
      typeOnly: false,
    });
  }

  return found;
}

describe("the browser bundle boundary", () => {
  it("finds the client-reachable modules to check", () => {
    // Guards the walk itself: a rule that silently matches nothing is worse
    // than no rule, and this is the file that would go quiet if src moved.
    const files = clientReachableFiles();
    expect(files.length).toBeGreaterThan(10);
    expect(files.some(({ file }) => file.endsWith(path.join("lib", "trpc", "client.tsx")))).toBe(
      true,
    );
  });

  it("names src/server only through a top-level type import", () => {
    const offenders = clientReachableFiles()
      .flatMap(({ file, source }) => serverReferences(file, source))
      .filter((reference) => !reference.typeOnly)
      .map((reference) => `${path.relative(SRC, reference.file)}: ${reference.statement}`);

    // Listed rather than counted, so a failure names the import to fix.
    expect(offenders).toEqual([]);
  });

  it("reads a top-level type import as allowed and every other form as not", () => {
    // The rule's own unit test. Without it a refactor of the matcher could
    // make the check above pass by matching nothing at all.
    const file = path.join(SRC, "lib", "example.ts");
    const forms = {
      topLevelType: `import type { AppRouter } from "@/server/trpc/root";`,
      inlineType: `import { type AppRouter } from "@/server/trpc/root";`,
      value: `import { upstreamFetch } from "@/server/trpc/upstream";`,
      dynamic: `const m = await import("@/server/trpc/upstream");`,
      relativeValue: `import { appRouter } from "../server/trpc/root";`,
      sideEffect: `import "@/server/trpc/upstream";`,
      relativeSideEffect: `import "../server/trpc/upstream";`,
      exportType: `export type { AppRouter } from "@/server/trpc/root";`,
      unrelated: `import { env } from "@/env";`,
      unrelatedSideEffect: `import "@/styles/globals.css";`,
    };

    const formOf = (source: string) => serverReferences(file, source);

    expect(formOf(forms.topLevelType)).toHaveLength(1);
    expect(formOf(forms.topLevelType)[0]?.typeOnly).toBe(true);
    expect(formOf(forms.exportType)[0]?.typeOnly).toBe(true);

    for (const source of [
      forms.inlineType,
      forms.value,
      forms.dynamic,
      forms.relativeValue,
      // A bare side-effect import has no clause to inspect, so it can only
      // ever be a value import. It is also the form the other two matchers
      // cannot see: both require a `from` or a paren.
      forms.sideEffect,
      forms.relativeSideEffect,
    ]) {
      const references = formOf(source);
      expect(references).toHaveLength(1);
      expect(references[0]?.typeOnly).toBe(false);
    }

    expect(formOf(forms.unrelated)).toEqual([]);
    expect(formOf(forms.unrelatedSideEffect)).toEqual([]);
  });
});
