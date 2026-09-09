import { beforeEach, vi } from "vitest";

// src/env.js validates on first import, and src/lib/api.ts reaches nearly
// every page test, so the two required server names need real-shaped values
// here. SKIP_ENV_VALIDATION would work too and is the wrong tool: it returns
// the raw environment, stripping every schema default out from under the
// assertions these suites already make.
process.env.BETTER_AUTH_SECRET ??=
  "test-not-a-real-secret-change-me-0123456789";
process.env.BETTER_AUTH_URL ??= "http://localhost:3000";

// Node 25 ships an experimental global `localStorage` that shadows jsdom's and
// throws without `--localstorage-file`. Replace it with a deterministic
// in-memory Storage before every test so the browser-side auth client
// (src/lib/api.ts, src/lib/auth.ts) reads/writes a clean slate.
class MemoryStorage implements Storage {
  private store = new Map<string, string>();
  get length(): number {
    return this.store.size;
  }
  clear(): void {
    this.store.clear();
  }
  getItem(key: string): string | null {
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }
  setItem(key: string, value: string): void {
    this.store.set(key, String(value));
  }
  removeItem(key: string): void {
    this.store.delete(key);
  }
  key(index: number): string | null {
    return [...this.store.keys()][index] ?? null;
  }
}

beforeEach(() => {
  vi.stubGlobal("localStorage", new MemoryStorage());
});
