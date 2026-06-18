import { beforeEach, vi } from "vitest";

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
