// Stand-in for the `server-only` package under vitest.
//
// Next aliases `server-only` to its own compiled module at build time, so it
// is not installed in node_modules and the test runner cannot resolve the bare
// specifier. `next build` is where the real guard runs: it fails when a client
// module reaches a file that imports it (KTD2).
//
// That build job is skipped whenever the unit lane is red, so under vitest
// alone the guard proves nothing. server-boundary.test.ts is the check that
// runs here instead: a client-reachable module may name src/server only
// through a top-level type import.
export {};
