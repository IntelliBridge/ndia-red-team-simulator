// Stand-in for the `server-only` package under vitest.
//
// Next aliases `server-only` to its own compiled module at build time, so it
// is not installed in node_modules and the test runner cannot resolve the
// bare specifier. The real guard still runs where it matters: `next build`
// fails when a client module reaches a file that imports it (KTD2).
export {};
