/**
 * The batch cap, shared by the fetch adapter and the browser link.
 *
 * It lives here rather than beside either caller because a Next route file may
 * only export the fields Next recognises, and because the two sides have to
 * agree: the adapter takes it as `maxBatchSize` and refuses a larger batch with
 * a 400, the link takes it as `maxItems` and splits before it gets there. One
 * credential-bearing request therefore amplifies into at most this many
 * upstream calls (KTD2).
 */
export const MAX_BATCH_ITEMS = 20;
