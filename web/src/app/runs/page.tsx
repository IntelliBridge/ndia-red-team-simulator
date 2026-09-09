// /runs — the reference page for the ported data layer.
//
// A server component that prefetches its one query into the request's
// QueryClient, awaits it, and hands the hydrated cache to a client leaf. The
// first HTML therefore already carries the rows (or the honest state for the
// error), and nothing flashes on hydration.

import { HydrateClient, prefetch, trpcServer } from "@/server/trpc/server";
import {
  pageSearchParam,
  pageSearchParamInt,
  type RawSearchParams,
} from "@/lib/page-search-params";

import { RunsTable } from "./runs-table";

export default async function RunsPage({
  searchParams,
}: {
  searchParams?: RawSearchParams;
}) {
  const project = pageSearchParam(searchParams, "project");
  const limit = pageSearchParamInt(searchParams, "limit");

  await prefetch(trpcServer.runs.list.queryOptions({ project, limit }));

  return (
    <HydrateClient>
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold">Runs</h1>
        <RunsTable project={project} limit={limit} />
      </div>
    </HydrateClient>
  );
}
