// /exports — every report and adversarial dataset a run has produced, and
// what can still be produced, across the caller's projects.
//
// The same shape as /runs: a server component prefetches the one inventory
// query, awaits it, and hands the hydrated cache to a client leaf, so the
// first HTML already carries the rows or the honest error state.

import { HydrateClient, prefetch, trpcServer } from "@/server/trpc/server";
import {
  pageSearchParam,
  pageSearchParamInt,
  type RawSearchParams,
} from "@/lib/page-search-params";

import { ExportsTable } from "./exports-table";
import { FoundryPanel } from "./foundry-panel";

export default async function ExportsPage({
  searchParams,
}: {
  searchParams?: RawSearchParams;
}) {
  const project = pageSearchParam(searchParams, "project");
  const limit = pageSearchParamInt(searchParams, "limit");

  await prefetch(trpcServer.exports.list.queryOptions({ project, limit }));
  // The Foundry panel needs a project; without `?project=` the client leaf
  // picks one from the caller's memberships and fetches on its own.
  if (project) {
    await prefetch(trpcServer.exports.foundrySettings.queryOptions({ project }));
  }

  return (
    <HydrateClient>
      <div className="space-y-6">
        <header>
          <div className="redsim-kicker">evidence out</div>
          <h1 className="text-2xl font-semibold">Exports</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Reports in Markdown, JSON, HTML and PDF, the Croissant over
            Parquet adversarial dataset of each finished campaign, and the
            scorecard push to a configured Palantir Foundry dataset.
            Downloads and new exports are gated by the API per project
            role. Nothing here is a score.
          </p>
        </header>
        <FoundryPanel project={project} />
        <ExportsTable project={project} limit={limit} />
      </div>
    </HydrateClient>
  );
}
