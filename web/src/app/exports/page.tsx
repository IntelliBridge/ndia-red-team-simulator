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

import { ExportsTable, type ExportKind } from "./exports-table";

function kindParam(raw: string | undefined): ExportKind | undefined {
  return raw === "campaign" || raw === "verify" ? raw : undefined;
}

export default async function ExportsPage({
  searchParams,
}: {
  searchParams?: RawSearchParams;
}) {
  const project = pageSearchParam(searchParams, "project");
  const kind = kindParam(pageSearchParam(searchParams, "kind"));
  const limit = pageSearchParamInt(searchParams, "limit");

  await prefetch(trpcServer.exports.list.queryOptions({ project, kind, limit }));

  return (
    <HydrateClient>
      <div className="space-y-6">
        <header>
          <div className="redsim-kicker">evidence out</div>
          <h1 className="text-2xl font-semibold">Exports</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Reports in Markdown, JSON, HTML and PDF, and the Croissant over
            Parquet adversarial dataset of each finished campaign or verify
            run. Downloads and new exports are gated by the API per project
            role. Nothing here is a score.
          </p>
        </header>
        <ExportsTable project={project} kind={kind} limit={limit} />
      </div>
    </HydrateClient>
  );
}
