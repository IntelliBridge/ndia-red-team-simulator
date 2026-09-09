import { PageHeaderSkeleton, TableSkeleton } from "@/ui/molecules/skeletons"

export default function Loading() {
  return (
    <div>
      <PageHeaderSkeleton />
      <TableSkeleton />
    </div>
  )
}
