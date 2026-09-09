import { DEV_FIXTURES } from "@/lib/env"
import { LabelBadge } from "@/ui/atoms/label-badge"

/**
 * Persistent ribbon painted on every page while the dev-fixtures deviation is
 * active, and on every Storybook story. Never shown against the real API.
 * [spec §6, §18.5]
 */
export function FixtureRibbon({ force = false }: { force?: boolean }) {
  if (!DEV_FIXTURES && !force) return null
  return (
    <div className="stripe-warning flex items-center justify-center gap-2 border-b border-illustrative/40 px-4 py-1 text-center text-[11px] text-illustrative">
      <LabelBadge variant="illustrative">FIXTURE</LabelBadge>
      <span>
        Illustrative fixture data (NEXT_PUBLIC_REDSIM_DEV_FIXTURES). Not a live measurement against the API.
      </span>
    </div>
  )
}
