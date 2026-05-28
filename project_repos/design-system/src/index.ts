// Public surface of @aegis/design-system.
//
// Components listed here must have an accompanying Storybook story
// (per the v0.4.0 F16 incremental gate — the CI gate flips on after
// the first batch lands).

export { AuditChainBadge, type AuditChainBadgeProps, type ChainVerifyState }
  from "./components/audit-chain-badge";
export { EvidenceDiff, type EvidenceDiffProps }
  from "./components/evidence-diff";
export { FindingCard, type FindingCardProps }
  from "./components/finding-card";
export { RoleGated, type RoleGatedProps }
  from "./components/role-gated";
export { RunStatusBadge, type RunStatusBadgeProps, type RunStatus }
  from "./components/run-status-badge";
export { SeverityChip, type SeverityChipProps, type Severity }
  from "./components/severity-chip";
export { StageTimeline, type StageEntry, type StageTimelineProps }
  from "./components/stage-timeline";
export { ToastList, type Toast, type ToastListProps, type ToastTone }
  from "./components/toast-list";

export { cn } from "./lib/utils";
