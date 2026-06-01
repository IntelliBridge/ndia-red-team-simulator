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

// Base shadcn/ui primitives (new-york-v4), ported into src/primitives/.
// These are dependency-free leaves; prop types are React.ComponentProps
// of the underlying element, so we export each component's props as a
// named type alias for downstream consumers.
import type { ComponentProps } from "react";
import {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
} from "./primitives/table";
import {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
} from "./primitives/card";
import { Skeleton } from "./primitives/skeleton";
import {
  Alert,
  AlertTitle,
  AlertDescription,
  alertVariants,
} from "./primitives/alert";
import { Input } from "./primitives/input";
import { Textarea } from "./primitives/textarea";

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
};
export type TableProps = ComponentProps<typeof Table>;
export type TableHeaderProps = ComponentProps<typeof TableHeader>;
export type TableBodyProps = ComponentProps<typeof TableBody>;
export type TableFooterProps = ComponentProps<typeof TableFooter>;
export type TableHeadProps = ComponentProps<typeof TableHead>;
export type TableRowProps = ComponentProps<typeof TableRow>;
export type TableCellProps = ComponentProps<typeof TableCell>;
export type TableCaptionProps = ComponentProps<typeof TableCaption>;

export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
};
export type CardProps = ComponentProps<typeof Card>;
export type CardHeaderProps = ComponentProps<typeof CardHeader>;
export type CardFooterProps = ComponentProps<typeof CardFooter>;
export type CardTitleProps = ComponentProps<typeof CardTitle>;
export type CardActionProps = ComponentProps<typeof CardAction>;
export type CardDescriptionProps = ComponentProps<typeof CardDescription>;
export type CardContentProps = ComponentProps<typeof CardContent>;

export { Skeleton };
export type SkeletonProps = ComponentProps<typeof Skeleton>;

export { Alert, AlertTitle, AlertDescription, alertVariants };
export type AlertProps = ComponentProps<typeof Alert>;
export type AlertTitleProps = ComponentProps<typeof AlertTitle>;
export type AlertDescriptionProps = ComponentProps<typeof AlertDescription>;

export { Input };
export type InputProps = ComponentProps<typeof Input>;

export { Textarea };
export type TextareaProps = ComponentProps<typeof Textarea>;

export { cn } from "./lib/utils";
