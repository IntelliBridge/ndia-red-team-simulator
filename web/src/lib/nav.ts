import {
  Boxes,
  DollarSign,
  FolderKanban,
  KeyRound,
  LayoutDashboard,
  PlayCircle,
  ScanSearch,
  ScrollText,
  ShieldCheck,
  type LucideIcon,
} from "@redsim/design-system";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

/**
 * The primary navigation, in the order spec section 18.1 fixes.
 *
 * The sidebar and the command palette read this one list, so the palette can
 * never offer a destination the sidebar omits.
 */
export const NAV: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/runs", label: "Runs", icon: PlayCircle },
  { href: "/models", label: "Models", icon: Boxes },
  { href: "/findings", label: "Findings", icon: ScanSearch },
  { href: "/projects", label: "Projects", icon: FolderKanban },
  { href: "/audit", label: "Audit", icon: ShieldCheck },
  { href: "/logs", label: "Logs", icon: ScrollText },
  { href: "/cost", label: "Cost", icon: DollarSign },
  { href: "/auth-profiles", label: "Auth Profiles", icon: KeyRound },
];
