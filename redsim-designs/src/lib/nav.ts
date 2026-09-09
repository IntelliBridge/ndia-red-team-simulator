import {
  LayoutDashboard,
  PlayCircle,
  Boxes,
  ScanSearch,
  FolderKanban,
  ShieldCheck,
  ScrollText,
  DollarSign,
  KeyRound,
  type LucideIcon,
} from "lucide-react"

export interface NavItem {
  href: string
  label: string
  icon: LucideIcon
}

/** Nav order is fixed by spec §18.1 and shared with the ⌘K palette. */
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
]
