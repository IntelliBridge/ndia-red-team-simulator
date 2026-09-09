// The one navigation list. The sidebar, the compact nav row below the md
// breakpoint and the command palette all read it, so a route is added or
// hidden in exactly one place.
//
// The six entries and their order mirror the header nav the app shipped
// before the sidebar shell. Projects, Auth Profiles, Logs and Cost stay off
// the list by owner request (2026-09-09): their pages remain reachable by
// URL. A route whose page does not exist yet gets no entry. The change that
// ships the page adds its entry, so the sidebar never shows a dead link.

import {
  AuditIcon,
  DashboardIcon,
  FindingsIcon,
  ModelsIcon,
  type NavIcon,
  RunsIcon,
  TestsIcon,
} from "./nav-icons";

export interface NavItem {
  href: string;
  label: string;
  icon: NavIcon;
}

export const NAV: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: DashboardIcon },
  { href: "/models", label: "Models", icon: ModelsIcon },
  { href: "/runs", label: "Runs", icon: RunsIcon },
  { href: "/tests", label: "Tests", icon: TestsIcon },
  { href: "/findings", label: "Findings", icon: FindingsIcon },
  { href: "/audit", label: "Audit", icon: AuditIcon },
];

/**
 * The same list without the icons, for a client component rendered by a
 * server component: a function cannot cross that boundary as a prop, and the
 * palette and the compact nav row need only the route and its label.
 */
export const NAV_LINKS: { href: string; label: string }[] = NAV.map(
  ({ href, label }) => ({ href, label }),
);

/** Whether `pathname` is `href` itself or a page beneath it. */
export function isCurrentRoute(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}
