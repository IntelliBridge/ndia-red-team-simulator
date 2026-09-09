// The six sidebar icons, one per NAV entry, as inline SVG so the shell adds
// no icon dependency to the workspace. 24-unit grid, 2px round strokes in
// currentColor, so each one takes the colour of the link it sits in.
//
// Decorative: every icon sits beside its label, so it is hidden from the
// accessibility tree and the label alone is read.

import type { SVGProps } from "react";

export type NavIcon = (props: SVGProps<SVGSVGElement>) => JSX.Element;

function Icon({ children, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  );
}

export const DashboardIcon: NavIcon = (props) => (
  <Icon {...props}>
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" />
  </Icon>
);

export const ModelsIcon: NavIcon = (props) => (
  <Icon {...props}>
    <path d="M12 2.5 20.5 7v10L12 21.5 3.5 17V7z" />
    <path d="M3.5 7 12 11.5 20.5 7" />
    <path d="M12 11.5v10" />
  </Icon>
);

export const RunsIcon: NavIcon = (props) => (
  <Icon {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="m10 8.5 5.5 3.5-5.5 3.5z" />
  </Icon>
);

export const TestsIcon: NavIcon = (props) => (
  <Icon {...props}>
    <path d="M9 3h6" />
    <path d="M10 3v6.5L4.7 18.5A1.5 1.5 0 0 0 6 21h12a1.5 1.5 0 0 0 1.3-2.5L14 9.5V3" />
    <path d="M7.5 15h9" />
  </Icon>
);

export const FindingsIcon: NavIcon = (props) => (
  <Icon {...props}>
    <circle cx="11" cy="11" r="6.5" />
    <path d="m20 20-4.4-4.4" />
  </Icon>
);

export const AuditIcon: NavIcon = (props) => (
  <Icon {...props}>
    <path d="M12 2.5 19.5 5.5v6c0 4.5-3.2 8-7.5 10-4.3-2-7.5-5.5-7.5-10v-6z" />
    <path d="m9 12 2 2 4-4" />
  </Icon>
);
