/**
 * The icon set the redsim UI draws from.
 *
 * A single re-export barrel rather than a direct `lucide-react` import at
 * every call site, so `@redsim/web` can render the shell without declaring
 * the icon package itself: the dependency stays where the components live.
 * Add an icon here before using it.
 */
export {
  AlertTriangle,
  Boxes,
  Check,
  ChevronDown,
  ChevronRight,
  Circle,
  Command as CommandIcon,
  DollarSign,
  Download,
  ExternalLink,
  FolderKanban,
  GitCompare,
  ImageOff,
  Inbox,
  KeyRound,
  LayoutDashboard,
  Loader2,
  Lock,
  Moon,
  PlayCircle,
  Plus,
  RefreshCw,
  Rocket,
  RotateCcw,
  ScanSearch,
  ScrollText,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Wand2,
  Wrench,
  X,
  type LucideIcon,
} from "lucide-react";
