/* Pictograme SVG inline (stroke: currentColor) — fără dependență de fonturi
   emoji, care lipsesc pe unele Android-uri și în Chromium headless. */

function Icon(props: { children: React.ReactNode; size?: number }) {
  return (
    <svg
      width={props.size ?? 16}
      height={props.size ?? 16}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {props.children}
    </svg>
  )
}

/* Design system 3.5.7: fiecare pictogramă primeşte `size` (implicit 16, unele 12/14 istoric);
   aceeaşi linie (stroke 2, capete rotunde) — ele înlocuiesc emoji-urile/glifele Unicode folosite
   ca pictograme (🔌 🩺 👁 ⚠ ✕ ✓ ☰ ⛶ ⌨ …), care arătau diferit pe fiecare OS. */
type IconProps = { size?: number }

export const StarIcon = ({ size = 14, filled = false }: { size?: number; filled?: boolean }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={filled ? 'currentColor' : 'none'} stroke="currentColor"
       strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1Z" />
  </svg>
)

export const MenuIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M4 6h16M4 12h16M4 18h16" />
  </Icon>
)

export const CheckIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M20 6 9 17l-5-5" />
  </Icon>
)

export const WarningIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
    <path d="M12 9v4M12 17h.01" />
  </Icon>
)

export const InfoIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 16v-4M12 8h.01" />
  </Icon>
)

// consolă serială: ştecher
export const PlugIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M9 2v6M15 2v6" />
    <path d="M6 8h12v3a6 6 0 0 1-12 0Z" />
    <path d="M12 17v5" />
  </Icon>
)

// diagnostic: stetoscop
export const StethoscopeIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M5 3H4a1 1 0 0 0-1 1v5a5 5 0 0 0 10 0V4a1 1 0 0 0-1-1h-1" />
    <path d="M8 14v1a6 6 0 0 0 12 0v-2" />
    <circle cx="20" cy="11" r="2" />
  </Icon>
)

export const BellIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
    <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
  </Icon>
)

export const BellOffIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M8.7 3A6 6 0 0 1 18 8a21.3 21.3 0 0 0 .6 5M17 17H3s3-2 3-9a4.67 4.67 0 0 1 .3-1.7" />
    <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0M2 2l20 20" />
  </Icon>
)

export const ArrowUpIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 19V5M5 12l7-7 7 7" />
  </Icon>
)

export const ArrowDownIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 5v14M19 12l-7 7-7-7" />
  </Icon>
)

export const ArrowLeftIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M19 12H5M12 19l-7-7 7-7" />
  </Icon>
)

export const ArrowRightIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="M5 12h14M12 5l7 7-7 7" />
  </Icon>
)

export const ArrowUpRightIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M7 17 17 7M7 7h10v10" />
  </Icon>
)

// „sus un nivel" (↰)
export const LevelUpIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M9 14 4 9l5-5" />
    <path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11" />
  </Icon>
)

// ţintă cuibărită sub un host (↳)
export const SubItemIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M6 4v8a3 3 0 0 0 3 3h11" />
    <path d="m16 11 4 4-4 4" />
  </Icon>
)

export const ArrowsUpDownIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="M7 4v16M3 8l4-4 4 4M17 20V4M13 16l4 4 4-4" />
  </Icon>
)

export const ArrowsLeftRightIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M4 8h16M16 4l4 4-4 4M20 16H4M8 20l-4-4 4-4" />
  </Icon>
)

export const ChevronDownIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="m6 9 6 6 6-6" />
  </Icon>
)

export const ChevronUpIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="m18 15-6-6-6 6" />
  </Icon>
)

export const PlayIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" strokeWidth="2"
       strokeLinejoin="round" aria-hidden="true">
    <path d="M7 4.5v15l12-7.5Z" />
  </svg>
)

export const PauseIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <rect x="6" y="4.5" width="4" height="15" rx="1" />
    <rect x="14" y="4.5" width="4" height="15" rx="1" />
  </svg>
)

export const SquareIcon = ({ size = 12 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <rect x="5" y="5" width="14" height="14" rx="2" />
  </svg>
)

export const KeyboardIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <rect x="2" y="5" width="20" height="14" rx="2" />
    <path d="M6 9h.01M10 9h.01M14 9h.01M18 9h.01M6 13h.01M18 13h.01M10 13h4M7 16h10" />
  </Icon>
)

export const FullscreenIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3" />
  </Icon>
)

// închide split-ul: panoul „se strânge" spre margine (⇤)
export const CollapseLeftIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M4 4v16" />
    <path d="M20 12H8M13 7l-5 5 5 5" />
  </Icon>
)

// ora din bara de stare (ceas simplu; ClockIcon e „istoric" — ceas cu săgeată înapoi)
export const TimeIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Icon>
)

export const FilePlusIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
    <path d="M14 3v5h5M12 11v6M9 14h6" />
  </Icon>
)

export const DotIcon = ({ size = 8 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 8 8" fill="currentColor" aria-hidden="true">
    <circle cx="4" cy="4" r="4" />
  </svg>
)

export const BanIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="9" />
    <path d="m5.6 5.6 12.8 12.8" />
  </Icon>
)

export const DiamondIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 2.5 21.5 12 12 21.5 2.5 12Z" />
  </Icon>
)

// schemă de culori a hostului (◧)
export const PaletteIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <path d="M12 3v18" />
    <path d="M3 3h9v18H3Z" fill="currentColor" stroke="none" opacity="0.35" />
  </Icon>
)

// „rulează" (⏎): Enter
export const EnterIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M9 10l-5 5 5 5" />
    <path d="M20 4v7a4 4 0 0 1-4 4H4" />
  </Icon>
)

export const LockIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="4" y="11" width="16" height="10" rx="2" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </Icon>
)

export const MinusIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M5 12h14" />
  </Icon>
)

// AI tools (✦)
export const SparkleIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 3c.6 4.2 2.8 6.4 7 7-4.2.6-6.4 2.8-7 7-.6-4.2-2.8-6.4-7-7 4.2-.6 6.4-2.8 7-7Z" />
  </Icon>
)

export const HourglassIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M6 2h12M6 22h12M7 2v4l5 6-5 6v4M17 2v4l-5 6 5 6v4" />
  </Icon>
)

export const ArrowUpCircleIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 16V8M8 12l4-4 4 4" />
  </Icon>
)

export const CheckCircleIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="9" />
    <path d="m8 12 3 3 5-6" />
  </Icon>
)

export const NoteIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" />
  </Icon>
)

export const PencilIcon = ({ size = 12 }: { size?: number }) => (
  <Icon size={size}>
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" />
  </Icon>
)

export const SearchIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="11" cy="11" r="7" />
    <path d="m21 21-4.3-4.3" />
  </Icon>
)

export const CopyIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="9" y="9" width="12" height="12" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
  </Icon>
)

export const PasteIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="6" y="4" width="12" height="17" rx="2" />
    <path d="M9 4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2" />
  </Icon>
)

export const StopIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="9" />
    <rect x="9" y="9" width="6" height="6" fill="currentColor" stroke="none" />
  </Icon>
)

/* „Partajează" (trei noduri legate): distinct de LinkIcon, pe care meniul ⋯ îl folosea şi
   pentru „Linkuri" şi pentru „Link de partajare" — două acţiuni diferite, aceeaşi pictogramă. */
export const ShareIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="18" cy="5" r="3" />
    <circle cx="6" cy="12" r="3" />
    <circle cx="18" cy="19" r="3" />
    <path d="m8.6 13.5 6.8 4M15.4 6.5l-6.8 4" />
  </Icon>
)

export const TrashIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M3 6h18" />
    <path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" />
    <path d="M6 6v14a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V6" />
  </Icon>
)

export const ServerIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="3" y="4" width="18" height="7" rx="1.5" />
    <rect x="3" y="13" width="18" height="7" rx="1.5" />
    <path d="M7 7.5h.01M7 16.5h.01" />
  </Icon>
)

export const ActivityIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M3 12h4l2 6 4-13 2 7h6" />
  </Icon>
)

export const GearIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
  </Icon>
)

export const PowerIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 2v10" />
    <path d="M18.4 6.6a9 9 0 1 1-12.77.04" />
  </Icon>
)

export const KeyIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="m11 12 9-9m-3 3 3 3m-6 0 2 2" />
  </Icon>
)

export const ShieldIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 3 5 6v5c0 4.6 3 7.6 7 9 4-1.4 7-4.4 7-9V6l-7-3Z" />
    <path d="m9 12 2.2 2.2L15 10" />
  </Icon>
)

export const EyeIcon = ({ size = 12 }: IconProps) => (
  <Icon size={size}>
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
    <circle cx="12" cy="12" r="3" />
  </Icon>
)

export const DownloadIcon = ({ size = 14 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 3v12m0 0 4-4m-4 4-4-4" />
    <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
  </Icon>
)

export const UploadIcon = ({ size = 14 }: { size?: number }) => (
  <Icon size={size}>
    <path d="M12 15V3m0 0 4 4m-4-4-4 4" />
    <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
  </Icon>
)

/** chevron de pliere/depliere; `open` îl roteşte în jos */
export const ChevronIcon = ({ open = false, size = 14 }: { open?: boolean; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
       strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"
       style={{ transform: open ? 'rotate(90deg)' : undefined, transition: 'transform 150ms' }}>
    <path d="m9 6 6 6-6 6" />
  </svg>
)

export const FolderIcon = ({ size = 16 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" aria-hidden="true">
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
  </svg>
)

export const FileIcon = ({ size = 16 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" aria-hidden="true">
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
    <path d="M14 3v5h5" />
  </svg>
)

// Marca „Flota": promptul se deschide spre trei noduri = hosturile din flotă.
export const LogoMark = ({ size = 22 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
    <rect x="2" y="2" width="20" height="20" rx="5.6" fill="url(#wt-g)" />
    <path d="M4.5 6.4 9.4 12 4.5 17.6" fill="none" stroke="#fff" strokeWidth="2.4"
      strokeLinecap="round" strokeLinejoin="round" />
    <path d="M9.4 12 14.6 7.1M9.4 12 18.4 12M9.4 12 14.6 16.9" fill="none" stroke="#fff"
      strokeWidth="1.35" strokeLinecap="round" opacity="0.6" />
    <circle cx="14.6" cy="7.1" r="2.1" fill="#fff" />
    <circle cx="18.4" cy="12" r="2.1" fill="#fff" />
    <circle cx="14.6" cy="16.9" r="2.1" fill="#fff" />
    <defs>
      <linearGradient id="wt-g" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse">
        <stop stopColor="#6366f1" />
        <stop offset="0.55" stopColor="#4f46e5" />
        <stop offset="1" stopColor="#7c3aed" />
      </linearGradient>
    </defs>
  </svg>
)

export const FilesIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
    <path d="M13 3v5h5" />
  </Icon>
)

export const ForwardIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M4 8h12l-3-3M20 16H8l3 3" />
  </Icon>
)

// balena Docker, stilizată: rânduri de containere + „valul" de deasupra
export const DockerIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="3" y="11" width="3" height="3" />
    <rect x="7" y="11" width="3" height="3" />
    <rect x="11" y="11" width="3" height="3" />
    <rect x="11" y="7" width="3" height="3" />
    <path d="M2 14c1.5 1 4 1.5 7 1.5 5 0 8-2.2 8.5-4.5.8.6 1.4 1.6 1.5 3 1-.3 1.7-.3 2 0" />
  </Icon>
)

// toolbox: conexiuni DB — o cheie fixă
export const ToolboxIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M14.7 6.3a3.5 3.5 0 0 1-4.6 4.6l-5 5a1.6 1.6 0 0 1-2.3-2.3l5-5a3.5 3.5 0 0 1 4.6-4.6L10 6l1.4 1.4 3.3-1.1z" />
  </Icon>
)

// servicii systemd: un cog (roată dinţată)
export const ServicesIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="10" cy="10" r="2.6" />
    <path d="M10 2.2v2.2M10 15.6v2.2M2.2 10h2.2M15.6 10h2.2M4.5 4.5l1.6 1.6M13.9 13.9l1.6 1.6M15.5 4.5l-1.6 1.6M6.1 13.9l-1.6 1.6" />
  </Icon>
)

export const GitBranchIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <line x1="6" y1="3" x2="6" y2="15" />
    <circle cx="18" cy="6" r="3" />
    <circle cx="6" cy="18" r="3" />
    <path d="M18 9a9 9 0 0 1-9 9" />
  </Icon>
)

export const FolderMoveIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
    <path d="M9 13h6m0 0-2-2m2 2-2 2" />
  </Icon>
)

export const RefreshIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M21 12a9 9 0 1 1-2.64-6.36M21 4v5h-5" />
  </Icon>
)

export const CloseIcon = ({ size = 16 }: { size?: number }) => (
  <Icon size={size}>
    <path d="M18 6 6 18M6 6l12 12" />
  </Icon>
)

export const PlusIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M12 5v14M5 12h14" />
  </Icon>
)

export const HomeIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M3 11l9-8 9 8" />
    <path d="M5 10v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V10" />
  </Icon>
)

export const CollapseIcon = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor"
       strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <rect x="1.5" y="2.5" width="13" height="11" rx="2" />
    <path d="M6 2.5v11" />
    <path d="M11.5 6.5 9.5 8l2 1.5" />
  </svg>
)

export const MoreIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <circle cx="5" cy="12" r="1.4" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
    <circle cx="19" cy="12" r="1.4" fill="currentColor" stroke="none" />
  </Icon>
)

export const TerminalPromptIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M5 8l3 3-3 3M11 14h5" />
  </Icon>
)

export const PopoutIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <path d="M14 4h6v6" />
    <path d="M20 4 10 14" />
    <path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" />
  </Icon>
)

export const SplitIcon = ({ size = 16 }: IconProps) => (
  <Icon size={size}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M12 4v16" />
  </Icon>
)

export const LinkIcon = ({ size = 16 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" />
    <path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" />
  </svg>
)

// history de clipboard (ceas cu săgeată înapoi) — paste picker
export const ClockIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M3 3v5h5" />
    <path d="M3.05 13a9 9 0 1 0 2.6-6.4L3 8" />
    <path d="M12 7v5l3 2" />
  </svg>
)

// distinct de LinkIcon (chain, folosit la Share): „deschide linkuri din terminal"
export const ExternalLinkIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M15 3h6v6" />
    <path d="M10 14 21 3" />
    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
  </svg>
)

// „Redenumeşte": casetă de nume cu cursor de text (I-beam) — distinct de PencilIcon,
// care rămâne „editează conţinutul"
export const RenameIcon = ({ size = 12 }: { size?: number }) => (
  <Icon size={size}>
    <path d="M14 7H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h10" />
    <path d="M20 7a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2" />
    <path d="M17 4v16" />
    <path d="M15 4h4" />
    <path d="M15 20h4" />
  </Icon>
)

// scut mic pentru rândul de host care cere 2FA (ShieldIcon are dimensiunea fixă de 16)
export const ShieldSmallIcon = ({ size = 12 }: { size?: number }) => (
  <Icon size={size}>
    <path d="M12 3 5 6v5c0 4.6 3 7.6 7 9 4-1.4 7-4.4 7-9V6l-7-3Z" />
  </Icon>
)
