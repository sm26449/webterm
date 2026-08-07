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

export const NoteIcon = () => (
  <Icon>
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

export const SearchIcon = () => (
  <Icon>
    <circle cx="11" cy="11" r="7" />
    <path d="m21 21-4.3-4.3" />
  </Icon>
)

export const CopyIcon = () => (
  <Icon>
    <rect x="9" y="9" width="12" height="12" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
  </Icon>
)

export const PasteIcon = () => (
  <Icon>
    <rect x="6" y="4" width="12" height="17" rx="2" />
    <path d="M9 4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2" />
  </Icon>
)

export const StopIcon = () => (
  <Icon>
    <circle cx="12" cy="12" r="9" />
    <rect x="9" y="9" width="6" height="6" fill="currentColor" stroke="none" />
  </Icon>
)

export const TrashIcon = () => (
  <Icon>
    <path d="M3 6h18" />
    <path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" />
    <path d="M6 6v14a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V6" />
  </Icon>
)

export const ServerIcon = () => (
  <Icon>
    <rect x="3" y="4" width="18" height="7" rx="1.5" />
    <rect x="3" y="13" width="18" height="7" rx="1.5" />
    <path d="M7 7.5h.01M7 16.5h.01" />
  </Icon>
)

export const ActivityIcon = () => (
  <Icon>
    <path d="M3 12h4l2 6 4-13 2 7h6" />
  </Icon>
)

export const GearIcon = () => (
  <Icon>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
  </Icon>
)

export const PowerIcon = () => (
  <Icon>
    <path d="M12 2v10" />
    <path d="M18.4 6.6a9 9 0 1 1-12.77.04" />
  </Icon>
)

export const KeyIcon = () => (
  <Icon>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="m11 12 9-9m-3 3 3 3m-6 0 2 2" />
  </Icon>
)

export const EyeIcon = () => (
  <Icon size={12}>
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
    <circle cx="12" cy="12" r="3" />
  </Icon>
)

export const DownloadIcon = () => (
  <Icon size={14}>
    <path d="M12 3v12m0 0 4-4m-4 4-4-4" />
    <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
  </Icon>
)

export const FolderIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" aria-hidden="true">
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
  </svg>
)

export const FileIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" aria-hidden="true">
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

export const FilesIcon = () => (
  <Icon>
    <path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
    <path d="M13 3v5h5" />
  </Icon>
)

export const ForwardIcon = () => (
  <Icon>
    <path d="M4 8h12l-3-3M20 16H8l3 3" />
  </Icon>
)

export const GitBranchIcon = () => (
  <Icon>
    <line x1="6" y1="3" x2="6" y2="15" />
    <circle cx="18" cy="6" r="3" />
    <circle cx="6" cy="18" r="3" />
    <path d="M18 9a9 9 0 0 1-9 9" />
  </Icon>
)

export const FolderMoveIcon = () => (
  <Icon>
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
    <path d="M9 13h6m0 0-2-2m2 2-2 2" />
  </Icon>
)

export const RefreshIcon = () => (
  <Icon>
    <path d="M21 12a9 9 0 1 1-2.64-6.36M21 4v5h-5" />
  </Icon>
)

export const CloseIcon = ({ size = 16 }: { size?: number }) => (
  <Icon size={size}>
    <path d="M18 6 6 18M6 6l12 12" />
  </Icon>
)

export const PlusIcon = () => (
  <Icon>
    <path d="M12 5v14M5 12h14" />
  </Icon>
)

export const HomeIcon = () => (
  <Icon>
    <path d="M3 11l9-8 9 8" />
    <path d="M5 10v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V10" />
  </Icon>
)

export const MoreIcon = () => (
  <Icon>
    <circle cx="5" cy="12" r="1.4" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
    <circle cx="19" cy="12" r="1.4" fill="currentColor" stroke="none" />
  </Icon>
)

export const TerminalPromptIcon = () => (
  <Icon>
    <path d="M5 8l3 3-3 3M11 14h5" />
  </Icon>
)

export const PopoutIcon = () => (
  <Icon>
    <path d="M14 4h6v6" />
    <path d="M20 4 10 14" />
    <path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" />
  </Icon>
)

export const SplitIcon = () => (
  <Icon>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M12 4v16" />
  </Icon>
)

export const LinkIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" />
    <path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" />
  </svg>
)
