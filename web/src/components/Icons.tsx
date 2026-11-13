import type { IconName } from "@/lib/status";

/**
 * Statusformen unabhängig von der Farbe unterscheidbar:
 * ok = Kreis mit Haken, warn = Dreieck mit !, crit = Raute mit ×, unknown = gestrichelter Kreis mit ?,
 * reboot = Kreispfeil, clock = Uhr, pending = leerer gestrichelter Kreis.
 * Alle Icons (auch `NavIcon`): 16er-Raster, Linie 1,5, currentColor.
 */
export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    focusable: false,
    className: "shrink-0",
  };
  switch (name) {
    case "ok":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.2" />
          <path d="M5.2 8.2l2 2 3.6-4" />
        </svg>
      );
    case "warn":
      return (
        <svg {...common}>
          <path d="M8 2l6.2 11H1.8z" />
          <path d="M8 6.6v3.2M8 11.6v.1" />
        </svg>
      );
    case "crit":
      return (
        <svg {...common}>
          <path d="M8 1.6l6.4 6.4L8 14.4 1.6 8z" />
          <path d="M5.9 5.9l4.2 4.2M10.1 5.9l-4.2 4.2" />
        </svg>
      );
    case "unknown":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.2" strokeDasharray="2.2 2" />
          <path d="M6.3 6.4a1.8 1.8 0 113 1.2c-.7.6-1.3.9-1.3 1.7M8 11.4v.1" />
        </svg>
      );
    case "reboot":
      return (
        <svg {...common}>
          <path d="M13.2 8a5.2 5.2 0 11-1.6-3.7" />
          <path d="M12.2 1.8v3h-3" />
        </svg>
      );
    case "clock":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.2" />
          <path d="M8 4.6V8l2.3 1.4" />
        </svg>
      );
    case "pending":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.2" strokeDasharray="2.2 2" />
        </svg>
      );
  }
}

export type NavIconName = "hosts" | "cves" | "agents" | "users" | "bell" | "settings" | "menu" | "close" | "refresh" | "plus" | "external" | "chevron" | "collapse" | "logout" | "sort" | "asc" | "desc" | "filter" | "star" | "star-fill" | "more";

/** Navigations- und Aktions-Icons: eigene Linienformen, immer mit Text daneben (nie allein). */
export function NavIcon({ name, size = 16 }: { name: NavIconName; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    focusable: false,
    className: "shrink-0",
  };
  switch (name) {
    case "hosts":
      return (
        <svg {...common}>
          <rect x="2" y="2.5" width="12" height="4.5" rx="1" />
          <rect x="2" y="9" width="12" height="4.5" rx="1" />
          <path d="M4.6 4.75v.1M4.6 11.25v.1" />
        </svg>
      );
    case "cves":
      return (
        <svg {...common}>
          <path d="M8 1.8l5.2 2v3.7c0 3-2.2 5.3-5.2 6.7-3-1.4-5.2-3.7-5.2-6.7V3.8z" />
          <path d="M8 5.4v3M8 10.3v.1" />
        </svg>
      );
    case "agents":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="2" />
          <path d="M3.9 4.1a5.8 5.8 0 000 7.8M12.1 4.1a5.8 5.8 0 010 7.8" />
        </svg>
      );
    case "users":
      return (
        <svg {...common}>
          <circle cx="6" cy="5.5" r="2.3" />
          <path d="M1.8 13c.3-2.4 2-3.7 4.2-3.7s3.9 1.3 4.2 3.7" />
          <path d="M10.4 3.6a2.3 2.3 0 010 3.8M12.2 9.6c1.3.5 2.1 1.6 2.3 3.4" />
        </svg>
      );
    case "bell":
      return (
        <svg {...common}>
          <path d="M3.5 11.2h9l-1.1-1.6V7a3.4 3.4 0 00-6.8 0v2.6z" />
          <path d="M6.6 13.4a1.5 1.5 0 002.8 0" />
        </svg>
      );
    case "settings":
      return (
        <svg {...common}>
          <path d="M2.5 4.5h6M11.5 4.5h2M2.5 11.5h2M7.5 11.5h6" />
          <circle cx="10" cy="4.5" r="1.5" />
          <circle cx="6" cy="11.5" r="1.5" />
        </svg>
      );
    case "menu":
      return (
        <svg {...common}>
          <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
        </svg>
      );
    case "close":
      return (
        <svg {...common}>
          <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />
        </svg>
      );
    case "refresh":
      return (
        <svg {...common}>
          <path d="M13.2 8a5.2 5.2 0 11-1.6-3.7" />
          <path d="M12.2 1.8v3h-3" />
        </svg>
      );
    case "plus":
      return (
        <svg {...common}>
          <path d="M8 3v10M3 8h10" />
        </svg>
      );
    case "sort":
      return (
        <svg {...common}>
          <path d="M5.5 6.5L8 4l2.5 2.5M5.5 9.5L8 12l2.5-2.5" />
        </svg>
      );
    case "asc":
      return (
        <svg {...common}>
          <path d="M8 12.5v-9M4.5 7L8 3.5 11.5 7" />
        </svg>
      );
    case "desc":
      return (
        <svg {...common}>
          <path d="M8 3.5v9M4.5 9L8 12.5 11.5 9" />
        </svg>
      );
    case "filter":
      return (
        <svg {...common}>
          <path d="M2.5 3.5h11L9.5 8.5v4l-3 1v-5z" />
        </svg>
      );
    case "star":
      return (
        <svg {...common}>
          <path d="M8 2l1.8 3.9 4.2.5-3.1 2.9.8 4.2L8 11.4l-3.7 2.1.8-4.2L2 6.4l4.2-.5z" />
        </svg>
      );
    case "star-fill":
      return (
        <svg {...common} fill="currentColor">
          <path d="M8 2l1.8 3.9 4.2.5-3.1 2.9.8 4.2L8 11.4l-3.7 2.1.8-4.2L2 6.4l4.2-.5z" />
        </svg>
      );
    case "more":
      return (
        <svg {...common} fill="currentColor" stroke="none">
          <circle cx="3.5" cy="8" r="1.3" />
          <circle cx="8" cy="8" r="1.3" />
          <circle cx="12.5" cy="8" r="1.3" />
        </svg>
      );
    case "collapse":
      return (
        <svg {...common}>
          <path d="M10 4L6 8l4 4" />
        </svg>
      );
    case "chevron":
      return (
        <svg {...common}>
          <path d="M4 6l4 4 4-4" />
        </svg>
      );
    case "logout":
      return (
        <svg {...common}>
          <path d="M6.5 2.5h-3v11h3M10 5.5L12.5 8 10 10.5M12.5 8H6" />
        </svg>
      );
    case "external":
      return (
        <svg {...common}>
          <path d="M6.5 3H3.5v9.5H13V9.5M9 2.5h4.5V7M13.5 2.5L7.5 8.5" />
        </svg>
      );
  }
}

/** Marke: Quadrat mit Haken (patchwatch prüft Patch-Stände). Flach, `currentColor` für den Rahmen, Akzent für den Haken. */
export function Logo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" fill="none" aria-hidden="true" focusable={false} className="shrink-0">
      <rect x="2.75" y="2.75" width="14.5" height="14.5" rx="3.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M6.6 10.2l2.4 2.4 4.4-5" stroke="var(--accent)" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
