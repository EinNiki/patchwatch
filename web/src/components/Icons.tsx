import type { IconName } from "@/lib/status";

/**
 * Statusformen unabhängig von der Farbe unterscheidbar:
 * ok = Kreis mit Haken, warn = Dreieck mit !, crit = Raute mit ×, unknown = gestrichelter Kreis mit ?,
 * reboot = Kreispfeil, clock = Uhr, pending = leerer gestrichelter Kreis.
 */
export function Icon({ name, size = 14 }: { name: IconName; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.6,
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
