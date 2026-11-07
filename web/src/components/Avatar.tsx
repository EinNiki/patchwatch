"use client";

import { useState } from "react";
import { colorIndex, initials } from "@/lib/avatar";

/**
 * Rundes Profilbild. Standard: Kreis mit Initialen (lokal erzeugt, Farbe aus festen Tokens, deterministisch aus dem Namen).
 * Mit `version` (Zeitstempel aus /auth/me) wird das eigene Bild geladen, immer von der eigenen API, nie von einer
 * frei gewählten Adresse. Das Bild ist dekorativ (`alt=""`): der Name steht daneben bzw. als Tooltip.
 */
export function Avatar({ name, version, size = 28, className = "" }: { name: string; version?: number | null; size?: number; className?: string }) {
  // Merkt sich, für welche Version das Laden fehlschlug (dann Initialen), ohne Zustand in einem Effekt zu setzen.
  const [failedFor, setFailedFor] = useState<number | null>(null);
  const style = { width: size, height: size } as const;
  if (version && failedFor !== version) {
    return (
      // eslint-disable-next-line @next/next/no-img-element -- eigene, geprüfte API-Antwort; next/image brächte hier nichts
      <img
        src={`/api/v1/auth/avatar?v=${version}`}
        alt=""
        width={size}
        height={size}
        style={style}
        referrerPolicy="no-referrer"
        decoding="async"
        onError={() => setFailedFor(version)}
        className={`shrink-0 rounded-full border border-line object-cover ${className}`}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      style={{ ...style, background: `var(--av-${colorIndex(name) + 1})`, color: "var(--av-fg)", fontSize: Math.round(size * 0.42) }}
      className={`grid shrink-0 select-none place-items-center rounded-full font-semibold leading-none ${className}`}
    >
      {initials(name)}
    </span>
  );
}
