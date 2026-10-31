"use client";

import { useEffect, useState } from "react";

/** Aktuelle Zeit, alle `ms` aktualisiert (für Anzeigen wie „seit 3 Min.“). */
export function useNow(ms = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}
