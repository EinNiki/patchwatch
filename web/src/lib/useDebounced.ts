"use client";

import { useEffect, useState } from "react";

/** Wert, der erst nach `ms` Ruhe übernommen wird (Suchfelder: nicht bei jedem Tastendruck abrufen). */
export function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}
