"use client";

import { useState } from "react";

type Theme = "system" | "light" | "dark";

function readTheme(): Theme {
  try {
    const t = localStorage.getItem("pw-theme");
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

/** Hell/Dunkel: folgt dem System, manuell umschaltbar und gemerkt (Skript in layout.tsx setzt es vor dem Rendern). */
export function ThemeSelect() {
  const [theme, setTheme] = useState<Theme>(() => (typeof window === "undefined" ? "system" : readTheme()));
  return (
    <label className="flex items-center gap-1.5 text-xs text-fg2">
      Farbschema
      <select
        value={theme}
        onChange={(e) => {
          const next = e.target.value as Theme;
          setTheme(next);
          const root = document.documentElement;
          if (next === "system") root.removeAttribute("data-theme");
          else root.setAttribute("data-theme", next);
          try {
            if (next === "system") localStorage.removeItem("pw-theme");
            else localStorage.setItem("pw-theme", next);
          } catch {
            /* Speicher gesperrt: Auswahl gilt nur für diese Sitzung */
          }
        }}
        className="min-h-8 rounded-[3px] border border-control bg-sunk px-1.5 text-xs text-fg max-md:min-h-11"
      >
        <option value="system">System</option>
        <option value="light">Hell</option>
        <option value="dark">Dunkel</option>
      </select>
    </label>
  );
}
