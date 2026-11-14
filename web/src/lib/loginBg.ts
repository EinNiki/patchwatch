import type { CSSProperties } from "react";

/** Hintergrund der Anmeldeseite (auch für das Übergangs-Overlay): kräftige Akzent-Glows oben links und unten rechts plus Punktraster. */
export const LOGIN_BG: CSSProperties = {
  backgroundColor: "var(--bg)",
  backgroundImage:
    "radial-gradient(52rem 34rem at 0% -6%, color-mix(in srgb, var(--accent) 32%, transparent), transparent 70%), radial-gradient(52rem 34rem at 100% 106%, color-mix(in srgb, var(--accent) 26%, transparent), transparent 70%), radial-gradient(color-mix(in srgb, var(--text-3) 30%, transparent) 1px, transparent 1px)",
  backgroundSize: "auto, auto, 22px 22px",
};
