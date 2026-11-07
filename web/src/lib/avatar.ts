// Profilbild: Initialen, Farbe und Dateiprüfung im Browser (reine Logik, ohne React).

/** Anzahl der Farben aus den Tokens `--av-1` … `--av-6`. */
export const PALETTE_SIZE = 6;
export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
export const AVATAR_SIZE = 128;
export const MAX_AVATAR_BYTES = 64 * 1024;

/** Zerlegt in Graphem-Cluster, damit Emoji und Zeichen mit Akzent nicht in der Mitte geschnitten werden. */
function graphemes(s: string): string[] {
  if (typeof Intl !== "undefined" && "Segmenter" in Intl) {
    return [...new Intl.Segmenter("de", { granularity: "grapheme" }).segment(s)].map((x) => x.segment);
  }
  return [...s];
}

/** Anzeigename ohne SSO-Präfix und ohne Mail-Domain („oidc:max.muster@example.com“ → „max.muster“). */
function baseName(name: string): string {
  return name.trim().replace(/^oidc:/i, "").split("@")[0] ?? "";
}

/** Initialen: bei mehreren Wörtern (getrennt durch Leerzeichen . _ -) die ersten beiden Anfangsbuchstaben, sonst einer. */
export function initials(name: string): string {
  const parts = baseName(name).split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  const first = (w: string) => graphemes(w)[0] ?? "";
  const letters = parts.length > 1 ? [first(parts[0]!), first(parts[1]!)] : [first(parts[0]!)];
  // „ß“ wird zu „SS“; Emoji bleiben als ganzes Graphem erhalten (nie mitten im Zeichen schneiden).
  return letters.map((l) => graphemes(l.toLocaleUpperCase("de")).slice(0, 2).join("")).join("");
}

/** Stabiler Index 0–5 aus dem Benutzernamen (FNV-1a, Groß-/Kleinschreibung egal). */
export function colorIndex(name: string): number {
  let h = 0x811c9dc5;
  for (const ch of name.trim().toLowerCase()) {
    h ^= ch.codePointAt(0)!;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % PALETTE_SIZE;
}

export type ImageKind = "png" | "jpeg" | "webp";

/** Erkennt PNG, JPEG und WebP an den ersten Bytes (nie an Endung oder angegebenem Typ). SVG, GIF und alles andere: `null`. */
export function sniffImage(b: Uint8Array): ImageKind | null {
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return "png";
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
  if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "webp";
  return null;
}

/** Ergebnis der Vorprüfung einer gewählten Datei (Text für Nutzer, `null` = in Ordnung). */
export function precheck(size: number, head: Uint8Array): string | null {
  if (size === 0) return "Die Datei ist leer.";
  if (size > MAX_UPLOAD_BYTES) return "Die Datei ist größer als 2 MB.";
  if (sniffImage(head) === null) return "Nur PNG, JPEG und WebP sind erlaubt (kein SVG, kein GIF).";
  return null;
}

/**
 * Quadratischer Ausschnitt in Quellpixeln. `zoom` ≥ 1 (1 = größtmögliches Quadrat), `px`/`py` in −1…1 verschieben
 * innerhalb des Bildes (0 = Mitte). Der Ausschnitt liegt immer ganz im Bild.
 */
export function cropRect(w: number, h: number, zoom = 1, px = 0, py = 0): { sx: number; sy: number; side: number } {
  const side = Math.max(1, Math.min(w, h) / Math.max(1, zoom));
  const clamp = (v: number) => Math.max(-1, Math.min(1, v));
  const sx = (w - side) / 2 + (clamp(px) * (w - side)) / 2;
  const sy = (h - side) / 2 + (clamp(py) * (h - side)) / 2;
  return { sx, sy, side };
}
