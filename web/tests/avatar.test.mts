import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { colorIndex, cropRect, initials, MAX_UPLOAD_BYTES, PALETTE_SIZE, precheck, sniffImage } from "../src/lib/avatar.ts";

test("Initialen: Umlaute, Emoji, ein Zeichen, mehrere Wörter, SSO-Name", () => {
  assert.equal(initials("admin"), "A");
  assert.equal(initials("Ömer"), "Ö");
  assert.equal(initials("ärger"), "Ä");
  assert.equal(initials("max.muster"), "MM");
  assert.equal(initials("Anna Lena Meier"), "AL");
  assert.equal(initials("oidc:max.muster@example.com"), "MM");
  assert.equal(initials("x"), "X");
  assert.equal(initials("🦊 fuchs"), "🦊F");
  assert.equal(initials("👩🏽‍💻"), "👩🏽‍💻");
  assert.equal(initials("ßeta"), "SS");
  assert.equal(initials("   "), "?");
  assert.equal(initials(""), "?");
});

test("Farbe ist deterministisch, unabhängig von Groß-/Kleinschreibung und liegt in der Palette", () => {
  assert.equal(colorIndex("admin"), colorIndex("admin"));
  assert.equal(colorIndex("Admin"), colorIndex(" admin "));
  const seen = new Set<number>();
  for (const n of ["admin", "anna", "bob", "carla", "dieter", "eva", "frank", "gerda", "hans", "ida"]) {
    const i = colorIndex(n);
    assert.ok(i >= 0 && i < PALETTE_SIZE);
    seen.add(i);
  }
  assert.ok(seen.size >= 3, "verteilt sich über mehrere Farben");
});

// Kontrast der Initialen auf dem Kreis, gelesen aus den Tokens (hell und dunkel).
function lum(hex: string): number {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0]! + 0.7152 * c[1]! + 0.0722 * c[2]!;
}
const contrast = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x! + 0.05) / (y! + 0.05);
};

test("Text auf dem Kreis hat mindestens 4,5:1 in beiden Modi", () => {
  const css = readFileSync(new URL("../src/app/tokens.css", import.meta.url), "utf8");
  // Blöcke: hell = erster :root, dunkel = die beiden Dunkel-Blöcke.
  const sets = [...css.matchAll(/--av-1: (#[0-9a-f]{6});[\s\S]*?--av-6: (#[0-9a-f]{6});\s*--av-fg: (#[0-9a-f]{6});/gi)];
  assert.equal(sets.length, 3, "ein heller und zwei dunkle Blöcke");
  for (const m of sets) {
    const block = m[0];
    const fg = m[3]!;
    for (let i = 1; i <= 6; i++) {
      const bg = new RegExp(`--av-${i}: (#[0-9a-f]{6})`, "i").exec(block)![1]!;
      assert.ok(contrast(bg, fg) >= 4.5, `--av-${i} ${bg} auf ${fg}: ${contrast(bg, fg).toFixed(2)}`);
    }
  }
});

test("Dateityp wird an den Bytes erkannt, nie an der Endung", () => {
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]);
  const jpeg = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0]);
  const webp = new TextEncoder().encode("RIFF\0\0\0\0WEBPVP8L");
  const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>');
  const gif = new TextEncoder().encode("GIF89a\x01\x00\x01\x00");
  assert.deepEqual([sniffImage(png), sniffImage(jpeg), sniffImage(webp), sniffImage(svg), sniffImage(gif)], ["png", "jpeg", "webp", null, null]);
  assert.equal(precheck(100, png), null);
  assert.match(precheck(100, svg)!, /PNG, JPEG und WebP/);
  assert.match(precheck(100, gif)!, /kein GIF/);
  assert.match(precheck(MAX_UPLOAD_BYTES + 1, png)!, /2 MB/);
  assert.match(precheck(0, png)!, /leer/);
});

test("Zuschnitt: Quadrat liegt immer im Bild, Zoom verkleinert, Mitte ist Standard", () => {
  assert.deepEqual(cropRect(400, 200), { sx: 100, sy: 0, side: 200 });
  const z = cropRect(400, 200, 2);
  assert.equal(z.side, 100);
  for (const [px, py] of [[-5, -5], [5, 5], [0, 1], [-1, 0]] as const) {
    const r = cropRect(400, 200, 2, px, py);
    assert.ok(r.sx >= 0 && r.sy >= 0 && r.sx + r.side <= 400 && r.sy + r.side <= 200);
  }
});
