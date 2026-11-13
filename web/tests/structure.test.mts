// Erzwingt einheitliche Seitenköpfe: jede Seite der App nutzt PageHeader, kein eigenes <h1> im Seitenkopf.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

function pages(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? pages(p) : n === "page.tsx" ? [p] : [];
  });
}

const ROOT = "src/app/(app)";
// Weiterleitungen ohne eigene Oberfläche dürfen keinen Kopf haben.
const NO_HEADER = new Set<string>();

test("jede Seite nutzt PageHeader und kein eigenes h1", () => {
  for (const p of pages(ROOT)) {
    if (NO_HEADER.has(p)) continue;
    const s = readFileSync(p, "utf8");
    assert.match(s, /<PageHeader[\s>]/, `${p}: PageHeader fehlt`);
    const own = [...s.matchAll(/<h1[^>]*>/g)].filter((m) => !m[0].includes("text-crit"));
    assert.equal(own.length, 0, `${p}: eigenes <h1> statt PageHeader`);
  }
});

test("PageHeader nimmt keine Knöpfe entgegen", () => {
  const s = readFileSync("src/components/PageHeader.tsx", "utf8");
  const sig = s.slice(s.indexOf("export function PageHeader"), s.indexOf("return", s.indexOf("export function PageHeader")));
  assert.doesNotMatch(sig, /children|actions/);
});
