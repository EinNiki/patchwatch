import assert from "node:assert/strict";
import { test } from "node:test";
import { activeLocks, isOutside, lockScroll } from "../src/lib/scrollLock.ts";

// Minimale Umgebung statt DOM: nur das, was die Sperre anfasst.
const style = { overflow: "", paddingRight: "" };
Object.assign(globalThis, { document: { documentElement: { style, clientWidth: 985 } }, window: { innerWidth: 1000 } });

test("lock hides page scroll, compensates the scrollbar and releases exactly once", () => {
  const release = lockScroll();
  assert.equal(style.overflow, "hidden");
  assert.equal(style.paddingRight, "15px");
  assert.equal(activeLocks(), 1);
  release();
  release(); // doppeltes Freigeben schadet nicht
  assert.equal(activeLocks(), 0);
  assert.equal(style.overflow, "");
  assert.equal(style.paddingRight, "");
});

test("nested dialogs keep the page locked until the last one closes", () => {
  const a = lockScroll();
  const b = lockScroll();
  a();
  assert.equal(style.overflow, "hidden", "das zweite Fenster ist noch offen");
  b();
  assert.equal(style.overflow, "");
  assert.equal(activeLocks(), 0);
});

test("a point outside the dialog box is a backdrop click, inside is not", () => {
  const r = { left: 100, right: 500, top: 50, bottom: 400 };
  assert.equal(isOutside(r, 99, 100), true);
  assert.equal(isOutside(r, 300, 401), true);
  assert.equal(isOutside(r, 100, 50), false, "Rand zählt zum Fenster");
  assert.equal(isOutside(r, 300, 200), false);
});
