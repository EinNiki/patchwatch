// Entscheidung der klickbaren Zeile: wann navigiert ein Klick, wann nicht.
import { test } from "node:test";
import assert from "node:assert/strict";
import { INTERACTIVE, rowClickAction, type ClickInfo } from "../src/lib/rowClick.ts";

const base: ClickInfo = { button: 0, defaultPrevented: false, modifier: false, onControl: false, selecting: false, overlayOpen: false };
const act = (o: Partial<ClickInfo> = {}) => rowClickAction({ ...base, ...o });

test("plain click navigates in the same tab", () => assert.equal(act(), "same"));

test("ctrl/cmd/shift click and middle click open a new tab", () => {
  assert.equal(act({ modifier: true }), "tab");
  assert.equal(act({ button: 1 }), "tab");
});

test("clicks on controls, with selected text, over an open dialog or already handled do nothing", () => {
  assert.equal(act({ onControl: true }), "none");
  assert.equal(act({ onControl: true, modifier: true }), "none");
  assert.equal(act({ selecting: true }), "none");
  assert.equal(act({ overlayOpen: true }), "none");
  assert.equal(act({ defaultPrevented: true }), "none");
  assert.equal(act({ button: 2 }), "none");
});

test("selected text still allows an explicit new-tab click", () => assert.equal(act({ selecting: true, modifier: true }), "tab"));

test("interactive selector covers the elements named in the spec", () => {
  for (const t of ["a", "button", "input", "select", "textarea", "summary", "label"]) assert.ok(INTERACTIVE.split(",").includes(t), t);
});
