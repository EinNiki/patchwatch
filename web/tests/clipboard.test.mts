import assert from "node:assert/strict";
import { test } from "node:test";
import { copyText } from "../src/lib/clipboard.ts";

test("uses the clipboard API when available", async () => {
  let got = "";
  const r = await copyText("sudo reboot", { writeText: async (t) => void (got = t), legacy: () => assert.fail("kein Rückfall nötig") });
  assert.equal(r, "clipboard");
  assert.equal(got, "sudo reboot");
});

test("falls back when navigator.clipboard is missing (insecure context)", async () => {
  let got = "";
  const r = await copyText("sudo apt update", { legacy: (t) => ((got = t), true) });
  assert.equal(r, "legacy");
  assert.equal(got, "sudo apt update");
});

test("falls back when the API rejects (no permission)", async () => {
  const r = await copyText("x", { writeText: async () => Promise.reject(new Error("NotAllowedError")), legacy: () => true });
  assert.equal(r, "legacy");
});

test("reports failure when nothing works and never throws", async () => {
  assert.equal(await copyText("x", {}), "failed");
  assert.equal(await copyText("x", { writeText: async () => Promise.reject(new Error("no")), legacy: () => false }), "failed");
  assert.equal(await copyText("x", { legacy: () => { throw new Error("execCommand weg"); } }), "failed");
});
