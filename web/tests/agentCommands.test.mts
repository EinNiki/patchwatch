import assert from "node:assert/strict";
import { test } from "node:test";
import { SET_TOKEN_COMMAND, installCommand } from "../src/lib/agentCommands.ts";

test("set-token command never contains a token argument", () => {
  assert.equal(SET_TOKEN_COMMAND, "sudo patchwatch-agent set-token");
  assert.ok(!/--token(\s|=)/.test(SET_TOKEN_COMMAND) && !SET_TOKEN_COMMAND.includes("pw_"));
});

test("install command carries the server url but no token", () => {
  const c = installCommand("https://pw.example.org", "https://x/releases/latest/download");
  assert.ok(c.includes("--server-url https://pw.example.org"));
  assert.ok(!c.includes("pw_") && !/--token(\s|=)/.test(c));
});
