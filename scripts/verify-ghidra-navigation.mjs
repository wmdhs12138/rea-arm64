import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import {
  requireMcpOperationResult,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";

// Headless by default. With REA_GHIDRA_ATTACH_ENDPOINT set, a user-launched
// CodeBrowser must already hold the same file with ReaGhidraBridge.java running.
const target = resolve(process.argv[2] ?? "");
assert.ok(process.argv[2], "Supply a source-owned compiled AArch64 ELF path");
const procedure = process.argv[3] ?? "rea_layout_probe";
const entry =
  process.argv[4] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const attached = process.env.REA_GHIDRA_ATTACH_ENDPOINT !== undefined;
const digest = async () =>
  createHash("sha256")
    .update(await readFile(target))
    .digest("hex");
const before = await digest();
const client = new Client({
  name: "rea-ghidra-navigation-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entry, "mcp"],
  env: { ...process.env },
  stderr: "pipe",
});
let diagnostics = "";
transport.stderr?.on("data", (chunk) => {
  diagnostics = (diagnostics + chunk).slice(-8192);
});
let opened = false;
let checks = 0;
async function call(name, args = {}) {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 240_000 },
  );
  const result = requireMcpOperationResult(response, name);
  checks++;
  return result;
}
async function reject(name, args, code) {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 240_000 },
  );
  assert.equal(requireMcpToolError(response).code, code, name);
  checks++;
}
// Fixed-width A64 instructions make the adjacent code unit exact.
const plus = (address, delta) => `0x${(BigInt(address) + delta).toString(16)}`;
try {
  await client.connect(transport);
  await call("open_binary", { path: target, provider_id: "ghidra" });
  opened = true;
  const document = await call("current_document");
  const address = await call("procedure_address", { document, procedure });
  const next = plus(address, 4n);
  assert.equal(await call("next_address", { document, address }), next);
  assert.equal(
    await call("prev_address", { document, address: next }),
    address,
  );
  assert.equal(
    await call("next_address", { document, address: plus(address, 2n) }),
    next,
  );
  await reject("next_address", { document, address: "0x1" }, "invalid_request");
  if (!attached) {
    await reject("next_address", { document }, "invalid_request");
    await reject("current_address", { document }, "capability_unavailable");
    await reject(
      "goto_address",
      { document, address },
      "capability_unavailable",
    );
  } else {
    assert.equal(await call("goto_address", { document, address: next }), next);
    assert.equal(await call("current_address", { document }), next);
    assert.equal(await call("prev_address", { document }), address);
    assert.equal(
      await call("goto_address", { document, address: plus(address, 2n) }),
      address,
    );
    assert.equal(await call("current_address", { document }), address);
    assert.equal(await call("next_address", { document }), next);
    assert.equal(await call("current_procedure", { document }), procedure);
    assert.deepEqual(await call("get_navigation_context"), {
      document,
      address,
      procedure,
    });
    await reject(
      "goto_address",
      { document, address: "0x1" },
      "invalid_request",
    );
    assert.equal(await call("current_address", { document }), address);
    await reject(
      "set_comment",
      { document, address, comment: "attached mode is read-only" },
      "capability_unavailable",
    );
    assert.equal(await call("comment", { document, address }), null);
    // Closing REA's target disconnects; the CodeBrowser keeps serving.
    await call("close_binary");
    opened = false;
    await call("open_binary", { path: target, provider_id: "ghidra" });
    opened = true;
    assert.equal(await call("current_address", { document }), address);
  }
  assert.equal(await digest(), before);
  console.log(
    `PASS ${checks} real Ghidra ${attached ? "attached CodeBrowser" : "headless"} MCP calls; navigation, cursor readback, refusals and original-byte identity verified.`,
  );
} catch (error) {
  console.error(diagnostics);
  throw error;
} finally {
  try {
    if (opened) await call("close_binary");
  } finally {
    await client.close();
  }
}
