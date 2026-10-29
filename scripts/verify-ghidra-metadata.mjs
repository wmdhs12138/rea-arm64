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

const target = resolve(process.argv[2] ?? "");
assert.ok(process.argv[2], "Supply a source-owned compiled ELF fixture path");
const procedure = process.argv[3] ?? "rea_layout_probe";
const entry =
  process.argv[4] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const digest = async () =>
  createHash("sha256")
    .update(await readFile(target))
    .digest("hex");
const before = await digest();
const client = new Client({
  name: "rea-ghidra-metadata-verifier",
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
  assert.equal(requireMcpToolError(response).code, code);
  checks++;
}
try {
  await client.connect(transport);
  await call("open_binary", { path: target, provider_id: "ghidra" });
  opened = true;
  const document = await call("current_document");
  assert.equal(typeof document, "string");
  assert.deepEqual(await call("list_documents"), [document]);
  const address = await call("procedure_address", { document, procedure });
  const location = { document, address };
  assert.equal(await call("comment", location), null);
  assert.equal(await call("inline_comment", location), null);
  assert.deepEqual(await call("list_bookmarks", { document }), []);
  const comment = "REA 注释 🌏\nSecond line";
  const inline = "REA 行内注释 🌏";
  assert.equal(await call("set_comment", { ...location, comment }), true);
  assert.equal(
    await call("set_inline_comment", { ...location, comment: inline }),
    true,
  );
  assert.equal(await call("comment", location), comment);
  assert.equal(await call("inline_comment", location), inline);
  const dossier = await call("analyze_function", {
    procedure: address,
    detail: "complete",
  });
  assert.ok(JSON.stringify(dossier).includes("REA 注释"));
  assert.ok(JSON.stringify(dossier).includes("REA 行内注释"));
  assert.equal(
    await call("set_bookmark", { ...location, name: "入口 🌏" }),
    true,
  );
  assert.equal(await call("set_bookmark", location), true);
  assert.deepEqual(await call("list_bookmarks", { document }), [
    { address, name: "入口 🌏" },
  ]);
  assert.equal(await call("set_bookmark", { ...location, name: "" }), true);
  assert.deepEqual(await call("list_bookmarks", { document }), [
    { address, name: null },
  ]);
  await reject(
    "set_comment",
    { ...location, comment: "bad\u0000text" },
    "invalid_request",
  );
  await reject(
    "set_bookmark",
    { ...location, name: "bad\u0000text" },
    "invalid_request",
  );
  await reject(
    "set_comment",
    { ...location, document: document + ".missing", comment: "lost" },
    "invalid_request",
  );
  await reject(
    "set_comment",
    { document, address: "0x1", comment: "unmapped" },
    "invalid_request",
  );
  assert.equal(await call("comment", location), comment);
  assert.deepEqual(await call("list_bookmarks", { document }), [
    { address, name: null },
  ]);
  assert.equal(await call("unset_bookmark", location), true);
  assert.equal(await call("unset_bookmark", location), true);
  assert.deepEqual(await call("list_bookmarks", { document }), []);
  for (const name of ["set_comment", "set_inline_comment"])
    assert.equal(await call(name, { ...location, comment: "" }), true);
  assert.equal(await call("comment", location), null);
  assert.equal(await call("inline_comment", location), null);
  // Leave metadata behind to prove that close discards it.
  await call("set_comment", { ...location, comment: "discard on close" });
  await call("set_bookmark", { ...location, name: "discard on close" });
  await call("close_binary");
  opened = false;
  await call("open_binary", { path: target, provider_id: "ghidra" });
  opened = true;
  assert.equal(await call("current_document"), document);
  assert.equal(await call("comment", location), null);
  assert.deepEqual(await call("list_bookmarks", { document }), []);
  assert.equal(await digest(), before);
  console.log(
    `PASS ${checks} real Ghidra MCP calls; readback, invalid input, cache freshness, ephemeral metadata and original-byte identity verified.`,
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
