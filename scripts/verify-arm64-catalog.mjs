import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { requireMcpLifecycleResult } from "./lib/mcp-verifier-results.mjs";

const entry =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
for (const profile of ["compact", "full"]) {
  const client = new Client({
    name: "rea-arm64-catalog-verifier",
    version: "1",
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: { ...process.env, REA_MCP_INPUT_SCHEMA_PROFILE: profile },
    stderr: "pipe",
  });
  let diagnostics = "";
  transport.stderr?.on("data", (chunk) => {
    diagnostics = (diagnostics + chunk).slice(-4096);
  });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    for (const name of [
      "inspect_binary_layout",
      "inspect_recorded_crash",
      "inspect_evm_interface",
      "recover_javascript_sources",
    ]) {
      const tool = tools.find((item) => item.name === name);
      assert.ok(tool, `${profile}: missing ${name}`);
      assert.match(
        tool.description,
        /Linux x64(?:\/| and | or )ARM64/,
        `${profile}: stale ${name} host description`,
      );
    }
    const layout = tools.find((tool) => tool.name === "inspect_binary_layout");
    assert.ok(
      JSON.stringify(layout.outputSchema).includes("EM_AARCH64"),
      `${profile}: stale ELF result schema`,
    );
    // Acquire the lazy runtime too: cached schemas alone do not prove that its
    // catalog identity agrees with the startup catalog.
    const session = requireMcpLifecycleResult(
      await client.callTool(
        { name: "binary_session", arguments: {} },
        { timeout: 60_000 },
      ),
      "binary_session",
    );
    assert.equal(session.tool_availability.length, tools.length);
    console.log(
      `PASS ${profile} MCP catalog, ARM64 descriptions, AArch64 output schema and deferred runtime identity (${tools.length} tools).`,
    );
  } catch (error) {
    console.error(diagnostics);
    throw error;
  } finally {
    await client.close();
  }
}
