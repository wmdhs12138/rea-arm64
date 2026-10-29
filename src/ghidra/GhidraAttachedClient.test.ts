import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { GhidraAttachedClient } from "./GhidraAttachedClient.js";
import {
  FakeAttachedBridge,
  nextRequest,
  TARGET_SHA256,
} from "./GhidraAttachedBridge.fixture.js";

const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task();
});

const attachedClient = async () => {
  const bridge = await FakeAttachedBridge.start();
  const client = new GhidraAttachedClient({
    endpointPath: bridge.endpointPath,
    targetSha256: TARGET_SHA256,
    connectTimeoutMs: 5_000,
  });
  cleanup.push(
    () => bridge.close(),
    () => client.close(),
  );
  return { bridge, client };
};

describe("Ghidra attached client", () => {
  it("verifies the published run and target before serving authenticated requests", async () => {
    const { bridge, client } = await attachedClient();
    const result = await client.callTool("current_address", { document: null });
    expect(result).toEqual({ ok: true, value: "0x100000" });
    expect(bridge.requests.map(({ method }) => method)).toEqual([
      "ping",
      "current_address",
    ]);
    expect(bridge.requests.every(({ token }) => token === bridge.token)).toBe(
      true,
    );
  });

  it("disconnects on close without stopping the user's bridge", async () => {
    const { bridge, client } = await attachedClient();
    expect((await client.start()).ok).toBe(true);
    expect((await client.close()).ok).toBe(true);
    expect(bridge.requests.map(({ method }) => method)).toEqual(["ping"]);
    const again = new GhidraAttachedClient({
      endpointPath: bridge.endpointPath,
      targetSha256: TARGET_SHA256,
      connectTimeoutMs: 5_000,
    });
    cleanup.push(() => again.close());
    expect((await again.start()).ok).toBe(true);
  });

  it("fails at once when no bridge has published an endpoint", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-ghidra-attach-"));
    cleanup.push(() => rm(root, { recursive: true, force: true }));
    const client = new GhidraAttachedClient({
      endpointPath: join(root, "endpoint.json"),
      targetSha256: TARGET_SHA256,
      connectTimeoutMs: 60_000,
    });
    const started = performance.now();
    const result = await client.start();
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("start");
    expect(result.error.message).toContain("ReaGhidraBridge.java");
  });

  it("names both digests when the CodeBrowser holds a different file", async () => {
    const { bridge, client } = await attachedClient();
    bridge.sha256 = "b".repeat(64);
    const result = await client.callTool("current_address", { document: null });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).toContain("b".repeat(64));
    expect(result.error.message).toContain(TARGET_SHA256);
    expect(bridge.requests.map(({ method }) => method)).toEqual(["ping"]);
  });

  it("refuses a Program whose auto-analysis is still running", async () => {
    const { bridge, client } = await attachedClient();
    bridge.analysis = { analyzed: true, active: true };
    const result = await client.start();
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatchObject({
      kind: "remote",
      remoteCode: "analysis_incomplete",
    });
    bridge.analysis = { analyzed: true, active: false };
    expect((await client.start()).ok).toBe(true);
  });

  it("redacts the bearer token from bridge-reported failures", async () => {
    const { bridge, client } = await attachedClient();
    bridge.reply = () => ({
      code: "invalid_request",
      message: `rejected ${bridge.token}`,
    });
    const result = await client.callTool("goto_address", {
      document: null,
      address: "0x1",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(JSON.stringify(result.error.diagnostics)).not.toContain(
      bridge.token,
    );
    expect(result.error.message).not.toContain(bridge.token);
  });

  it("reconnects after the bridge drops a connection mid-request", async () => {
    const { bridge, client } = await attachedClient();
    bridge.reply = () => "hold";
    const pending = client.callTool("current_address", { document: null });
    await nextRequest(bridge, "current_address");
    bridge.dropConnections();
    const lost = await pending;
    expect(lost.ok).toBe(false);
    if (!lost.ok) expect(lost.error.kind).toBe("process");
    bridge.reply = () => ({ result: "0x100004" });
    expect(
      await client.callTool("current_address", { document: null }),
    ).toEqual({ ok: true, value: "0x100004" });
    expect(bridge.sockets).toHaveLength(2);
  });

  it("cancels an active request by disconnecting, then reconnects for the next one", async () => {
    const { bridge, client } = await attachedClient();
    bridge.reply = () => "hold";
    const controller = new AbortController();
    const reason = { request: "cancel attached request" };
    const pending = client.callTool(
      "procedure_pseudo_code",
      { document: null, procedure: "main" },
      { signal: controller.signal },
    );
    await nextRequest(bridge, "procedure_pseudo_code");
    controller.abort(reason);
    const cancelled = await pending;
    expect(cancelled.ok).toBe(false);
    if (cancelled.ok) return;
    expect(cancelled.error.kind).toBe("cancelled");
    expect(cancelled.error.cancellation?.reason).toBe(reason);
    await expect
      .poll(() => bridge.closedConnections, { timeout: 2_000 })
      .toBe(1);
    expect(bridge.requests.some(({ method }) => method === "shutdown")).toBe(
      false,
    );
    bridge.reply = () => ({ result: "main" });
    expect(
      await client.callTool("current_procedure", { document: null }),
    ).toEqual({ ok: true, value: "main" });
  });
});
