import { afterEach, describe, expect, it } from "vitest";

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseConfig } from "../config/parseConfig.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import {
  FakeAttachedBridge,
  TARGET_SHA256,
} from "./GhidraAttachedBridge.fixture.js";
import { parseGhidraInventoryInput } from "./GhidraInventoryValues.js";
import { GhidraProvider } from "./GhidraProvider.js";
import {
  GHIDRA_ATTACHED_OPERATIONS,
  GHIDRA_SESSION_CAPABILITIES,
  parseGhidraAttachedSessionInfo,
} from "./GhidraSessionValues.js";

const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task();
});

const provider = (environment: Readonly<Record<string, string>>) => {
  const config = parseConfig(environment);
  if (!config.ok) throw config.error;
  return new GhidraProvider(config.value, silentLogger, {});
};

const elfTarget = (
  availableArchitectures: readonly ("arm64" | "x86_64")[] = ["arm64"],
): BinaryTarget => ({
  path: "/tmp/probe.elf",
  sha256: TARGET_SHA256,
  kind: "executable",
  format: availableArchitectures.length > 1 ? "mach-o-universal" : "elf",
  architecture: "arm64",
  availableArchitectures: [...availableArchitectures],
});

const descriptor = (ghidra: GhidraProvider, operation: string) =>
  ghidra.capabilities().find((entry) => entry.operation === operation);

describe("Ghidra attached mode capabilities", () => {
  it("serves live reads and cursor navigation without edits or local processes", () => {
    const ghidra = provider({
      REA_GHIDRA_ATTACH_ENDPOINT: "/run/rea/endpoint.json",
    });
    expect(descriptor(ghidra, "current_address")).toMatchObject({
      available: true,
      cachePolicy: "live",
      effects: { launchesProcess: false, mayWriteFilesystem: false },
    });
    expect(descriptor(ghidra, "goto_address")?.effects.mayShowUi).toBe(true);
    for (const operation of ["set_comment", "inspect_native_load_image"])
      expect(descriptor(ghidra, operation)).toMatchObject({
        available: false,
        availabilityCode: "not_configured",
      });
  });

  it("keeps cursor state unavailable to headless sessions while serving explicit navigation", () => {
    const ghidra = provider({ GHIDRA_INSTALL_DIR: "/opt/ghidra" });
    const cursor = descriptor(ghidra, "current_address");
    expect(cursor).toMatchObject({
      available: false,
      availabilityCode: "not_configured",
    });
    expect(cursor?.reason).toContain("REA_GHIDRA_ATTACH_ENDPOINT");
    expect(descriptor(ghidra, "next_address")?.available).toBe(true);
    expect(GHIDRA_SESSION_CAPABILITIES).toContain("prev_address");
    expect(GHIDRA_SESSION_CAPABILITIES).not.toContain("goto_address");
  });

  it("requires an explicit address unless a cursor can stand in for it", () => {
    expect(parseGhidraInventoryInput("next_address", {}).ok).toBe(false);
    expect(
      parseGhidraInventoryInput("prev_address", {}, { cursor: true }),
    ).toEqual({ ok: true, value: { document: null, address: null } });
    expect(
      parseGhidraInventoryInput("goto_address", {}, { cursor: true }).ok,
    ).toBe(false);
  });

  it("is available without a local Ghidra installation", async () => {
    const availability = await provider({
      REA_GHIDRA_ATTACH_ENDPOINT: "/run/rea/endpoint.json",
    }).inspectAvailability();
    expect(availability).toMatchObject({
      status: "available",
      diagnostics: { mode: "attached" },
    });
  });

  it("refuses a universal Mach-O whose imported slice the digest cannot prove", () => {
    const ghidra = provider({
      REA_GHIDRA_ATTACH_ENDPOINT: "/run/rea/endpoint.json",
    });
    expect(
      ghidra.inspectTargetSupport(elfTarget(["arm64", "x86_64"])),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
    });
    expect(ghidra.inspectTargetSupport(elfTarget()).status).toBe("supported");
  });
});

describe("Ghidra attached handshake", () => {
  const runId = "d6fcbb66-e829-4ff6-a535-0035aec63139";
  const session = (capabilities: readonly string[]) => ({
    name: "REA Ghidra bridge",
    mode: "attached",
    run_id: runId,
    provider: { id: "ghidra", version: "12.1.4" },
    read_only: true,
    analysis: { analyzed: true, active: false },
    capabilities,
    target: {
      name: "probe.elf",
      language_id: "AARCH64:LE:64:v8A",
      compiler_spec_id: "default",
      image_base: "0x100000",
      default_address_space: "ram",
      sha256: TARGET_SHA256,
      project_path: "/probe.elf",
    },
    pdb: {
      file: null,
      guid: null,
      age: null,
      signature: null,
      version: null,
      loaded: null,
    },
  });
  const expected = { runId, targetSha256: TARGET_SHA256 };

  it("rejects a bridge that would admit edits to the analyst's Program", () => {
    const served = ["ping", ...GHIDRA_ATTACHED_OPERATIONS];
    expect(parseGhidraAttachedSessionInfo(session(served), expected).ok).toBe(
      true,
    );
    expect(
      parseGhidraAttachedSessionInfo(
        session([...served, "set_comment"]),
        expected,
      ).ok,
    ).toBe(false);
    expect(
      parseGhidraAttachedSessionInfo(session([...served, "ping"]), expected).ok,
    ).toBe(false);
    expect(
      parseGhidraAttachedSessionInfo(session(served), {
        ...expected,
        runId: "00000000-0000-4000-8000-000000000000",
      }).ok,
    ).toBe(false);
  });
});

describe("Ghidra attached analysis client", () => {
  const attachedSession = async () => {
    const bridge = await FakeAttachedBridge.start();
    cleanup.push(() => bridge.close());
    const ghidra = provider({
      REA_GHIDRA_ATTACH_ENDPOINT: bridge.endpointPath,
    });
    const target = elfTarget();
    const resolved = await ghidra.resolveAnalysisProfile(target);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected an attached profile");
    const client = ghidra.createClient(target, resolved.value.profile);
    cleanup.push(() => client.close());
    return { bridge, client, profile: resolved.value.profile };
  };

  it("serves cursor-default navigation as live Evidence of the observed Program", async () => {
    const { bridge, client, profile } = await attachedSession();
    expect(profile.parameters).toMatchObject({
      mode: "attached",
      endpoint: bridge.endpointPath,
    });
    bridge.reply = () => ({ result: "0x100004" });
    const next = await client.execute("next_address", {});
    if (!next.ok) throw next.error;
    expect(next.value.result).toBe("0x100004");
    expect(next.value.cachePolicy).toBe("live");
    expect(next.value.limitations).toContain(
      "Observed CodeBrowser Program /probe.elf in Ghidra 12.1.4: language AARCH64:LE:64:v8A, compiler default, image base 0x100000.",
    );
    expect(bridge.requests.at(-1)).toMatchObject({
      method: "next_address",
      params: { document: null, address: null },
    });
  });

  it("guides the analyst to start the bridge when none is serving", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-ghidra-attach-"));
    cleanup.push(() => rm(root, { recursive: true, force: true }));
    const ghidra = provider({
      REA_GHIDRA_ATTACH_ENDPOINT: join(root, "endpoint.json"),
    });
    const target = elfTarget();
    const resolved = await ghidra.resolveAnalysisProfile(target);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected an attached profile");
    const client = ghidra.createClient(target, resolved.value.profile);
    cleanup.push(() => client.close());
    const result = await client.execute("current_address", {});
    if (result.ok) throw new Error("expected a missing bridge");
    const projected = projectAnalysisError(result.error);
    expect(projected.message).toContain("ReaGhidraBridge.java");
    expect(projected.remediation?.action).toContain(
      "REA_GHIDRA_ATTACH_ENDPOINT",
    );
    expect(projected.remediation?.action).not.toContain("reconnects");
  });

  it("refuses edits before they reach the bridge and projects rejected navigation as input", async () => {
    const { bridge, client } = await attachedSession();
    const edit = await client.execute("set_comment", {
      address: "0x100000",
      comment: "note",
    });
    expect(edit.ok).toBe(false);
    if (!edit.ok)
      expect(edit.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(bridge.requests.some(({ method }) => method === "set_comment")).toBe(
      false,
    );
    bridge.reply = () => ({
      code: "invalid_request",
      message: "Address is outside every Ghidra memory block: 0x1",
    });
    const moved = await client.execute("goto_address", { address: "0x1" });
    expect(moved.ok).toBe(false);
    if (!moved.ok) expect(moved.error._tag).toBe("AnalysisInputError");
  });
});
