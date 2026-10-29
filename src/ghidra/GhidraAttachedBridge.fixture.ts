import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { JsonValue } from "../domain/jsonValue.js";
import { GHIDRA_ATTACHED_OPERATIONS } from "./GhidraSessionValues.js";

export const TARGET_SHA256 = "a".repeat(64);

export type Reply =
  | { readonly result: JsonValue }
  | { readonly code: string; readonly message: string }
  | "hold";

export interface BridgeRequest {
  readonly id: number;
  readonly token: string;
  readonly method: string;
  readonly params: JsonValue;
}

/** Simulated CodeBrowser bridge that speaks the Java bridge's line protocol. */
export class FakeAttachedBridge {
  readonly token = randomBytes(32).toString("hex");
  readonly runId = randomUUID();
  readonly requests: BridgeRequest[] = [];
  readonly sockets: Socket[] = [];
  closedConnections = 0;
  sha256 = TARGET_SHA256;
  analysis = { analyzed: true, active: false };
  reply: (request: BridgeRequest) => Reply = () => ({ result: "0x100000" });
  readonly #server: Server;

  private constructor(
    readonly root: string,
    readonly endpointPath: string,
  ) {
    this.#server = createServer((socket) => this.#serve(socket));
  }

  static async start(): Promise<FakeAttachedBridge> {
    const root = await mkdtemp(join(tmpdir(), "rea-ghidra-attach-"));
    const bridge = new FakeAttachedBridge(root, join(root, "endpoint.json"));
    const socketPath = join(root, "bridge.sock");
    await new Promise<void>((resolve) =>
      bridge.#server.listen(socketPath, resolve),
    );
    await writeFile(
      bridge.endpointPath,
      `${JSON.stringify({
        schema: "rea-ghidra-attach-v1",
        transport: "unix-socket",
        socket_path: socketPath,
        token: bridge.token,
        run_id: bridge.runId,
      })}\n`,
      { mode: 0o600 },
    );
    return bridge;
  }

  ping(): JsonValue {
    return {
      name: "REA Ghidra bridge",
      mode: "attached",
      run_id: this.runId,
      provider: { id: "ghidra", version: "12.1.4" },
      read_only: true,
      analysis: this.analysis,
      capabilities: ["ping", ...GHIDRA_ATTACHED_OPERATIONS],
      target: {
        name: "probe.elf",
        language_id: "AARCH64:LE:64:v8A",
        compiler_spec_id: "default",
        image_base: "0x100000",
        default_address_space: "ram",
        sha256: this.sha256,
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
    };
  }

  dropConnections(): void {
    for (const socket of this.sockets) socket.destroy();
  }

  async close(): Promise<void> {
    this.dropConnections();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
    await rm(this.root, { recursive: true, force: true });
  }

  #serve(socket: Socket): void {
    this.sockets.push(socket);
    socket.setEncoding("utf8");
    socket.on("close", () => {
      this.closedConnections += 1;
    });
    let buffered = "";
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      for (;;) {
        const newline = buffered.indexOf("\n");
        if (newline < 0) return;
        const request = JSON.parse(buffered.slice(0, newline)) as BridgeRequest;
        buffered = buffered.slice(newline + 1);
        this.requests.push(request);
        if (request.token !== this.token) {
          socket.destroy();
          return;
        }
        const reply =
          request.method === "ping"
            ? { result: this.ping() }
            : this.reply(request);
        if (reply === "hold") continue;
        socket.write(
          `${JSON.stringify(
            "result" in reply
              ? { id: request.id, ok: true, result: reply.result }
              : {
                  id: request.id,
                  ok: false,
                  error: { code: reply.code, message: reply.message },
                },
          )}\n`,
        );
      }
    });
  }
}

/** Poll until the bridge has observed one request for this method. */
export const nextRequest = async (
  bridge: FakeAttachedBridge,
  method: string,
): Promise<BridgeRequest> => {
  for (;;) {
    const found = bridge.requests.find((request) => request.method === method);
    if (found !== undefined) return found;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};
