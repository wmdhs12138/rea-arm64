import { createConnection, type Socket } from "node:net";
import type { Logger } from "pino";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  DEFAULT_BRIDGE_MAX_REQUEST,
  type BridgeMaxRequestBytes,
} from "../config/bridgeMaxRequestBytes.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import { DecodedNdjsonLineBuffer } from "../process/DecodedNdjsonLineBuffer.js";
import { PendingOperations } from "../process/PendingOperations.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";
import { redactCapturedTransportCredential } from "../process/ProviderDiagnosticRedaction.js";
import { SharedStartupAttempt } from "../process/SharedStartupAttempt.js";
import { GhidraWire } from "./GhidraClientWire.js";
import { GhidraRequestQueue } from "./GhidraRequestQueue.js";
import { GhidraResponseRouter } from "./GhidraResponseRouter.js";
import {
  bindGhidraSessionFailure,
  type GhidraSessionError,
  type GhidraSessionFailureKind,
} from "./GhidraSessionError.js";
import {
  parseGhidraAttachedSessionInfo,
  type GhidraAttachedSessionInfo,
} from "./GhidraSessionValues.js";
import {
  readGhidraAttachedEndpoint,
  type GhidraAttachedEndpoint,
} from "./GhidraTransport.js";

/** Inputs for connecting to one CodeBrowser-attached bridge. */
export interface GhidraAttachedClientOptions {
  /** Record published by ReaGhidraBridge.java; REA reads but never writes it. */
  readonly endpointPath: string;
  readonly targetSha256: string;
  /** Bound on reading the record, connecting, and the identity handshake. */
  readonly connectTimeoutMs: number;
  readonly bridgeMaxRequestBytes?: BridgeMaxRequestBytes;
  readonly logger?: Logger;
}

type AttachedStartResult = Result<
  GhidraAttachedSessionInfo,
  GhidraSessionError
>;

/**
 * Serial requests to a bridge served from a user-launched CodeBrowser. The
 * client owns only its connection: close and cancellation disconnect without
 * stopping the GUI task, and the next request reconnects and re-verifies.
 */
export class GhidraAttachedClient {
  readonly #options: GhidraAttachedClientOptions;
  readonly #logger: Logger;
  readonly #pending = new PendingOperations<
    number,
    Result<JsonValue, GhidraSessionError>
  >();
  readonly #fileResources = new ArtifactResourceScope();
  readonly #lines = new DecodedNdjsonLineBuffer();
  readonly #tokens = new Set<string>();
  #socket: Socket | undefined;
  #endpoint: GhidraAttachedEndpoint | undefined;
  #nextId = 1;
  #connection: SharedStartupAttempt<AttachedStartResult> | undefined;
  readonly #failure = bindGhidraSessionFailure(
    () => this.#diagnostics(),
    (value, incomplete) => this.#redact(value, incomplete),
  );
  readonly #wire: GhidraWire;
  readonly #queue: GhidraRequestQueue;
  readonly #router: GhidraResponseRouter;

  constructor(options: GhidraAttachedClientOptions) {
    this.#options = options;
    this.#logger = options.logger ?? silentLogger;
    this.#wire = new GhidraWire({
      getSocket: () => this.#socket,
      getToken: () => this.#endpoint?.token,
      nextId: () => this.#nextId++,
      pending: this.#pending,
      logger: this.#logger,
      failure: this.#failure,
      bridgeMaxRequestBytes:
        options.bridgeMaxRequestBytes ?? DEFAULT_BRIDGE_MAX_REQUEST,
    });
    this.#queue = new GhidraRequestQueue(
      (method, parameters, requestOptions) =>
        this.#wire.request(method, parameters, requestOptions),
      this.#failure,
      // Java cannot interrupt the GUI task's request; dropping the connection
      // releases the caller, and the bridge discards the late reply.
      () => {
        this.#disconnect(
          "process",
          "REA disconnected from the Ghidra attached bridge after cancellation",
        );
        return Promise.resolve(ok(null));
      },
    );
    this.#router = new GhidraResponseRouter({
      pending: this.#pending,
      nextId: () => this.#nextId,
      remoteFailure: (failure) =>
        this.#failure("remote", failure.message, failure, {
          remoteCode: failure.code,
        }),
      protocolFailure: (message, cause) =>
        this.#disconnect("protocol", message, cause),
    });
  }

  /** Connect and verify identity once; later calls reuse a live connection. */
  async start(signal?: AbortSignal): Promise<AttachedStartResult> {
    let attempt = this.#connection;
    if (
      attempt === undefined ||
      (attempt.settled && !this.#connectedThrough(attempt))
    ) {
      attempt = new SharedStartupAttempt((owner) => this.#connect(owner));
      this.#connection = attempt;
    }
    const waited = await attempt.wait(signal);
    if (waited.status !== "cancelled") return waited.value;
    return err(
      this.#failure(
        "cancelled",
        "Ghidra attached connection wait was cancelled",
        signal?.reason,
        { cancellation: { reason: signal?.reason } },
      ),
    );
  }

  /** Execute one operation after the current connection's handshake. */
  async callTool(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    options: {
      readonly signal?: AbortSignal;
      readonly decompileTimeoutSeconds?: number | null;
    } = {},
  ): Promise<Result<JsonValue, GhidraSessionError>> {
    const started = await this.start(options.signal);
    if (!started.ok) return started;
    return this.#queue.run(operation, parameters, options);
  }

  /** Disconnect; the CodeBrowser and its bridge task keep running. */
  async close(): Promise<Result<null, AnalysisError>> {
    this.#connection?.close();
    await this.#connection?.promise.catch(() => undefined);
    this.#connection = undefined;
    this.#disconnect("process", "The Ghidra attached client was closed");
    try {
      await this.#fileResources.retryCleanup();
      return ok(null);
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          "ghidra",
          this.#fileResources.cleanupResources,
          {
            reason: "Ghidra attached endpoint read cleanup remains incomplete",
          },
          { cause },
        ),
      );
    }
  }

  async #connect(owner: AbortSignal): Promise<AttachedStartResult> {
    this.#disconnect("process", "Ghidra attached bridge is reconnecting");
    const deadline = new ProviderStartupDeadline(
      this.#options.connectTimeoutMs,
      owner,
    );
    try {
      const endpoint = await readGhidraAttachedEndpoint(
        this.#options.endpointPath,
        { signal: deadline.signal, resourceScope: this.#fileResources },
      );
      if (!endpoint.ok)
        return err(this.#interrupted(deadline) ?? endpoint.error);
      this.#endpoint = endpoint.value;
      this.#tokens.add(endpoint.value.token);
      const socket = await connectSocket(
        endpoint.value.socket_path,
        deadline.signal,
      );
      if (!socket.ok)
        return err(
          this.#interrupted(deadline) ??
            this.#failure(
              "start",
              "The Ghidra attached bridge is not accepting connections; restart bridge/ghidra/ReaGhidraBridge.java from the CodeBrowser Script Manager",
              socket.error,
            ),
        );
      this.#attach(socket.value);
      this.#queue.reopen();
      const ping = await this.#wire.request(
        "ping",
        {},
        { signal: deadline.signal, timeoutMs: deadline.remainingMs() },
      );
      if (!ping.ok)
        return this.#rejected(this.#interrupted(deadline) ?? ping.error);
      const info = parseGhidraAttachedSessionInfo(ping.value, {
        runId: endpoint.value.run_id,
        targetSha256: this.#options.targetSha256,
      });
      if (!info.ok)
        return this.#rejected(
          this.#failure("start", info.error.message, info.error),
        );
      if (!info.value.analysis.analyzed || info.value.analysis.active)
        return this.#rejected(
          this.#failure(
            "remote",
            info.value.analysis.active
              ? "Ghidra auto-analysis is still running in the CodeBrowser; retry after it finishes"
              : "The CodeBrowser Program has not been auto-analyzed; run Analysis > Auto Analyze first",
            undefined,
            { remoteCode: "analysis_incomplete" },
          ),
        );
      return ok(info.value);
    } finally {
      deadline.dispose();
    }
  }

  #interrupted(
    deadline: ProviderStartupDeadline,
  ): GhidraSessionError | undefined {
    if (deadline.interruption === "cancelled")
      return this.#failure(
        "cancelled",
        "Ghidra attached connection was cancelled",
        deadline.signal.reason,
        { cancellation: { reason: deadline.signal.reason } },
      );
    if (deadline.interruption === "timeout")
      return this.#failure(
        "timeout",
        "The Ghidra attached bridge did not complete its handshake in time",
        undefined,
        { timeoutMs: this.#options.connectTimeoutMs },
      );
    return undefined;
  }

  #rejected(failure: GhidraSessionError): AttachedStartResult {
    this.#disconnect(failure.kind, failure.message);
    return err(failure);
  }

  #connectedThrough(
    attempt: SharedStartupAttempt<AttachedStartResult>,
  ): boolean {
    const settlement = attempt.settlement;
    return (
      settlement.status === "completed" &&
      settlement.value.ok &&
      this.#socket !== undefined &&
      !this.#socket.destroyed
    );
  }

  #attach(socket: Socket): void {
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      if (this.#socket !== socket) return;
      for (const line of this.#lines.push(chunk)) this.#router.route(line);
    });
    socket.on("error", () => {
      if (this.#socket === socket)
        this.#disconnect("process", "Ghidra attached bridge socket failed");
    });
    socket.on("close", () => {
      if (this.#socket === socket)
        this.#disconnect(
          "process",
          "The Ghidra attached bridge closed the connection; its CodeBrowser task may have stopped",
        );
    });
    this.#socket = socket;
  }

  /** Fail outstanding work for the current connection and release its socket. */
  #disconnect(
    kind: GhidraSessionFailureKind,
    message: string,
    cause?: unknown,
  ): void {
    const socket = this.#socket;
    this.#socket = undefined;
    this.#lines.reset();
    const failure = this.#failure(kind, message, cause);
    this.#queue.failQueued(failure);
    this.#pending.failAll(() => err(failure));
    socket?.destroy();
  }

  #redact(value: string, incomplete = false): string {
    for (const token of this.#tokens) {
      const bytes = Buffer.byteLength(value);
      value = redactCapturedTransportCredential(
        { text: value, bytes, observedBytes: bytes + (incomplete ? 1 : 0) },
        token,
        "[REDACTED]",
      );
    }
    return value;
  }

  #diagnostics(): Readonly<Record<string, JsonValue>> {
    return {
      mode: "attached",
      endpoint_path: this.#options.endpointPath,
      ...(this.#endpoint === undefined
        ? {}
        : {
            socket_path: this.#endpoint.socket_path,
            run_id: this.#endpoint.run_id,
          }),
    };
  }
}

const connectSocket = (
  path: string,
  signal: AbortSignal,
): Promise<Result<Socket, Error>> =>
  new Promise((resolve) => {
    const socket = createConnection(path);
    const detach = (): void => {
      socket.off("connect", onConnect);
      socket.off("error", onError);
      signal.removeEventListener("abort", onAbort);
    };
    const onConnect = (): void => {
      detach();
      resolve(ok(socket));
    };
    const onError = (cause: Error): void => {
      detach();
      socket.destroy();
      resolve(err(cause));
    };
    const onAbort = (): void => {
      detach();
      socket.destroy();
      resolve(err(new Error("Ghidra attached connection was interrupted")));
    };
    socket.once("connect", onConnect);
    socket.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
