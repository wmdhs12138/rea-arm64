import type { Logger } from "pino";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import { analysisSettingLimit } from "../domain/analysisSettingDefinitions.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import { GhidraAttachedClient } from "./GhidraAttachedClient.js";
import {
  isGhidraFunctionOperation,
  parseGhidraFunctionInput,
  parseGhidraFunctionResult,
} from "./GhidraFunctionValues.js";
import {
  isGhidraInventoryOperation,
  parseGhidraInventoryInput,
  parseGhidraInventoryResult,
} from "./GhidraInventoryValues.js";
import { ghidraPePdbLimitations } from "./GhidraPeProfile.js";
import {
  attachedHealthLimitations,
  GHIDRA_ATTACH_REMEDIATION,
  limitationsFor,
} from "./GhidraProviderCapabilities.js";
import {
  ghidraFailureContext,
  projectGhidraRequestFailure,
  type GhidraExecutionMetadata,
} from "./GhidraProviderClient.js";
import type { GhidraSessionError } from "./GhidraSessionError.js";
import {
  GHIDRA_ATTACHED_OPERATIONS,
  type GhidraAttachedSessionInfo,
} from "./GhidraSessionValues.js";

/** Bound on reading the endpoint record, connecting, and the identity ping. */
export const GHIDRA_ATTACH_CONNECT_TIMEOUT_MS = 30_000;

/**
 * Adapter-scoped identity committed by attached profiles. The GUI's Ghidra
 * version is observed per connection and reported as a limitation instead.
 */
const ATTACHED_PROFILE_PROVIDER = Object.freeze({
  id: "ghidra",
  name: "Ghidra",
  version: "rea-attached-1",
});

/** Profile for one configured endpoint; the live database stays unbound. */
export const ghidraAttachedProfile = (
  endpointPath: string,
): AnalysisProfileCommitment =>
  createAnalysisProfile(ATTACHED_PROFILE_PROVIDER, {
    mode: "attached",
    version_scope: "rea-ghidra-attached-adapter",
    endpoint: endpointPath,
    cache_policy: "live",
  });

const attachedOperations: ReadonlySet<string> = new Set(
  GHIDRA_ATTACHED_OPERATIONS,
);

/** Production seam for exercising projection without a CodeBrowser. */
export type GhidraAttachedClientFactory = (
  options: ConstructorParameters<typeof GhidraAttachedClient>[0],
) => Pick<GhidraAttachedClient, "start" | "callTool" | "close">;

/** Build one AnalysisClient bound to a CodeBrowser-attached bridge. */
export const createGhidraAttachedProviderClient = (input: {
  readonly config: AppConfig;
  readonly endpointPath: string;
  readonly target: Extract<BinaryTarget, { readonly kind: "executable" }>;
  readonly profile: AnalysisProfileCommitment;
  readonly logger: Logger;
  readonly clientFactory?: GhidraAttachedClientFactory;
}): AnalysisClient => {
  const { config, target, profile } = input;
  const client = (
    input.clientFactory ?? ((options) => new GhidraAttachedClient(options))
  )({
    endpointPath: input.endpointPath,
    targetSha256: target.sha256,
    connectTimeoutMs: GHIDRA_ATTACH_CONNECT_TIMEOUT_MS,
    bridgeMaxRequestBytes: config.bridgeMaxRequestBytes,
    logger: input.logger.child({ layer: "ghidra-attached-bridge" }),
  });
  const observed = (info: GhidraAttachedSessionInfo): readonly string[] => [
    `Observed CodeBrowser Program ${info.target.project_path} in Ghidra ${info.provider.version}: language ${info.target.language_id}, compiler ${info.target.compiler_spec_id}, image base ${info.target.image_base}.`,
    ...(target.format === "pe" ? ghidraPePdbLimitations(target, info.pdb) : []),
  ];
  return {
    execute: async (operation, parameters, options) => {
      const signal = options?.signal;
      const started = await client.start(signal);
      if (!started.ok)
        return err(projectAttachedFailure(operation, started.error, config));
      if (operation === "health")
        return ok(
          createAnalysisExecution(started.value, profile.provider, {
            analysisProfile: profile,
            cachePolicy: "live",
            limitations: [
              ...attachedHealthLimitations,
              ...observed(started.value),
            ],
          }),
        );
      if (
        !attachedOperations.has(operation) ||
        (!isGhidraFunctionOperation(operation) &&
          !isGhidraInventoryOperation(operation))
      )
        return err(
          new AnalysisCapabilityUnavailableError(
            "ghidra",
            operation,
            "Ghidra attached mode serves the CodeBrowser Program read-only and does not declare this operation.",
          ),
        );
      const input = isGhidraFunctionOperation(operation)
        ? parseGhidraFunctionInput(operation, parameters)
        : parseGhidraInventoryInput(operation, parameters, { cursor: true });
      if (!input.ok) return input;
      const called = await client.callTool(operation, input.value, {
        decompileTimeoutSeconds: config.ghidraDecompileTimeoutSeconds ?? null,
        ...(signal === undefined ? {} : { signal }),
      });
      if (!called.ok)
        return err(projectAttachedFailure(operation, called.error, config));
      const result = isGhidraFunctionOperation(operation)
        ? parseGhidraFunctionResult(operation, called.value)
        : parseGhidraInventoryResult(operation, called.value);
      if (!result.ok) return result;
      const { value, ...parsed } = result.value;
      const observation: GhidraExecutionMetadata = parsed;
      return ok(
        createAnalysisExecution(value, profile.provider, {
          ...observation,
          cachePolicy: "live",
          analysisProfile: profile,
          limitations: [
            ...limitationsFor(operation, "attached"),
            ...(observation.limitations ?? []),
            ...observed(started.value),
          ],
        }),
      );
    },
    close: () => client.close(),
  };
};

/** Lifecycle failures name the user-owned GUI task; REA never restarts it. */
const projectAttachedFailure = (
  operation: AnalysisOperation,
  failure: GhidraSessionError,
  limits: Pick<AppConfig, "ghidraDecompileTimeoutSeconds">,
): AnalysisError => {
  const request = projectGhidraRequestFailure(operation, failure);
  if (request !== undefined) return request;
  const context = ghidraFailureContext(failure);
  // A failed first connection never reached a bridge; a lost one may have.
  const recovery =
    failure.kind === "start"
      ? GHIDRA_ATTACH_REMEDIATION
      : `REA disconnected; while the CodeBrowser task still runs, the next request reconnects. Otherwise: ${GHIDRA_ATTACH_REMEDIATION}`;
  if (
    failure.kind === "cancelled" ||
    (failure.kind === "remote" && failure.remoteCode === "decompile_cancelled")
  )
    return new AnalysisCancelledError(operation, {
      ...context,
      cause:
        failure.cancellation === undefined
          ? failure
          : failure.cancellation.reason,
    });
  if (failure.kind === "remote" && failure.remoteCode === "decompile_failed")
    return new ProviderAdapterError("ghidra", operation, {
      ...context,
      userMessage: `${failure.message.trim().replace(/\.$/u, "")}. Only the decompiler failed for this procedure; the attached bridge remains usable.`,
      remediationAction:
        "Call analyze_function (CLI: `rea function`) for listing facts; repeating the unchanged decompile request is not expected to succeed.",
    });
  if (
    failure.kind === "remote" &&
    failure.remoteCode === "decompile_timed_out" &&
    limits.ghidraDecompileTimeoutSeconds !== undefined
  )
    return new AnalysisTimeoutError(
      operation,
      limits.ghidraDecompileTimeoutSeconds * 1000,
      {
        ...context,
        limit: analysisSettingLimit(
          "ghidra.decompile_timeout_seconds",
          limits.ghidraDecompileTimeoutSeconds,
          undefined,
        ),
        remediationAction:
          "Use analyze_function for listing facts, or raise ghidra.decompile_timeout_seconds with update_analysis_settings.",
      },
    );
  if (
    failure.kind === "remote" &&
    failure.remoteCode === "regex_stack_exhausted"
  )
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      `${failure.message.trim().replace(/\.$/u, "")}. The attached bridge remains usable.`,
      null,
      {
        ...context,
        remediationAction:
          "Retry this search in literal mode or simplify the regex.",
      },
    );
  if (failure.kind === "remote" && failure.remoteCode === "analysis_incomplete")
    return new ProviderAdapterError("ghidra", operation, {
      ...context,
      userMessage: failure.message,
      remediationAction:
        "Finish or run Ghidra auto-analysis in the CodeBrowser, then retry; REA does not start analysis in an analyst's Program.",
    });
  if (failure.kind === "timeout")
    return new AnalysisTimeoutError(
      operation,
      failure.timeoutMs ?? GHIDRA_ATTACH_CONNECT_TIMEOUT_MS,
      { ...context, remediationAction: recovery },
    );
  return new ProviderAdapterError("ghidra", operation, {
    ...context,
    userMessage:
      failure.kind === "remote" ? failure.message : `${failure.message}.`,
    remediationAction: recovery,
  });
};

/** Owning admission check shared with the headless client factory. */
export const admitGhidraAttachedProfile = (
  profile: AnalysisProfileCommitment | undefined,
  endpointPath: string,
): Result<AnalysisProfileCommitment, AnalysisError> =>
  profile !== undefined &&
  profile.digest === ghidraAttachedProfile(endpointPath).digest
    ? ok(profile)
    : err(
        new ProviderAdapterError("ghidra", "health", {
          diagnostics: {
            reason:
              "The selected profile does not match REA_GHIDRA_ATTACH_ENDPOINT; reopen the target to resolve the attached profile.",
          },
        }),
      );
