import { nativeSymbolMetadataSchema } from "../domain/native/nativeSymbol.js";
import { nativeAddressObservationSchema } from "../domain/native/nativeAddress.js";
import { nativeByteReadSchema } from "../domain/native/nativeByteRead.js";
import { z } from "zod";
import {
  bytePatternFields,
  validateBytePattern,
  byteSearchResultSchema,
} from "../domain/native/bytePattern.js";
import {
  nativeLoadImageObservationSchema,
  type NativeLoadImageObservation,
} from "../domain/native/nativeLoadImage.js";

import {
  type AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import {
  functionBodySchema,
  functionBodyEntryAgrees,
  projectBinaryOverview,
} from "../domain/hopperValues.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";

/**
 * Direct inventory operations admitted by the Ghidra adapter. All are reads
 * except metadata operations, which edit the ephemeral session database, and
 * goto_address, which moves an attached CodeBrowser cursor.
 */
export const GHIDRA_INVENTORY_OPERATIONS = [
  "read_binary_inventory_summary",
  "inspect_native_load_image",
  "read_bytes",
  "search_bytes",
  "address_to_file_offset",
  "address_name",
  "current_document",
  "comment",
  "inline_comment",
  "list_bookmarks",
  "set_comment",
  "set_inline_comment",
  "set_bookmark",
  "unset_bookmark",
  "list_documents",
  "list_names",
  "list_procedures",
  "list_segments",
  "list_strings",
  "procedure_address",
  "resolve_containing_procedure",
  "search_procedures",
  "search_strings",
  "set_address_name",
  "set_addresses_names",
  "next_address",
  "prev_address",
  "current_address",
  "current_procedure",
  "goto_address",
] as const;

/** Inventory operations that edit analyst metadata in the ephemeral database. */
export const GHIDRA_INVENTORY_MUTATIONS = [
  "set_address_name",
  "set_addresses_names",
  "set_comment",
  "set_inline_comment",
  "set_bookmark",
  "unset_bookmark",
] as const satisfies readonly GhidraInventoryOperation[];

/** Cursor-state operations that only a CodeBrowser-attached bridge serves. */
export const GHIDRA_ATTACHED_CURSOR_OPERATIONS = [
  "current_address",
  "current_procedure",
  "goto_address",
] as const satisfies readonly GhidraInventoryOperation[];

/** One direct inventory operation implemented by the packaged Java bridge. */
export type GhidraInventoryOperation =
  (typeof GHIDRA_INVENTORY_OPERATIONS)[number];

const operationSet: ReadonlySet<string> = new Set(GHIDRA_INVENTORY_OPERATIONS);

/** Narrow an application operation to the Ghidra inventory surface. */
export const isGhidraInventoryOperation = (
  operation: string,
): operation is GhidraInventoryOperation => operationSet.has(operation);

export const ghidraIdentifierSchema = z.string().min(1);
const identifier = ghidraIdentifierSchema;
const document = identifier.nullable().default(null);
/** Caller address spelling; the bridge resolves its space and emits canonical output. */
export const ghidraInputAddressSchema = z
  .string()
  .regex(
    /^(?:(?:0[xX])?[0-9a-fA-F]+|(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+:0[xX][0-9a-fA-F]+)$/u,
    "Use hexadecimal digits, optionally prefixed with 0x, or an encoded address-space name followed by :0x and hexadecimal digits",
  );
const explicitAddress = ghidraInputAddressSchema;
const filteredAddress = explicitAddress.nullable().default(null);
/** Null selects the attached CodeBrowser cursor; headless input requires an address. */
const navigationInput = z
  .object({ document, address: explicitAddress.nullable().default(null) })
  .strict();
const headlessNavigationInput = z
  .object({ document, address: explicitAddress })
  .strict();
const CURSOR_DEFAULT_OPERATIONS: ReadonlySet<string> = new Set([
  "next_address",
  "prev_address",
]);
const searchInput = {
  pattern: z.string().min(1),
  mode: z.enum(["literal", "regex"]).default("literal"),
  case_sensitive: z.boolean().default(false),
  document,
};

const inputSchemas = {
  read_binary_inventory_summary: z.strictObject({}),
  search_bytes: z
    .strictObject({
      ...bytePatternFields,
      document,
      start: explicitAddress.optional(),
      end: explicitAddress.optional(),
      limit: z.int().min(1).max(1000).default(100),
      cursor: z.string().min(1).optional(),
    })
    .superRefine(validateBytePattern),
  inspect_native_load_image: z.strictObject({}),
  read_bytes: z.strictObject({
    document,
    address: explicitAddress,
    length: z.int().min(1).max(Number.MAX_SAFE_INTEGER).default(256),
  }),
  address_to_file_offset: z.strictObject({
    document,
    address: explicitAddress,
  }),
  address_name: z.object({ document, address: explicitAddress }).strict(),
  current_document: z.object({}).strict(),
  comment: z.object({ document, address: explicitAddress }).strict(),
  inline_comment: z.object({ document, address: explicitAddress }).strict(),
  list_bookmarks: z.object({ document }).strict(),
  set_comment: z
    .object({ document, address: explicitAddress, comment: z.string() })
    .strict(),
  set_inline_comment: z
    .object({ document, address: explicitAddress, comment: z.string() })
    .strict(),
  set_bookmark: z
    .object({
      document,
      address: explicitAddress,
      name: z.string().exactOptional(),
    })
    .strict(),
  unset_bookmark: z.object({ document, address: explicitAddress }).strict(),
  list_documents: z.object({}).strict(),
  list_names: z.object({ document, address: filteredAddress }).strict(),
  list_procedures: z.object({ document }).strict(),
  list_segments: z.object({ document }).strict(),
  list_strings: z.object({ document, address: filteredAddress }).strict(),
  procedure_address: z.object({ document, procedure: identifier }).strict(),
  resolve_containing_procedure: z
    .object({ document, address: explicitAddress })
    .strict(),
  search_procedures: z.object(searchInput).strict(),
  search_strings: z.object(searchInput).strict(),
  next_address: navigationInput,
  prev_address: navigationInput,
  current_address: z.object({ document }).strict(),
  current_procedure: z.object({ document }).strict(),
  goto_address: z.object({ document, address: explicitAddress }).strict(),
  set_address_name: z
    .object({ document, address: explicitAddress, name: z.string().min(1) })
    .strict(),
  set_addresses_names: z
    .object({
      document,
      names: z.record(explicitAddress, z.string().min(1)),
    })
    .strict()
    .refine(
      (value) => Object.keys(value.names).length > 0,
      "Supply at least one address name",
    ),
} satisfies Readonly<Record<GhidraInventoryOperation, z.ZodType>>;

/**
 * Validate and default one provider request before it crosses the socket.
 * Only an attached bridge has a cursor to stand in for an omitted address.
 */
export const parseGhidraInventoryInput = (
  operation: GhidraInventoryOperation,
  value: Readonly<Record<string, JsonValue>>,
  options: { readonly cursor?: boolean } = {},
): Result<Readonly<Record<string, JsonValue>>, AnalysisInputError> => {
  const schema =
    options.cursor !== true && CURSOR_DEFAULT_OPERATIONS.has(operation)
      ? headlessNavigationInput
      : inputSchemas[operation];
  const parsed = schema.safeParse(value);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(operation, parsed.error.issues, value, {
        cause: parsed.error,
      }),
    );
  return ok(parsed.data);
};

const symbolFacts = z
  .object({
    primary: z.boolean(),
    dynamic: z.boolean(),
    external: z.boolean(),
    type: z.string().min(1),
    source: z.enum(["default", "analysis", "ai", "imported", "user_defined"]),
  })
  .strict();
const procedureFacts = z
  .object({
    external: z.boolean(),
    thunk: z.boolean(),
    thunk_target: nativeAddressObservationSchema.nullable(),
  })
  .strict();
/** Ghidra FunctionManager classification, independent of body ownership inference. */
export const ghidraFunctionClassificationSchema = procedureFacts
  .extend({ provenance: z.literal("ghidra-function-manager") })
  .strict();
/** Require complete canonical AddressSet evidence on every Ghidra function identity. */
export const ghidraFunctionBodySchema = functionBodySchema.superRefine(
  (body, context) => {
    if (
      !body.available ||
      body.provenance !== "ghidra-function-body-address-set" ||
      body.ranges.some(
        ({ start, end }) =>
          !nativeAddressObservationSchema.safeParse(start).success ||
          !nativeAddressObservationSchema.safeParse(end).success,
      )
    )
      context.addIssue({
        code: "custom",
        message:
          "Ghidra omitted complete canonical function-body AddressSet evidence",
      });
  },
);

/** Strict provider identity shared by inventory and function-analysis results. */
export const ghidraProcedureIdentitySchema = z
  .object({
    address: nativeAddressObservationSchema,
    name: z.string().min(1),
    symbol: nativeSymbolMetadataSchema.nullable(),
    classification: ghidraFunctionClassificationSchema,
    body: ghidraFunctionBodySchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      !functionBodyEntryAgrees(value.body, value.address) ||
      (value.body.available &&
        !value.classification.external &&
        !value.body.contains_entry)
    )
      context.addIssue({
        code: "custom",
        message: "Ghidra function body disagrees with its entry point",
      });
  });

const stringFacts = z
  .object({
    encoding: z.string().min(1),
    termination: z.enum(["missing", "present_or_not_required"]),
    byte_length: z.int().min(0),
  })
  .strict();
const baseItem = {
  address: nativeAddressObservationSchema,
  value: z.string(),
};
const symbolItem = z.object({ ...baseItem, symbol: symbolFacts }).strict();
const addressedItem = z
  .object({ ...baseItem, symbol: symbolFacts.exactOptional() })
  .strict();
const procedureItem = addressedItem.extend({ procedure: procedureFacts });
const stringItem = z.object({ ...baseItem, string: stringFacts }).strict();

const availablePermissions = z
  .object({
    available: z.literal(true),
    source: z.literal("ghidra-memory-block"),
  })
  .strict();
const memoryRegion = z
  .object({
    name: z.string(),
    start: nativeAddressObservationSchema,
    end: nativeAddressObservationSchema,
    readable: z.boolean(),
    writable: z.boolean(),
    executable: z.boolean(),
    permissions: availablePermissions,
    provenance: z.literal("ghidra-memory-block"),
    address_space: z.string().min(1),
    image_base: nativeAddressObservationSchema,
    initialized: z.boolean(),
    overlay: z.boolean(),
  })
  .strict();
const segment = memoryRegion
  .extend({ sections: z.array(memoryRegion) })
  .strict();
const containingProcedure = z.discriminatedUnion("found", [
  z
    .object({
      query_address: nativeAddressObservationSchema,
      found: z.literal(true),
      procedure: ghidraProcedureIdentitySchema,
    })
    .strict()
    .superRefine((value, context) => {
      const body = value.procedure.body;
      const exactExternalEntry =
        value.procedure.classification.external &&
        value.query_address === value.procedure.address;
      if (
        !exactExternalEntry &&
        body.available &&
        !functionBodyEntryAgrees(
          { ...body, contains_entry: true },
          value.query_address,
        )
      )
        context.addIssue({
          code: "custom",
          message:
            "Found containing procedure body does not contain the query address",
        });
    }),
  z
    .object({
      query_address: nativeAddressObservationSchema,
      found: z.literal(false),
      procedure: z.null(),
      reason: z.enum(["outside_segments", "not_in_procedure"]),
    })
    .strict(),
]);

const resultSchemas = {
  read_binary_inventory_summary: z
    .strictObject({
      document: identifier,
      segments: z.array(segment),
      procedure_count: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
      string_count: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
    })
    .transform(projectBinaryOverview),
  search_bytes: byteSearchResultSchema.superRefine((value, context) => {
    const addresses = [
      ...value.matches.flatMap((match) => [
        match.address,
        ...(match.procedure === null ? [] : [match.procedure.address]),
      ]),
      ...[
        ...value.searched.blocks,
        ...value.searched.skipped_uninitialized,
        ...value.searched.skipped_not_loaded,
      ].flatMap((block) => [block.start, block.end]),
    ];
    if (
      addresses.some(
        (value) => !nativeAddressObservationSchema.safeParse(value).success,
      )
    )
      context.addIssue({
        code: "custom",
        message: "Byte search addresses must be canonical",
      });
  }),
  inspect_native_load_image: nativeLoadImageObservationSchema,
  read_bytes: nativeByteReadSchema
    .safeExtend({ address: nativeAddressObservationSchema })
    .strict(),
  address_to_file_offset: z.strictObject({
    address: nativeAddressObservationSchema,
    file_offset: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
  }),
  address_name: z.string().nullable(),
  current_document: identifier,
  comment: z.string().nullable(),
  inline_comment: z.string().nullable(),
  list_bookmarks: z.array(
    z.strictObject({
      address: nativeAddressObservationSchema,
      name: z.string().nullable(),
    }),
  ),
  set_comment: z.boolean(),
  set_inline_comment: z.boolean(),
  set_bookmark: z.boolean(),
  unset_bookmark: z.boolean(),
  list_documents: z.array(z.string().min(1)).length(1),
  list_names: z.array(symbolItem),
  list_procedures: z.array(procedureItem),
  list_segments: z.array(segment),
  list_strings: z.array(stringItem),
  procedure_address: nativeAddressObservationSchema,
  resolve_containing_procedure: containingProcedure,
  search_procedures: z.array(addressedItem),
  search_strings: z.array(addressedItem),
  set_address_name: z.boolean(),
  set_addresses_names: z.record(z.string(), z.boolean()),
  next_address: nativeAddressObservationSchema,
  prev_address: nativeAddressObservationSchema,
  current_address: nativeAddressObservationSchema,
  current_procedure: identifier,
  goto_address: nativeAddressObservationSchema,
} satisfies Readonly<Record<GhidraInventoryOperation, z.ZodType>>;

/** The format owner retains raw output only when projection omits reported facts. */
export interface ParsedGhidraInventoryResult<Value = JsonValue> {
  readonly value: Value;
  readonly rawResult?: JsonValue;
}

/** Validate exact Java-bridge output and own its Evidence representation. */
export function parseGhidraInventoryResult(
  operation: "inspect_native_load_image",
  value: JsonValue,
): Result<
  ParsedGhidraInventoryResult<NativeLoadImageObservation>,
  AnalysisOutputError
>;
export function parseGhidraInventoryResult(
  operation: GhidraInventoryOperation,
  value: JsonValue,
): Result<ParsedGhidraInventoryResult, AnalysisOutputError>;
export function parseGhidraInventoryResult(
  operation: GhidraInventoryOperation,
  value: JsonValue,
): Result<
  ParsedGhidraInventoryResult<JsonValue | NativeLoadImageObservation>,
  AnalysisOutputError
> {
  if (operation === "inspect_native_load_image") {
    const parsed = resultSchemas.inspect_native_load_image.safeParse(value);
    return parsed.success
      ? ok({ value: parsed.data, rawResult: value })
      : err(inventoryOutputFailure(operation, parsed.error));
  }
  const parsed = resultSchemas[operation].safeParse(value);
  return parsed.success
    ? ok({
        value: jsonValueSchema.parse(parsed.data),
        // The overview omits detailed segment permissions, sections and provenance.
        // Load-image observations above undergo separate local attestation.
        ...(operation === "read_binary_inventory_summary"
          ? { rawResult: value }
          : {}),
      })
    : err(inventoryOutputFailure(operation, parsed.error));
}

const inventoryOutputFailure = (
  operation: GhidraInventoryOperation,
  cause: unknown,
): AnalysisOutputError =>
  new AnalysisOutputError(
    operation,
    "Ghidra bridge output did not match the inventory contract",
    { cause },
  );
