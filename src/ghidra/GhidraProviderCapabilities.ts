import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import {
  inspectWindowsNativeReadiness,
  type WindowsNativeReadiness,
} from "../process/WindowsAuthority.js";
import { GHIDRA_FUNCTION_OPERATIONS } from "./GhidraFunctionValues.js";
import {
  GHIDRA_ATTACHED_CURSOR_OPERATIONS,
  GHIDRA_INVENTORY_OPERATIONS,
} from "./GhidraInventoryValues.js";
import {
  GHIDRA_ATTACHED_OPERATIONS,
  GHIDRA_MUTATING_OPERATIONS,
} from "./GhidraSessionValues.js";

/** Target architectures admitted by the Windows P0 native PE boundary. */
export const WINDOWS_P0_NATIVE_PE_ARCHITECTURES: readonly string[] =
  Object.freeze(["x86", "x86_64", "arm", "arm64"]);

/** Public identity committed by every Ghidra-backed observation. */
export const GHIDRA_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "ghidra",
  name: "Ghidra",
  version: null,
});

/** Provider observations, including internal aggregates consumed by workflows. */
const providerOperations = Object.freeze([
  ...GHIDRA_INVENTORY_OPERATIONS,
  ...GHIDRA_FUNCTION_OPERATIONS,
]);

/** Public analyst tools backed by these observations; aggregates stay internal. */
export const GHIDRA_OPERATIONS = Object.freeze(
  providerOperations.map((operation) =>
    operation === "read_binary_inventory_summary"
      ? "binary_overview"
      : operation,
  ),
);

/** Session lifecycle: an REA-owned import, or a user-launched CodeBrowser. */
export type GhidraSessionMode = "headless" | "attached";

/** How to select attached mode; REA never launches the GUI or its script. */
export const GHIDRA_ATTACH_REMEDIATION =
  "Open the target in a Ghidra CodeBrowser, run bridge/ghidra/ReaGhidraBridge.java from its Script Manager, and set REA_GHIDRA_ATTACH_ENDPOINT to the endpoint path it prints.";

/** Health limitations shared by every Ghidra-backed capability. */
export const healthLimitations = Object.freeze([
  "The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.",
  "The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.",
  "Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.",
]);

/** Health limitations shared by every CodeBrowser-attached capability. */
export const attachedHealthLimitations = Object.freeze([
  "Attached mode serves the one Program on which a user-launched CodeBrowser started bridge/ghidra/ReaGhidraBridge.java. REA requires its recorded executable SHA-256 to match the opened target, never edits, saves, or closes that Program, and never stops the GUI task.",
  "Results observe the live CodeBrowser database, including the analyst's edits, analysis options, image base, and language; they are not bound to an REA analysis profile and are never replayed from snapshots. Requests fail before the Program is analyzed and while auto-analysis runs.",
  "Cancelling a request disconnects REA; the bridge finishes in-flight Ghidra work before serving the next connection.",
]);

/** Additional limitations applied to the experimental Windows x64 P0 boundary. */
export const windowsP0Limitations = Object.freeze([
  "Windows Ghidra P0 accepts native x86, x86-64, ARMNT (Thumb-2) and ARM64 PE applications and DLLs, and explicitly selected raw 6502 images; managed, hostile, sensitive, and mutable-path targets are unsupported.",
  "The Windows bridge uses authenticated IPv4 loopback because Node path-based IPC does not expose Java AF_UNIX sockets; the endpoint file contains no bearer token.",
  "Windows sessions require the matching packaged Windows x64 native addon, local NTFS targets and runtimes, and Windows 10 or later. Native handles enforce path admission, private DACLs, and Job Object ownership automatically.",
]);

const stringInventoryLimitation =
  "Only Ghidra-defined string Data is observed; packed or undefined string bytes may be absent. Completeness applies to that inventory, and an empty search does not establish that text is absent from the artifact. If an address is known, use read_bytes and xrefs to inspect bytes and references.";

const searchLimitation =
  "Regex mode uses Java Pattern semantics. Matcher or compiler stack exhaustion returns a resource constraint without closing the session; literal mode avoids regex recursion and returns complete matching values.";

/** Limitation text for one admitted operation, including the common base. */
export const limitationsFor = (
  operation: string,
  mode: GhidraSessionMode = "headless",
): readonly string[] => {
  const attached = mode === "attached";
  const common = [
    ...(attached ? attachedHealthLimitations : healthLimitations),
    "Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.",
  ];
  switch (operation) {
    case "read_binary_inventory_summary":
      return [
        ...common,
        stringInventoryLimitation,
        "Counts use the complete defined-string inventory and the same local/external function inventory as list_strings and list_procedures. They do not establish discovery of undefined strings or unidentified functions.",
        "Memory-block end addresses are exclusive; segment lengths use those observed address coordinates.",
      ];
    case "annotate_native_function":
      return [
        ...common,
        "Names use Ghidra USER_DEFINED source. Name writes accept a leaf name or a fully qualified name within the existing namespace; readback uses the fully qualified name and can be reused without adding namespace prefixes. Edits retain the current namespace; other namespace-like text remains literal leaf-name text. Regular comments map to PRE and inline comments to EOL at the exact function entry. Changes commit together after readback and refreshed analysis; failure rolls them all back.",
        "Annotation text rejects NUL and unpaired Unicode surrogates before mutation, with the field and UTF-16 index in the error. Supported Unicode and line endings are preserved.",
        "Metadata edits invalidate immutable analysis snapshots and are discarded on close. CLI returns the updated dossier before session cleanup; this is not a saved Ghidra project.",
      ];
    case "set_address_name":
    case "set_addresses_names":
      return [
        ...common,
        "Names use Ghidra USER_DEFINED source. A local function entry renames that function; any other mapped address receives a new or renamed primary label. Existing symbols retain their namespace and accept leaf names or qualified names within that namespace; qualified readback can be reused without adding namespace prefixes. Readback compares the primary symbol name.",
        "set_addresses_names applies each address in its own transaction and reports per-address success; invalid names, unmapped addresses, and readback mismatches roll back only that address.",
        "Metadata edits invalidate immutable analysis snapshots and are discarded on close; this is not a saved Ghidra project.",
      ];
    case "comment":
    case "inline_comment":
    case "set_comment":
    case "set_inline_comment":
      return [
        ...common,
        attached
          ? "Ghidra requires an explicit mapped address; PRE and EOL listing comments represent regular and inline comments."
          : "Ghidra requires an explicit mapped address; PRE and EOL listing comments represent regular and inline comments. Empty writes clear the comment. Writes use a transaction and exact readback, invalidate analysis snapshots, and are discarded on close.",
      ];
    case "list_bookmarks":
    case "set_bookmark":
    case "unset_bookmark":
      return [
        ...common,
        attached
          ? "Ghidra exposes only analyst Note bookmarks in the REA category; analysis warnings and bookmarks in other categories are not listed. Names are stored in the bookmark comment; an empty name reads as null."
          : "Ghidra exposes only analyst Note bookmarks in the REA category. Analysis warnings and bookmarks in other categories are not listed or modified. Names are stored in the bookmark comment; an empty name reads as null. An omitted name preserves an existing name. These ephemeral metadata edits do not move a GUI cursor or change executable bytes.",
      ];
    case "inspect_native_load_image":
      return [
        ...common,
        "Independent verification covers admitted DOS MZ, explicitly selected COM with measured entry context, and caller-supplied raw-binary imports. Measured source mappings use inclusive end addresses and complete region digests; no target execution or project mutation occurs.",
      ];
    case "read_bytes":
      return [
        ...common,
        "Bytes reflect Ghidra's initialized memory, including loader fixups. Reads stop at an unmapped or uninitialized byte and report completeness explicitly.",
      ];
    case "search_bytes":
      return [
        ...common,
        "Searches initialized loader-adjusted memory independently per block, in provider address order. Bounds and page coverage ends are inclusive. Uninitialized blocks are listed separately. Overlapping matches are included; patterns never cross block boundaries. A cursor resumes the same target, profile and query. Cancellation discards the active search and returns no successful partial page.",
      ];
    case "address_to_file_offset":
      return [
        ...common,
        "Offsets come from Ghidra source-byte mappings, not virtual-address arithmetic. Uninitialized memory, missing mappings and ambiguous mappings fail explicitly.",
      ];
    case "current_document":
    case "list_documents":
      return [
        ...common,
        attached
          ? "Attached mode exposes exactly the Program on which the bridge started; other Programs open in Ghidra are not served."
          : "A headless Ghidra session contains exactly one imported Program, unlike Hopper's multi-document GUI session.",
      ];
    case "next_address":
    case "prev_address":
      return [
        ...common,
        "Adjacent objects are Ghidra Listing code units: instructions, defined data, or undefined bytes. An interior address resolves through its containing code unit, and results must lie in mapped memory blocks. This is navigation, not control flow.",
        attached
          ? "An omitted address uses the CodeBrowser Listing cursor."
          : "Headless sessions have no GUI cursor and require an explicit address.",
      ];
    case "current_address":
    case "current_procedure":
      return [
        ...common,
        "Reads the primary CodeBrowser Listing cursor on the Swing thread and fails when it is in another Program. current_procedure returns the qualified name of the function containing that address and fails outside functions. Cursor state is volatile and never cached.",
      ];
    case "goto_address":
      return [
        ...common,
        "Moves the CodeBrowser Listing to the start of the code unit containing a mapped address through GoToService, then requires that exact cursor readback. Unmapped addresses fail before navigation. Only navigation state and history change, not the Program.",
      ];
    case "list_names":
      return [
        ...common,
        "The symbol inventory includes memory and external symbols, including dynamic symbols, but excludes variable and no-address namespace records.",
      ];
    case "list_procedures":
    case "procedure_address":
      return [
        ...common,
        "External functions and local thunks are distinct; procedure metadata identifies both and preserves a thunk target when Ghidra resolves one.",
      ];
    case "list_strings":
      return [
        ...common,
        stringInventoryLimitation,
        "Charset is reported, while a non-missing terminator cannot distinguish a present terminator from a fixed or Pascal layout.",
      ];
    case "resolve_containing_procedure":
      return [
        ...common,
        "An exact external entry resolves to its observed function identity even when its body is empty. This does not establish mapped executable bytes or containment of nearby external addresses.",
      ];
    case "list_segments":
      return [
        ...common,
        "Memory-block end addresses are exclusive; permissions come from Ghidra MemoryBlock flags rather than inference from section names.",
      ];
    case "search_procedures":
      return [...common, searchLimitation];
    case "search_strings":
      return [...common, stringInventoryLimitation, searchLimitation];
    case "procedure_pseudo_code":
      return [
        ...common,
        "Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.",
        "External functions and functions without an analyzable body return null; other decompiler failures remain explicit.",
      ];
    case "read_function_instructions":
      return [
        ...common,
        "This fast path reads only the requested function and does not invoke the decompiler or whole-program string/name inventories.",
        "Instruction text is Ghidra-specific and does not claim textual equivalence with Hopper output.",
      ];
    case "procedure_assembly":
      return [
        ...common,
        "Assembly is Ghidra Listing text and does not claim textual equivalence with Hopper output.",
      ];
    case "procedure_callers":
    case "procedure_callees":
      return common;
    case "xrefs":
      return [
        ...common,
        "The direct address list projects exact Ghidra references to one address but does not expose their kinds; procedure_references and analyze_function preserve available kind metadata.",
        "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
      ];
    case "procedure_references":
      return [
        ...common,
        "References cover the complete Ghidra function-body AddressSet and exact entry, including instruction-interior destinations and embedded-data sources; an enclosing address span does not establish function ownership.",
        "Reference kinds are direct Ghidra ReferenceManager observations; unresolved computed flows without a target are absent and remain unknown.",
        "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
      ];
    case "analyze_function":
      return [
        ...common,
        "References cover the complete Ghidra function-body AddressSet and exact entry. Dossier incoming edges omit sources owned by that function; procedure_references also retains those internal edges.",
        "The dossier combines Ghidra FunctionManager, Listing, ReferenceManager, BasicBlockModel, and decompiler observations; provider-specific pseudocode and assembly are not cross-provider text invariants.",
        "Resolved reference metadata identifies computed, indirect, external, call, jump, and data edges; unresolved targetless flows remain unknown, and function classifications distinguish thunks and externals.",
        "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
        "The Java bridge serializes one function request per Program. Decompilation runs until completion or caller cancellation unless REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS sets a per-function limit. That limit stops the requested decompile without requesting session closure; caller cancellation requests session closure.",
      ];
    default:
      return common;
  }
};

const cursorOperations: ReadonlySet<string> = new Set(
  GHIDRA_ATTACHED_CURSOR_OPERATIONS,
);
const attachedOperations: ReadonlySet<string> = new Set(
  GHIDRA_ATTACHED_OPERATIONS,
);

/** Provider-neutral capabilities advertised by every non-Windows Ghidra session. */
export const CAPABILITIES: readonly CapabilityDescriptor[] = Object.freeze(
  providerOperations.map((operation) => {
    const descriptor = {
      provider: GHIDRA_PROVIDER_IDENTITY,
      operation,
      // Project writes are private import machinery. Analysis reads are bound
      // to the artifact/profile; session annotations disable snapshot replay.
      ...(GHIDRA_MUTATING_OPERATIONS.has(operation) ||
      cursorOperations.has(operation) ||
      operation === "list_documents" ||
      operation === "current_document"
        ? {}
        : { cachePolicy: "snapshot" as const }),
      effects: Object.freeze({
        mutatesArtifact: GHIDRA_MUTATING_OPERATIONS.has(operation),
        launchesProcess: true,
        mayShowUi: false,
        mayAccessNetwork: false,
        mayWriteFilesystem: true,
        changesPermissions: false,
        requiresRoot: false,
      }),
      limitations: Object.freeze(limitationsFor(operation)),
    };
    return Object.freeze(
      cursorOperations.has(operation)
        ? {
            ...descriptor,
            available: false as const,
            reason: `Headless Ghidra has no CodeBrowser cursor. ${GHIDRA_ATTACH_REMEDIATION}`,
            availabilityCode: "not_configured" as const,
          }
        : { ...descriptor, available: true as const, reason: null },
    );
  }),
);

/** Capabilities of a CodeBrowser-attached session: live reads and navigation. */
export const ATTACHED_CAPABILITIES: readonly CapabilityDescriptor[] =
  Object.freeze(
    providerOperations.map((operation) => {
      const descriptor = {
        provider: GHIDRA_PROVIDER_IDENTITY,
        operation,
        cachePolicy: "live" as const,
        effects: Object.freeze({
          mutatesArtifact: GHIDRA_MUTATING_OPERATIONS.has(operation),
          launchesProcess: false,
          mayShowUi: operation === "goto_address",
          mayAccessNetwork: false,
          mayWriteFilesystem: false,
          changesPermissions: false,
          requiresRoot: false,
        }),
        limitations: Object.freeze(limitationsFor(operation, "attached")),
      };
      return Object.freeze(
        attachedOperations.has(operation)
          ? { ...descriptor, available: true as const, reason: null }
          : {
              ...descriptor,
              available: false as const,
              reason:
                "Ghidra attached mode serves the CodeBrowser Program read-only and does not attest REA-owned imports; unset REA_GHIDRA_ATTACH_ENDPOINT to use an ephemeral headless session.",
              availabilityCode: "not_configured" as const,
            },
      );
    }),
  );

/** Capabilities advertised for the experimental Windows x64 P0 boundary. */
export const windowsP0Capabilities = (
  readiness: WindowsNativeReadiness = inspectWindowsNativeReadiness("win32"),
): readonly CapabilityDescriptor[] => {
  return Object.freeze(
    CAPABILITIES.map((capability): CapabilityDescriptor => {
      const limitations = Object.freeze([
        ...capability.limitations,
        ...windowsP0Limitations,
      ]);
      if (capability.effects.mutatesArtifact)
        return Object.freeze({
          ...capability,
          available: false,
          reason: "Windows Ghidra P0 does not admit database mutation.",
          availabilityCode: "unsupported_host",
          limitations,
        });
      return readiness.available
        ? Object.freeze({ ...capability, limitations })
        : Object.freeze({
            ...capability,
            available: false,
            reason: readiness.reason,
            availabilityCode: readiness.code,
            limitations,
          });
    }),
  );
};
