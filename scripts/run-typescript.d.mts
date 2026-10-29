export function selectTypeScriptCompiler(
  platform: string,
  arch: string,
  optionalDependencies: Readonly<Record<string, string>>,
): "tsrs" | "typescript";

export function resolveTypeScriptCompiler(
  environment?: Readonly<Record<string, string | undefined>>,
): {
  readonly name: "tsrs" | "typescript" | "typescript6" | "typescript-termux";
  readonly identity: string;
  readonly launcher: string;
};
