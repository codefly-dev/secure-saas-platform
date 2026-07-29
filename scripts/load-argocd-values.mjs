import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

export function loadArgocdValues(outputDirectory) {
  const source = fileURLToPath(
    new URL("../src/argocdValues.ts", import.meta.url),
  );
  const output = path.join(outputDirectory, "argocd-values.cjs");
  const transpiled = ts.transpileModule(readFileSync(source, "utf8"), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      strict: true,
    },
    fileName: source,
    reportDiagnostics: true,
  });
  const errors = (transpiled.diagnostics ?? []).filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
  );
  if (errors.length > 0) {
    throw new Error(
      `Cannot load production Argo CD values: ${errors
        .map((diagnostic) =>
          ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
        )
        .join("; ")}`,
    );
  }
  writeFileSync(output, transpiled.outputText, { mode: 0o600 });
  return createRequire(import.meta.url)(output);
}
