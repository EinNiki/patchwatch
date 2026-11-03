import { readFile } from "node:fs/promises";
import ts from "typescript";

/** Transpiliert TypeScript-Dateien beim Laden (nur Typen entfernen, keine Prüfung; die Prüfung macht `npm run typecheck`). */
export async function load(url, context, nextLoad) {
  if (/\.m?ts$/.test(url)) {
    const source = await readFile(new URL(url), "utf8");
    const out = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
      fileName: url,
    });
    return { format: "module", source: out.outputText, shortCircuit: true };
  }
  return nextLoad(url, context);
}
