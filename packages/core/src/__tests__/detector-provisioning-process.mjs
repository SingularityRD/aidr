/**
 * One real hook-like process per observation. The parent writes signed policy and
 * entitlement files; this process loads the isolated production build prepared
 * by the parent test, never a stale workspace dist tree, test models, or a shared
 * in-memory orchestrator.
 */
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [inputJson, outputPath, detectorModulePath] = process.argv.slice(2);
if (!inputJson || !outputPath || !detectorModulePath) {
	throw new Error("Expected event JSON, result path, and detector module path");
}
const { loadProvisionedDetectorContext } = await import(pathToFileURL(detectorModulePath).href);
const context = await loadProvisionedDetectorContext("opencode");
const detector = context.runtimeDetectors?.behavioral;
if (!detector?.enabled) throw new Error("Signed behavioral detector is unavailable");
const result = await detector.orchestrator.evaluate(JSON.parse(inputJson));
await writeFile(outputPath, JSON.stringify({ pid: process.pid, result }), "utf8");
