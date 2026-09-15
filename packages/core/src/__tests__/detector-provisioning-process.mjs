/**
 * One real hook-like process per observation. The parent writes signed policy and
 * entitlement files; this process must load built production code and disk state,
 * never test models or a shared in-memory orchestrator.
 */
import { writeFile } from "node:fs/promises";
import { loadProvisionedDetectorContext } from "../../dist/detector-provisioning.js";

const [inputJson, outputPath] = process.argv.slice(2);
if (!inputJson || !outputPath) throw new Error("Expected event JSON and result path");
const context = await loadProvisionedDetectorContext("opencode");
const detector = context.runtimeDetectors?.behavioral;
if (!detector?.enabled) throw new Error("Signed behavioral detector is unavailable");
const result = await detector.orchestrator.evaluate(JSON.parse(inputJson));
await writeFile(outputPath, JSON.stringify({ pid: process.pid, result }), "utf8");
