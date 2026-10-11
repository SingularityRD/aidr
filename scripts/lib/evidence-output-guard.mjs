import { lstatSync } from "node:fs";
import path from "node:path";
import { CANDIDATE_RELEASE_DIR, CANDIDATE_SUFFIX } from "../generate-v8-evidence-index.mjs";

/** Fixed output paths used by the evidence rehearsal and its child commands. */
export function evidenceRunnerOutputs(root, env = {}) {
	const evidence = path.join(root, ".release-evidence");
	const prompt = path.resolve(root, env.AIDR_NEXT_AGENT_PROMPT ?? ".release-evidence/next-agent-execution-prompt-v8.md");
	const releaseOutput = path.resolve(root, env.RELEASE_OUTPUT_DIR ?? "release-output");
	return [...new Set([
		path.join(root, CANDIDATE_RELEASE_DIR),
		path.join(evidence, `aidr-customer-kit-${CANDIDATE_SUFFIX}`),
		path.join(evidence, `aidr-envelope-${CANDIDATE_SUFFIX}`),
		path.join(evidence, "v8-logs"),
		path.join(root, ".release-evidence", "v8-evidence-index.json"),
		path.join(evidence, "gate-run-summary.json"),
		path.join(evidence, "aidr-sbom.cdx.json"),
		path.join(evidence, "aidr-sbom.cdx.json.sha256"),
		path.join(evidence, "dependency-audit.json"),
		path.join(evidence, "privacy-canary-v6.json"),
		prompt,
		releaseOutput,
		...[
			"v7-claim-inventory.json",
			"v7-claim-inventory-final.json",
			"v7-claim-gate.json",
			"v7-claim-gate-final.json",
		].map((name) => path.join(evidence, name)),
	])];
}

/** Treat files, directories, and symlinks (including dangling symlinks) as collisions. */
export function existingOutputPaths(paths) {
	return paths.filter((target) => {
		try {
			lstatSync(target);
			return true;
		} catch (error) {
			if (error?.code === "ENOENT") return false;
			throw error;
		}
	});
}
