import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { evidenceRunnerOutputs, existingOutputPaths } from "./evidence-output-guard.mjs";

test("evidence runner guard catches its fixed and environment-selected outputs", () => {
	const root = mkdtempSync(path.join(tmpdir(), "aidr-evidence-output-guard-"));
	try {
		const evidence = path.join(root, ".release-evidence");
		const externalPrompt = path.join(root, "custom-prompt.md");
		const customRelease = path.join(root, "custom-release-output");
		mkdirSync(evidence);
		writeFileSync(path.join(evidence, "privacy-canary-v6.json"), "privacy sentinel");
		mkdirSync(path.join(evidence, "next-agent-execution-prompt-v8.md"));
		writeFileSync(externalPrompt, "prompt sentinel");
		mkdirSync(customRelease);

		const outputs = evidenceRunnerOutputs(root, {
			AIDR_NEXT_AGENT_PROMPT: externalPrompt,
			RELEASE_OUTPUT_DIR: "custom-release-output",
		});
		const collisions = existingOutputPaths(outputs);
		const defaultOutputs = evidenceRunnerOutputs(root);

		assert.ok(collisions.includes(path.join(evidence, "privacy-canary-v6.json")));
		assert.ok(collisions.includes(externalPrompt));
		assert.ok(collisions.includes(customRelease));
		assert.ok(existingOutputPaths(defaultOutputs).includes(path.join(evidence, "next-agent-execution-prompt-v8.md")));
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("output guard treats a dangling symlink as occupied", (t) => {
	if (process.platform === "win32") {
		t.skip("creating a symlink may require an elevated Windows privilege");
		return;
	}
	const root = mkdtempSync(path.join(tmpdir(), "aidr-evidence-output-link-"));
	try {
		const link = path.join(root, "dangling-output");
		symlinkSync(path.join(root, "missing-target"), link);
		assert.deepEqual(existingOutputPaths([link]), [link]);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
