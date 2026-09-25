/**
 * Tier 2: the bundled PreToolUse hook surfaces secure-code guardrail findings
 * (a notice by default, a confirmation with `secure_code.action: "ask"`) and
 * holds or blocks unsafe model loading. Requires `pnpm build` (dist/*.cjs).
 */

import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const PRE_TOOL_USE = resolve(__dirname, "..", "..", "dist", "pre-tool-use.cjs");

interface HookRun {
	response: Record<string, unknown>;
	audit: Array<Record<string, unknown>>;
}

/** Run the hook in a fresh home, optionally with an AIDR configuration. */
async function runHook(
	input: Record<string, unknown>,
	config?: Record<string, unknown>,
): Promise<HookRun> {
	const home = mkdtempSync(join(tmpdir(), "aidr-secure-code-home-"));
	try {
		const aidrDir = join(home, ".singularity-aidr");
		mkdirSync(aidrDir, { recursive: true });
		if (config) writeFileSync(join(aidrDir, "config.json"), JSON.stringify(config));
		const env: Record<string, string | undefined> = {
			...process.env,
			HOME: home,
			USERPROFILE: home,
			XDG_CONFIG_HOME: join(home, ".config"),
			XDG_STATE_HOME: join(home, ".local", "state"),
			XDG_CACHE_HOME: join(home, ".cache"),
		};
		for (const key of Object.keys(env)) {
			if (key.startsWith("AIDR_")) delete env[key];
		}
		const stdout = await new Promise<string>((resolveRun, reject) => {
			const child = execFile("node", [PRE_TOOL_USE], { timeout: 30_000, env }, (error, out) => {
				if (error && !out) reject(error);
				else resolveRun(out);
			});
			child.stdin?.end(JSON.stringify(input));
		});
		let audit: Array<Record<string, unknown>> = [];
		try {
			audit = readFileSync(join(aidrDir, "audit.jsonl"), "utf8")
				.trim()
				.split("\n")
				.map((line) => JSON.parse(line) as Record<string, unknown>)
				.filter((entry) => entry.type === "runtime_verdict");
		} catch {
			// No audit entry was written.
		}
		return { response: JSON.parse(stdout.trim()) as Record<string, unknown>, audit };
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
}

function hookOutput(response: Record<string, unknown>): Record<string, unknown> {
	return (response.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

const INSECURE_WRITE = {
	tool_name: "Write",
	tool_input: {
		file_path: "/work/client.py",
		content: "import requests\n\nr = requests.get(url, verify=False)\n",
	},
};

describe("PreToolUse secure-code guardrails", () => {
	it("allows an insecure write with a notice to the user and the model, and audits it", async () => {
		const { response, audit } = await runHook(INSECURE_WRITE);
		const output = hookOutput(response);
		expect(output.permissionDecision).toBeUndefined();
		expect(output.hookEventName).toBe("PreToolUse");
		expect(String(response.systemMessage)).toContain("secure-code notice");
		expect(String(response.systemMessage)).toContain("/work/client.py:3");
		expect(String(output.additionalContext)).toContain("SCG-TLS-001");
		expect(audit).toEqual([
			expect.objectContaining({
				verdict: "allow",
				category: "secure_code_warning",
				secure_code: { findings: 1, rule_ids: ["SCG-TLS-001"] },
			}),
		]);
	}, 30_000);

	it("stays silent for the secure twin", async () => {
		const { response } = await runHook({
			tool_name: "Write",
			tool_input: { file_path: "/work/client.py", content: "r = requests.get(url, verify=True)\n" },
		});
		expect(response).toEqual({});
	}, 30_000);

	it("asks for confirmation when secure_code.action is ask", async () => {
		const { response } = await runHook(INSECURE_WRITE, { secure_code: { action: "ask" } });
		const output = hookOutput(response);
		expect(output.permissionDecision).toBe("ask");
		expect(String(output.permissionDecisionReason)).toContain(
			"TLS certificate verification disabled",
		);
	}, 30_000);

	it("only inspects the lines an Edit adds", async () => {
		const unchanged = "r = requests.get(url, verify=False)";
		const { response } = await runHook({
			tool_name: "Edit",
			tool_input: {
				file_path: "/work/client.py",
				old_string: `# fetch\n${unchanged}`,
				new_string: `# fetch the index\n${unchanged}`,
			},
		});
		expect(response).toEqual({});
	}, 30_000);
});

describe("PreToolUse AI model supply chain", () => {
	it("asks before writing torch.load without weights_only=True", async () => {
		const { response } = await runHook({
			tool_name: "Write",
			tool_input: { file_path: "/work/train.py", content: 'model = torch.load("model.pt")\n' },
		});
		const output = hookOutput(response);
		expect(output.permissionDecision).toBe("ask");
		expect(String(output.permissionDecisionReason)).toContain("weights_only=True");
	}, 30_000);

	it("blocks unpickling a network response", async () => {
		const { response } = await runHook({
			tool_name: "Write",
			tool_input: {
				file_path: "/work/load.py",
				content: "obj = pickle.loads(requests.get(url).content)\n",
			},
		});
		expect(hookOutput(response).permissionDecision).toBe("deny");
		expect(String(response.systemMessage)).toContain("safetensors");
	}, 30_000);
});
