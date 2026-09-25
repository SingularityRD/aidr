/**
 * `scanCodePath` (behind `aidr scan --code`): file:line findings for the AI
 * supply-chain and secure-code rules over a project on disk.
 */
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { loadTrustedModelSources, type TrustedModelSources } from "../ai-supply-chain.js";
import { scanCodePath } from "../code-scanner.js";
import { loadThreats } from "../threat-loader.js";
import type { Threat } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");
const FAKE_GITHUB_TOKEN = `ghp_${"A1b2C3d4".repeat(4)}E5f6`;

let threats: Threat[];
let sources: TrustedModelSources;

beforeAll(async () => {
	threats = await loadThreats(THREATS_DIR);
	sources = await loadTrustedModelSources(ALLOWLISTS_DIR);
});

async function project(files: Record<string, string>): Promise<string> {
	const root = await makeTmpDir();
	for (const [path, content] of Object.entries(files)) {
		await mkdir(join(root, path, ".."), { recursive: true });
		await writeFile(join(root, path), content);
	}
	return root;
}

describe("scanCodePath", () => {
	it("reports every finding with its file and line", async () => {
		const root = await project({
			"src/train.py": [
				"import torch",
				"",
				'model = torch.load("model.pt")',
				"",
				"r = requests.get(url, verify=False)",
			].join("\n"),
			"src/app.js": "const x = 1;\nconst token = Math.random().toString(36).slice(2);\n",
			"scripts/get.sh":
				"#!/bin/sh\nhuggingface-cli download randomuser/model\nhuggingface-cli download meta-llama/Llama-3.1-8B\n",
		});
		const report = await scanCodePath(root, threats, { trustedModelSources: sources });
		expect(report.exists).toBe(true);
		expect(report.filesScanned).toBe(3);
		expect(
			report.findings.map(
				(finding) => `${finding.file}:${finding.line} ${finding.ruleId} ${finding.kind}`,
			),
		).toEqual([
			"scripts/get.sh:2 AISC-012 ai_supply_chain",
			"src/app.js:2 SCG-CRYPTO-003 secure_code",
			"src/train.py:3 AISC-001 ai_supply_chain",
			"src/train.py:5 SCG-TLS-001 secure_code",
		]);
		expect(report.findings[2]?.evidence).toBe('model = torch.load("model.pt")');
	});

	it("skips dependencies, build output, documentation and symbolic links", async () => {
		const root = await project({
			"node_modules/pkg/index.js": "eval(req.query.code)",
			"dist/bundle.js": "eval(req.query.code)",
			".venv/lib/x.py": "requests.get(u, verify=False)",
			"README.md": "Never call torch.load(path) on untrusted files.",
			"real.py": "import os\n",
		});
		await symlink(join(root, "real.py"), join(root, "link.py"));
		const report = await scanCodePath(root, threats);
		expect(report.findings).toEqual([]);
		expect(report.filesScanned).toBe(1);
		expect(report.linksSkipped).toBe(1);
	});

	it("masks credentials in evidence and reports them as SCG-SECRET-001", async () => {
		const root = await project({ "config.py": `GITHUB_TOKEN = "${FAKE_GITHUB_TOKEN}"\n` });
		const report = await scanCodePath(root, threats);
		expect(report.findings.map((finding) => finding.ruleId)).toEqual(["SCG-SECRET-001"]);
		expect(JSON.stringify(report)).not.toContain(FAKE_GITHUB_TOKEN);
		expect(report.findings[0]?.evidence).toContain("[REDACTED GitHub token]");
	});

	it("scans notebook code cells and reports the cell", async () => {
		const notebook = JSON.stringify({
			cells: [
				{ cell_type: "markdown", source: ["# np.load(x, allow_pickle=True) is unsafe"] },
				{
					cell_type: "code",
					source: ["import numpy as np\n", 'a = np.load("x.npy", allow_pickle=True)\n'],
				},
			],
		});
		const report = await scanCodePath(await project({ "nb.ipynb": notebook }), threats);
		expect(report.findings).toEqual([
			expect.objectContaining({ file: "nb.ipynb", cell: 2, line: 2, ruleId: "AISC-010" }),
		]);
	});

	it("scans a single file and honours disabled rules", async () => {
		const root = await project({ "a.py": 'torch.load("m.pt")\nrequests.get(u, verify=False)\n' });
		const report = await scanCodePath(join(root, "a.py"), threats, {
			disabledThreats: ["SCG-TLS-001"],
		});
		expect(report.findings.map((finding) => finding.ruleId)).toEqual(["AISC-001"]);
	});

	it("never presents an unreadable scope as clean", async () => {
		const missing = await scanCodePath(join(await makeTmpDir(), "nope"), threats);
		expect(missing.exists).toBe(false);
		const root = await project({ "big.py": `# ${"x".repeat(2048)}\ntorch.load(p)\n` });
		const report = await scanCodePath(root, threats, { maxFileBytes: 1024 });
		expect(report.filesScanned).toBe(0);
		expect(report.filesSkipped).toBe(1);
	});
});
