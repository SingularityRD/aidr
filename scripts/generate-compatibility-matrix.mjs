#!/usr/bin/env node
/**
 * Generate the customer-facing compatibility matrix (docs/compatibility-matrix.md) from the
 * release records, so the published statement cannot drift from them:
 *
 *   deploy/native/support-matrix.json       sold connectors, target platforms, install paths,
 *                                           known bypasses, real-host acceptance evidence
 *   deploy/native/interception-matrix.json  interception points and host failure behaviour
 *   docs/evidence/real-host/*.json          the tested host version, platform and results
 *   packages/<connector>/package.json       runtime requirement (Node.js / VS Code engine)
 *
 * A connector counts as tested only when its support-matrix row names an evidence record
 * whose sha256 matches the file on disk; otherwise it is listed as a preview.
 *
 *   node scripts/generate-compatibility-matrix.mjs           # write the document
 *   node scripts/generate-compatibility-matrix.mjs --check   # exit 1 when it is stale
 *
 * Tested by scripts/compatibility-matrix.test.mjs.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const OUTPUT_PATH = "docs/compatibility-matrix.md";

export const PREVIEW_LABEL = "Preview — no real-host acceptance evidence yet";

const CONNECTORS = {
	"claude-code": { name: "Claude Code", packageDir: "packages/claude-code", guide: "platform-guides/claude-code.md" },
	cursor: { name: "Cursor", packageDir: "packages/extension", guide: "platform-guides/cursor.md" },
	vscode: { name: "VS Code", packageDir: "packages/extension", guide: "platform-guides/cursor.md" },
	openclaw: { name: "OpenClaw", packageDir: "packages/openclaw", guide: "platform-guides/openclaw.md" },
	opencode: { name: "OpenCode", packageDir: "packages/opencode", guide: "platform-guides/opencode.md" },
	codex: { name: "Codex CLI", packageDir: "packages/codex", guide: "platform-guides/codex.md" },
};

const PLATFORM = { windows: "Windows", linux: "Linux", macos: "macOS" };
const POINT_LABEL = {
	"pre-prompt": "Prompt before the model",
	"pre-tool": "Tool call before it runs",
	"post-tool-output": "Tool output before the model",
	"pre-delivery-response": "Response before delivery",
	"model-stream": "Model stream",
	network: "Network egress",
};
const STATUS_LABEL = {
	enforced: "Enforced (real-host record)",
	"declared-not-proven": "Declared, not proven",
	"tamper-evident-only": "Tamper-evident only",
	unsupported: "Not supported",
};
const CONDITION_LABEL = {
	"disabled-hook": "Hook or plugin disabled / not trusted",
	"crashed-hook": "Hook process killed or crashed",
	offline: "Offline",
	"large-binary-response": "Large or binary tool output",
};
const OUTCOME_LABEL = {
	"fail-open": "Call runs (host fails open)",
	"fail-closed": "Call blocked",
	unobserved: "Not observed on a real host",
	"explicitly-unsupported": "See notes below",
};

const readJson = (root, file) => JSON.parse(readFileSync(path.join(root, file), "utf8"));
const sha256 = (root, file) => createHash("sha256").update(readFileSync(path.join(root, file))).digest("hex");
const cell = (text) => String(text).replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
const list = (values) => values.join(", ");

/** Everything the document is generated from. */
export function loadInputs(root = repositoryRoot) {
	const support = readJson(root, "deploy/native/support-matrix.json");
	const interception = readJson(root, "deploy/native/interception-matrix.json");
	const evidence = {};
	for (const row of support.rows) {
		for (const ref of row.acceptanceEvidence ?? []) {
			const present = existsSync(path.join(root, ref.path));
			evidence[ref.path] = {
				matches: present && sha256(root, ref.path) === ref.sha256,
				record: present ? readJson(root, ref.path) : null,
			};
		}
	}
	const packages = {};
	for (const { packageDir } of Object.values(CONNECTORS)) {
		const manifest = readJson(root, `${packageDir}/package.json`);
		packages[packageDir] = { name: manifest.name, version: manifest.version, engines: manifest.engines ?? {} };
	}
	return { support, interception, evidence, packages };
}

/** The verified real-host records for a support-matrix row (digest must match). */
export function acceptedRecords(row, evidence) {
	return (row.acceptanceEvidence ?? []).map((ref) => evidence[ref.path]).filter((entry) => entry?.matches && entry.record?.passed === true).map((entry) => entry.record);
}

function runtimeRequirement(pkg) {
	if (pkg.engines.vscode) return `extension engine \`vscode ${pkg.engines.vscode}\``;
	if (pkg.engines.node) return `Node.js ${pkg.engines.node}`;
	return "not declared";
}

/** Render the Markdown document. Pure: same inputs, same bytes. */
export function renderCompatibilityMatrix({ support, interception, evidence, packages }) {
	const rows = support.rows.filter((row) => support.soldConnectorScope.includes(row.connector));
	const records = Object.fromEntries(rows.map((row) => [row.connector, acceptedRecords(row, evidence)]));
	const name = (connector) => CONNECTORS[connector]?.name ?? connector;
	const out = [];
	const push = (...lines) => out.push(...lines);

	push(
		"# Compatibility matrix",
		"",
		"<!-- Generated by `node scripts/generate-compatibility-matrix.mjs` from deploy/native/support-matrix.json, deploy/native/interception-matrix.json and docs/evidence/real-host/*.json. Do not edit by hand: scripts/compatibility-matrix.test.mjs fails when this file is stale. -->",
		"",
		"Which host versions and platforms each Singularity AIDR agent connector has actually been",
		"tested on, which interception points it enforces, and what the host does when the AIDR hook",
		"cannot answer. Anything not listed as tested here is untested, not supported-by-default.",
		"",
		`Release decision recorded in the support matrix (reviewed ${support.reviewedAt}): **${support.decision}**.`,
		"",
		"## Tested host versions",
		"",
		"A connector is listed as tested only where a real-host acceptance record exists: the real,",
		"unmodified host binary ran with AIDR installed and a scripted mock model supplied the tool",
		"calls. That proves the host honours AIDR at its interception points for those calls on that",
		"host version and platform; it does not prove behaviour with a real model, on other host",
		"versions or on other platforms.",
		"",
		"| Connector | Status | Tested host version | Tested on | AIDR artefact | Runtime requirement | Guide |",
		"| --- | --- | --- | --- | --- | --- | --- |",
	);
	for (const row of rows) {
		const meta = CONNECTORS[row.connector] ?? { name: row.connector, packageDir: null, guide: null };
		const pkg = packages[meta.packageDir];
		const accepted = records[row.connector];
		const guide = meta.guide ? `[guide](${meta.guide})` : "";
		if (accepted.length === 0) {
			push(`| ${cell(meta.name)} | **${PREVIEW_LABEL}** | none | none | ${pkg ? `\`${pkg.name}\` ${pkg.version}` : ""} | ${pkg ? cell(runtimeRequirement(pkg)) : ""} | ${guide} |`);
			continue;
		}
		const versions = accepted.map((record) => {
			const recorded = String(record.host.version);
			const pinned = record.host.pinnedVersion && !recorded.includes(record.host.pinnedVersion) ? ` (pinned ${record.host.pinnedVersion})` : "";
			return `${recorded}${pinned}`;
		});
		const tested = accepted.map((record) => `${record.platform}/${record.architecture}, ${record.recordedAtUtc.slice(0, 10)}`);
		const artefact = accepted.map((record) => `${record.aidrArtifact?.buildFlavor ?? "unknown"} build`);
		push(`| ${cell(meta.name)} | Tested on one host version | ${cell(list(versions))} | ${cell(list(tested))} | ${cell(list([...new Set(artefact)]))} | ${pkg ? cell(runtimeRequirement(pkg)) : ""} | ${guide} |`);
	}
	push(
		"",
		"Host vendors change hook schemas and tool-call formats between releases. Treat every host",
		"version not listed above as unverified and repeat the acceptance run (`pnpm test:e2e:real-host`)",
		"before rolling out a host upgrade.",
		"",
		"## Target platform scope",
		"",
		"The support matrix lists the platforms and architectures each connector is intended for.",
		"This is **target scope, not tested support**: the acceptance records above cover only the",
		"platform and architecture named in the table.",
		"",
		"| Connector | Target platforms | Target architectures | Contexts | Install | Uninstall |",
		"| --- | --- | --- | --- | --- | --- |",
	);
	for (const row of rows) {
		push(
			`| ${cell(name(row.connector))} | ${cell(list(row.supportedPlatforms.map((p) => PLATFORM[p] ?? p)))} | ${cell(list(row.supportedArchitectures))} | ${cell(list(row.supportedContexts))} | ${cell(row.installPath.join("; "))} | ${cell(row.uninstallPath.join("; "))} |`,
		);
	}

	const points = interception.pointVocabulary;
	push("", "## Interception points", "", "`Enforced` requires a real-host acceptance record for that point; `Declared, not proven` means the connector implements the point but no real host has been observed honouring it.", "");
	push(`| Connector | ${points.map((p) => POINT_LABEL[p] ?? p).join(" | ")} |`, `| --- | ${points.map(() => "---").join(" | ")} |`);
	for (const row of rows) {
		const statuses = points.map((point) => {
			const entry = interception.rows.find((r) => r.connector === row.connector && r.point === point);
			return entry ? (STATUS_LABEL[entry.status] ?? entry.status) : "not recorded";
		});
		push(`| ${cell(name(row.connector))} | ${statuses.map(cell).join(" | ")} |`);
	}

	const conditions = interception.conditionVocabulary;
	const failureEntry = (connector, condition) => interception.failureConditions.find((r) => r.connector === connector && r.condition === condition);
	push(
		"",
		"## Host failure behaviour",
		"",
		"Every connector answers its own internal errors with a deny (or block): it fails closed.",
		"That guarantee ends where the host stops asking. When the host never runs the hook (disabled,",
		"removed or untrusted) or kills it before it answers (crash, host timeout), no verdict exists",
		"and the host decides; the rows below record what each host does.",
		"",
		`| Connector | ${conditions.map((c) => CONDITION_LABEL[c] ?? c).join(" | ")} | Connector internal error |`,
		`| --- | ${conditions.map(() => "---").join(" | ")} | --- |`,
	);
	for (const row of rows) {
		const outcomes = conditions.map((condition) => {
			const entry = failureEntry(row.connector, condition);
			return entry ? (OUTCOME_LABEL[entry.outcome] ?? entry.outcome) : "not recorded";
		});
		const observed = records[row.connector].some((record) => record.proves?.failurePolicy?.["internal-error"] === "fail-closed");
		const internal = observed ? "Call blocked (observed on the real host)" : "Deny returned by the connector; not observed on a real host";
		push(`| ${cell(name(row.connector))} | ${outcomes.map(cell).join(" | ")} | ${internal} |`);
	}
	push("", "Notes per connector:", "");
	for (const row of rows) {
		push(`- **${name(row.connector)}**: ${cell(row.tamperResistance)}.`);
		for (const condition of conditions) {
			const entry = failureEntry(row.connector, condition);
			if (entry) push(`  - ${CONDITION_LABEL[condition] ?? condition}: ${cell(entry.reason)}`);
		}
	}

	push("", "## Known bypasses and unobserved behaviour", "");
	for (const row of rows) {
		push(`### ${name(row.connector)}`, "", "Known bypasses:", "");
		for (const bypass of row.knownBypasses) push(`- ${cell(bypass)}`);
		push("", "Not observed on a real host:", "");
		for (const action of row.unobservedActions) push(`- ${cell(action)}`);
		push("");
	}

	push("## Evidence limitations", "", "Every acceptance record states its own limits:", "");
	const limitations = new Set(rows.flatMap((row) => records[row.connector].flatMap((record) => record.limitations ?? [])));
	for (const limitation of limitations) push(`- ${cell(limitation)}`);
	push("", "See also [upgrade notes](upgrade-notes.md) and the [support matrix README](../deploy/native/README.md).", "");
	return out.join("\n");
}

function main(argv) {
	const output = path.join(repositoryRoot, OUTPUT_PATH);
	const rendered = renderCompatibilityMatrix(loadInputs());
	if (argv.includes("--check")) {
		const current = existsSync(output) ? readFileSync(output, "utf8") : "";
		if (current !== rendered) {
			console.error(`${OUTPUT_PATH} is stale; run node scripts/generate-compatibility-matrix.mjs`);
			process.exitCode = 1;
			return;
		}
		console.log(`${OUTPUT_PATH} is up to date.`);
		return;
	}
	writeFileSync(output, rendered);
	console.log(`Wrote ${OUTPUT_PATH}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main(process.argv.slice(2));
}
