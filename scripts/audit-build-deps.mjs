import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ALLOWED_ESBUILD_ADVISORY = "1120680";

function isAllowedVitestDevServerAdvisory(advisory) {
	if (
		String(advisory?.id) !== ALLOWED_ESBUILD_ADVISORY ||
		advisory?.module_name !== "esbuild" ||
		advisory?.severity !== "low"
	) {
		return false;
	}
	const findings = advisory.findings ?? [];
	return (
		findings.length === 1 &&
		findings[0]?.version === "0.27.7" &&
		findings[0]?.paths?.length === 1 &&
		findings[0].paths[0] === ".>vitest>vite>esbuild"
	);
}

export function assessBuildAudit(report) {
	if (!report || typeof report !== "object" || report.error) {
		return { allowed: [], failures: ["invalid or failed pnpm audit report"] };
	}
	const allowed = [];
	const failures = [];
	for (const advisory of Object.values(report.advisories ?? {})) {
		if (isAllowedVitestDevServerAdvisory(advisory)) {
			allowed.push(String(advisory.id));
		} else {
			failures.push(`${advisory.id} ${advisory.module_name} (${advisory.severity})`);
		}
	}
	return { allowed, failures };
}

function run() {
	const npmExecPath = process.env.npm_execpath;
	const command = npmExecPath ? process.execPath : process.platform === "win32" ? "pnpm.cmd" : "pnpm";
	const args = npmExecPath ? [npmExecPath, "audit", "--json"] : ["audit", "--json"];
	const result = spawnSync(command, args, {
		encoding: "utf8",
		maxBuffer: 64 * 1024 * 1024,
		shell: !npmExecPath && process.platform === "win32",
	});
	const output = (result.stdout ?? "").trim();
	if (!output) {
		console.error("Build dependency audit produced no JSON output.");
		if (result.stderr) console.error(result.stderr.trim());
		process.exit(1);
	}

	let report;
	try {
		report = JSON.parse(output);
	} catch (error) {
		console.error("Unable to parse build dependency audit JSON:", error);
		process.exit(1);
	}

	const { allowed, failures } = assessBuildAudit(report);
	const summary = report.metadata?.vulnerabilities ?? {};
	console.log(
		`Build dependency audit: critical=${summary.critical ?? 0}, high=${summary.high ?? 0}, ` +
			`moderate=${summary.moderate ?? 0}, low=${summary.low ?? 0}.`,
	);
	if (failures.length > 0) {
		console.error("Build dependency audit failed:");
		for (const failure of failures) console.error(`- ${failure}`);
		process.exit(1);
	}
	if (allowed.includes(ALLOWED_ESBUILD_ADVISORY)) {
		console.log(
			`Allowed ${ALLOWED_ESBUILD_ADVISORY}: Vitest's Windows development-server-only esbuild path; ` +
				"CI and release use non-listening `vitest run`. Any version, path, severity, or advisory change fails closed.",
		);
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) run();
