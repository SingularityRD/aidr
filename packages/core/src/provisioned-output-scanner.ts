import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { loadConfig, resolvePath } from "./config.js";
import { detectorPolicyPath, loadProvisionedDlpPolicy } from "./detector-provisioning.js";
import { PiiDetectorImpl } from "./dlp/pii-detector.js";
import { scanDlpOutput } from "./dlp/scanner.js";
import { managedStatePath } from "./managed.js";
import { canonicalOutput, type OutputFinding, scanModelOutput } from "./output-scanner.js";
import type { AgentRuntime } from "./types.js";

const MAX_TRUST_FILE_BYTES = 8 * 1024 * 1024;
const commonPii = new PiiDetectorImpl({
	enableIpAddress: false,
	enableAwsKey: false,
	enableApiKey: false,
});
type TrustedPolicy = Awaited<ReturnType<typeof loadProvisionedDlpPolicy>>;
interface Snapshot {
	paths: string[];
	fingerprint: string;
	policy: TrustedPolicy;
}
// ponytail: one snapshot per supported runtime; synchronous host persistence cannot await trust I/O.
const snapshots = new Map<string, Snapshot>();

function unavailable(): OutputFinding[] {
	return [
		{
			type: "inspection_incomplete",
			severity: "critical",
			reason:
				"Tenant output inspection could not verify its current policy and entitlement; output was withheld.",
			redactedExcerpt: "[REDACTED_UNINSPECTED_OUTPUT]",
			ruleId: "OUT-DLP-UNAVAILABLE",
		},
	];
}

function trustFile(path: string): Buffer | null {
	try {
		const info = lstatSync(path);
		if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_TRUST_FILE_BYTES)
			throw new Error("Invalid trust file");
		const bytes = readFileSync(path);
		if (bytes.length > MAX_TRUST_FILE_BYTES) throw new Error("Oversized trust file");
		return bytes;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		return null;
	}
}

function fingerprintSources(paths: readonly string[], files: readonly (Buffer | null)[]): string {
	const hash = createHash("sha256");
	for (const [index, path] of paths.entries()) {
		hash.update(path).update("\0");
		const bytes = files[index];
		if (bytes) hash.update("present\0").update(bytes);
		else hash.update("missing\0");
	}
	return hash.digest("hex");
}

function trustFingerprint(paths: readonly string[]): string {
	return fingerprintSources(paths, paths.map(trustFile));
}

function scanViews(views: readonly string[], trusted: TrustedPolicy): OutputFinding[] {
	const byRule = new Map<string, OutputFinding>();
	for (const view of views) {
		for (const finding of scanModelOutput(view)) byRule.set(finding.ruleId, finding);
		if (!trusted?.policy || !view) continue;
		let contentType = "text/plain";
		try {
			JSON.parse(view);
			contentType = "application/json";
		} catch {
			/* Plain model-visible text. */
		}
		const inspected = scanDlpOutput(trusted.policy, {
			tenantId: trusted.tenantId,
			content: view,
			contentType,
		});
		if (inspected.status === "unavailable") return unavailable();
		if (inspected.action !== "allow") {
			for (const finding of inspected.findings.slice(0, 128)) {
				const ruleId = `OUT-DLP-${finding.ruleId}`;
				byRule.set(ruleId, {
					type: "secret_leak",
					severity: "critical",
					reason: "Tenant DLP policy requires withholding this output.",
					redactedExcerpt: "[REDACTED_TENANT_OUTPUT]",
					ruleId,
				});
			}
		}
		for (const finding of commonPii.detect(canonicalOutput(view)).slice(0, 128)) {
			const ruleId = `OUT-DLP-PII-${finding.type.toUpperCase()}`;
			byRule.set(ruleId, {
				type: "secret_leak",
				severity: "critical",
				reason: "Tenant DLP detected personal information; output was withheld.",
				redactedExcerpt: "[REDACTED_PERSONAL_INFORMATION]",
				ruleId,
			});
		}
	}
	return [...byRule.values()];
}

/** Fresh signed tenant DLP verification before an asynchronous delivery boundary. */
export async function scanProvisionedOutput(
	views: readonly string[],
	agentRuntime: AgentRuntime,
): Promise<OutputFinding[]> {
	let key: string | undefined;
	const configPath = resolvePath("~/.singularity-aidr/config.json");
	try {
		key = detectorPolicyPath(agentRuntime);
		const configBytes = trustFile(configPath);
		const rawConfig = configBytes?.toString("utf8") ?? null;
		const config = await loadConfig(undefined, undefined, undefined, { raw: rawConfig });
		const paths = [
			configPath,
			key,
			managedStatePath(),
			resolvePath(config.licensing.revocations_cache_path),
		];
		const files = [configBytes, ...paths.slice(1).map(trustFile)];
		const fingerprint = fingerprintSources(paths, files);
		const rawFiles = files.map((bytes) => bytes?.toString("utf8") ?? null);
		const policy = await loadProvisionedDlpPolicy(agentRuntime, {
			config: rawConfig,
			policy: rawFiles[1] ?? null,
			managed: rawFiles[2] ?? null,
			revocations: rawFiles[3] ?? null,
		});
		if (fingerprint !== trustFingerprint(paths)) throw new Error("Trust changed");
		const snapshot = { paths, fingerprint, policy };
		snapshots.set(key, snapshot);
		return scanCachedProvisionedOutput(views, agentRuntime);
	} catch {
		if (key) snapshots.delete(key);
		return unavailable();
	}
}

/** Sync-only host boundary: changed files or expired validation require an async refresh. */
export function scanCachedProvisionedOutput(
	views: readonly string[],
	agentRuntime: AgentRuntime,
): OutputFinding[] {
	try {
		const snapshot = snapshots.get(detectorPolicyPath(agentRuntime));
		if (
			!snapshot ||
			(snapshot.policy && Date.now() < snapshot.policy.validFromMs) ||
			(snapshot.policy && Date.now() >= snapshot.policy.validUntilMs) ||
			snapshot.fingerprint !== trustFingerprint(snapshot.paths)
		)
			return unavailable();
		return scanViews(views, snapshot.policy);
	} catch {
		return unavailable();
	}
}
