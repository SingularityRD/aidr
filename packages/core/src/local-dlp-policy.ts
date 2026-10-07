/**
 * Optional, unsigned DLP policy for local-mode installs.
 *
 * Managed installs only accept DLP policy inside a signed, entitlement-bound
 * detector bundle (`detector-provisioning.ts`). A local-mode install has no
 * tenant and no signing authority, so it may instead read a plain
 * `DlpPolicySchema` document that the machine's own operator wrote:
 *
 *   ~/.singularity-aidr/dlp-policy.json   (override: AIDR_DLP_POLICY_PATH)
 *
 * The location is operator-controlled (home directory or environment), never
 * selected by a tool payload. Failure policy follows the detection-internals
 * layer: a missing file means local DLP is off; an unreadable or invalid file
 * is skipped, logged, and surfaced as a degraded health check so it is never
 * reported as a clean, enforced policy.
 */
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import type { ZodIssue } from "zod";
import { resolvePath } from "./config.js";
import { type DlpPolicy, DlpPolicySchema } from "./dlp/policy.js";

export const LOCAL_DLP_POLICY_ENV = "AIDR_DLP_POLICY_PATH";
export const DEFAULT_LOCAL_DLP_POLICY_PATH = "~/.singularity-aidr/dlp-policy.json";
const MAX_LOCAL_DLP_POLICY_BYTES = 8 * 1024 * 1024;
const MAX_REPORTED_ISSUES = 5;

export type LocalDlpPolicyState =
	| { status: "absent"; path: string }
	| { status: "loaded"; path: string; policy: DlpPolicy }
	| { status: "invalid"; path: string; reason: string };

/** Resolved location of the local DLP policy file. */
export function localDlpPolicyPath(env: NodeJS.ProcessEnv = process.env): string {
	const override = env[LOCAL_DLP_POLICY_ENV]?.trim();
	return resolve(resolvePath(override ? override : DEFAULT_LOCAL_DLP_POLICY_PATH));
}

/**
 * Summarize schema issues by location and code only. Zod messages can echo
 * the offending value, and a DLP policy may contain the very keywords it is
 * meant to protect.
 */
function describeIssues(issues: readonly ZodIssue[]): string {
	const listed = issues
		.slice(0, MAX_REPORTED_ISSUES)
		.map((issue) => `${issue.path.length > 0 ? issue.path.join(".") : "(root)"} (${issue.code})`);
	const more =
		issues.length > MAX_REPORTED_ISSUES ? ` and ${issues.length - listed.length} more` : "";
	return `schema validation failed at ${listed.join(", ")}${more}`;
}

/** Read and validate the local DLP policy without applying it. */
export async function inspectLocalDlpPolicy(
	path: string = localDlpPolicyPath(),
): Promise<LocalDlpPolicyState> {
	let raw: string;
	try {
		const info = await stat(path);
		if (!info.isFile()) {
			return { status: "invalid", path, reason: "path is not a regular file" };
		}
		if (info.size > MAX_LOCAL_DLP_POLICY_BYTES) {
			return { status: "invalid", path, reason: "file exceeds the 8 MiB size limit" };
		}
		raw = await readFile(path, "utf8");
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		if (code === "ENOENT") return { status: "absent", path };
		return { status: "invalid", path, reason: `file could not be read (${code ?? "error"})` };
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return { status: "invalid", path, reason: "file is not valid JSON" };
	}
	const result = DlpPolicySchema.safeParse(parsed);
	if (!result.success) {
		return { status: "invalid", path, reason: describeIssues(result.error.issues) };
	}
	return { status: "loaded", path, policy: result.data };
}
