import { readFileSync } from "node:fs";
import path from "node:path";

import type { ExtensionHookHost } from "./hook-responses.js";

/**
 * Host builds the extension's hook contract has been verified against in a
 * real extension host (docs/evidence/native-host-acceptance-run-20260916.md).
 * A host on the same major.minor line is treated as verified; anything else
 * still runs (the hooks fail closed on an unknown payload) but is reported as
 * unverified so a host change to the hook API cannot go unnoticed.
 *
 * Add a version here only together with a recorded acceptance run.
 */
export const VERIFIED_HOST_VERSIONS: Readonly<Record<ExtensionHookHost, readonly string[]>> = {
	cursor: ["3.19.7"],
	vscode: ["1.137.0"],
};

type HostVersionStatus = "verified" | "older" | "newer" | "unknown";

export interface HostVersionAssessment {
	host: ExtensionHookHost;
	version: string | undefined;
	status: HostVersionStatus;
	verified: readonly string[];
	/** User-facing warning; undefined when the host line is verified. */
	warning: string | undefined;
}

function parse(version: string | undefined): number[] | undefined {
	const match = /^v?(\d+)\.(\d+)(?:\.(\d+))?/.exec(version?.trim() ?? "");
	return match ? [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)] : undefined;
}

function compareMinor(a: number[], b: number[]): number {
	return (a[0] ?? 0) - (b[0] ?? 0) || (a[1] ?? 0) - (b[1] ?? 0);
}

export function assessHostVersion(
	host: ExtensionHookHost,
	version: string | undefined,
): HostVersionAssessment {
	const verified = VERIFIED_HOST_VERSIONS[host];
	const hostName = host === "cursor" ? "Cursor" : "VS Code";
	const parsed = parse(version);
	const verifiedParsed = verified.map(parse).filter((value): value is number[] => !!value);
	let status: HostVersionStatus;
	if (!parsed) {
		status = "unknown";
	} else if (verifiedParsed.some((entry) => compareMinor(entry, parsed) === 0)) {
		status = "verified";
	} else if (verifiedParsed.every((entry) => compareMinor(parsed, entry) < 0)) {
		status = "older";
	} else {
		status = "newer";
	}
	const list = verified.join(", ");
	const warning =
		status === "verified"
			? undefined
			: status === "unknown"
				? `Singularity AIDR could not determine the ${hostName} version; its hooks are verified on ${hostName} ${list}. Protection stays on, but check Show hook health after host updates.`
				: `Singularity AIDR is running on ${hostName} ${version}, which is ${status} than the verified ${hostName} ${list}. Protection stays on (unrecognised hook payloads are denied), but this host build is unverified.`;
	return { host, version, status, verified, warning };
}

/**
 * The host application's own version. `vscode.version` is the VS Code API
 * level, which Cursor reports for its VS Code base, not Cursor's release; a
 * Cursor build's `product.json` carries both (`version` and `vscodeVersion`),
 * so Cursor's own version is read only when that pair is present.
 */
export function detectHostVersion(
	host: ExtensionHookHost,
	vscodeApiVersion: string | undefined,
	appRoot: string | undefined,
): string | undefined {
	if (host === "vscode") return vscodeApiVersion;
	if (!appRoot) return undefined;
	try {
		const product = JSON.parse(readFileSync(path.join(appRoot, "product.json"), "utf8")) as Record<
			string,
			unknown
		>;
		return typeof product.vscodeVersion === "string" && typeof product.version === "string"
			? product.version
			: undefined;
	} catch {
		return undefined;
	}
}
