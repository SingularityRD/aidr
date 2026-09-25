import { readFile, stat } from "node:fs/promises";
import { type ComplianceVerification, verifyComplianceReport } from "../utils/compliance-verify.js";

/**
 * `aidr compliance verify <report.json>` — offline integrity check of a compliance
 * evidence report downloaded from the dashboard (or the `compliance-report` API).
 *
 * Exit codes: 0 verified, 2 verification failed (altered, unsigned when a signature
 * is required, or signed by a different key), 1 usage or input error.
 */

export const COMPLIANCE_EXIT = Object.freeze({ verified: 0, error: 1, failed: 2 });

/** Reports are small JSON documents; refuse anything larger outright. */
const COMPLIANCE_REPORT_MAX_BYTES = 16 * 1024 * 1024;

export interface ComplianceVerifyCommandOptions {
	publicKey?: string;
	requireSignature?: boolean;
	json?: boolean;
}

export interface ComplianceVerifyDependencies {
	stdout?: (text: string) => void;
	stderr?: (text: string) => void;
	readText?: (path: string) => Promise<string>;
}

const PROBLEM_TEXT: Readonly<Record<string, string>> = {
	not_a_report: "the file is not a compliance report object",
	unsupported_schema: "the report schema is not aidr.compliance-report/v1",
	missing_integrity: "the report has no integrity section",
	unsupported_integrity_method: "the integrity method is not aidr-canonical-json/v1 + sha256",
	not_canonicalizable: "the report contains values that cannot be canonicalized",
	hash_mismatch: "the SHA-256 does not match the report content (the report was altered)",
	invalid_pinned_key: "the --public-key file is not an Ed25519 public key",
	signature_required: "the report is not signed",
	malformed_signature: "the signature block is malformed",
	signer_key_not_pinned_key: "the report was signed with a different key than --public-key",
	signature_invalid: "the Ed25519 signature does not verify",
};

async function readLimited(path: string): Promise<string> {
	if ((await stat(path)).size > COMPLIANCE_REPORT_MAX_BYTES) throw new Error("too_large");
	return readFile(path, "utf8");
}

function signatureLine(result: ComplianceVerification): string {
	if (result.signature === "absent") return "Signature: none (hash-only report)";
	const key = result.keyId ? ` key ${result.keyId}` : "";
	let pin = "; embedded key only (pass --public-key to confirm the issuer)";
	if (result.keyPinned === true) pin = ", matches --public-key";
	if (result.keyPinned === false) pin = ", does NOT match --public-key";
	return `Signature: ${result.signature}${key}${pin}`;
}

function summary(result: ComplianceVerification): string {
	const period = result.period ? `${result.period.from} .. ${result.period.to}` : "unknown";
	const lines = [
		`Report:    ${result.reportId ?? "unknown"} (${result.schema ?? "unknown schema"})`,
		`Tenant:    ${result.tenantId ?? "unknown"}`,
		`Period:    ${period}`,
		`SHA-256:   ${result.sha256.valid ? "OK" : "MISMATCH"} ${result.sha256.computed ?? ""}`.trimEnd(),
		signatureLine(result),
		...result.problems.map((problem) => `Problem:   ${PROBLEM_TEXT[problem] ?? problem}`),
		result.ok ? "Result:    VERIFIED" : "Result:    NOT VERIFIED",
	];
	return `${lines.join("\n")}\n`;
}

/** Testable core; returns the exit code. */
export async function runComplianceVerify(
	file: string,
	options: ComplianceVerifyCommandOptions,
	deps: ComplianceVerifyDependencies = {},
): Promise<number> {
	const stdout = deps.stdout ?? ((text: string) => process.stdout.write(text));
	const stderr = deps.stderr ?? ((text: string) => process.stderr.write(text));
	const readText = deps.readText ?? readLimited;
	let report: unknown;
	try {
		report = JSON.parse(await readText(file));
	} catch {
		stderr("aidr compliance verify: cannot read the report as JSON\n");
		return COMPLIANCE_EXIT.error;
	}
	let publicKeyPem: string | undefined;
	if (options.publicKey !== undefined) {
		try {
			publicKeyPem = await readText(options.publicKey);
		} catch {
			stderr("aidr compliance verify: cannot read --public-key\n");
			return COMPLIANCE_EXIT.error;
		}
	}
	const result = verifyComplianceReport(report, {
		publicKeyPem,
		requireSignature: options.requireSignature === true,
	});
	stdout(options.json ? `${JSON.stringify(result, null, 2)}\n` : summary(result));
	return result.ok ? COMPLIANCE_EXIT.verified : COMPLIANCE_EXIT.failed;
}

export default async function complianceVerifyCommand(
	file: string,
	options: ComplianceVerifyCommandOptions,
): Promise<void> {
	process.exitCode = await runComplianceVerify(file, options);
}
