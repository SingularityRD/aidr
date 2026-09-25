import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { COMPLIANCE_EXIT, runComplianceVerify } from "../commands/compliance.js";
import { canonicalJson, verifyComplianceReport } from "../utils/compliance-verify.js";

/**
 * `aidr compliance verify`: offline integrity check of a compliance evidence report.
 * Reports are sealed here by the real Edge Function module, so the round trip proves
 * the server's canonicalization, hash and Ed25519 signature match the CLI verifier.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..", "..");
const CLI_ENTRY = join(HERE, "..", "..", "dist", "index.js");

type Report = Record<string, unknown> & {
	integrity: { sha256: string; signature: Record<string, string> | null };
	sections: Record<string, Record<string, unknown>>;
};

interface Server {
	buildComplianceReportBody: (input: Record<string, unknown>) => Record<string, unknown>;
	sealComplianceReport: (
		body: Record<string, unknown>,
		signer: { keyId: string; privateKeyPkcs8B64: string } | null,
	) => Promise<Report>;
	canonicalJson: (value: unknown) => string;
	complianceEvidenceFixture: () => Record<string, unknown>;
}

let dir: string;
let server: Server;
let signed: Report;
let unsigned: Report;
let issuerPem: string;
let otherPem: string;

async function sealed(
	signer: { keyId: string; privateKeyPkcs8B64: string } | null,
): Promise<Report> {
	const body = server.buildComplianceReportBody({
		evidence: server.complianceEvidenceFixture(),
		reportId: "99999999-9999-4999-8999-999999999999",
		actorUserId: "11111111-1111-4111-8111-111111111111",
		from: new Date("2026-06-27T00:00:00.000Z"),
		to: new Date("2026-09-25T00:00:00.000Z"),
	});
	return server.sealComplianceReport(body, signer);
}

async function file(name: string, content: unknown): Promise<string> {
	const path = join(dir, name);
	await writeFile(path, typeof content === "string" ? content : JSON.stringify(content, null, 2));
	return path;
}

async function run(path: string, options: Parameters<typeof runComplianceVerify>[1] = {}) {
	let stdout = "";
	let stderr = "";
	const code = await runComplianceVerify(path, options, {
		stdout: (text) => {
			stdout += text;
		},
		stderr: (text) => {
			stderr += text;
		},
	});
	return { code, stdout, stderr };
}

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "aidr-compliance-"));
	const load = (path: string) => import(pathToFileURL(resolve(REPO_ROOT, path)).href);
	const [shared, fixtures] = await Promise.all([
		load("supabase/functions/_shared/compliance-report.ts"),
		load("supabase/functions/__tests__/compliance-fixtures.ts"),
	]);
	server = { ...shared, ...fixtures } as Server;
	const issuer = generateKeyPairSync("ed25519");
	issuerPem = issuer.publicKey.export({ format: "pem", type: "spki" }).toString();
	otherPem = generateKeyPairSync("ed25519")
		.publicKey.export({ format: "pem", type: "spki" })
		.toString();
	signed = await sealed({
		keyId: "compliance-2026-09",
		privateKeyPkcs8B64: issuer.privateKey
			.export({ format: "der", type: "pkcs8" })
			.toString("base64"),
	});
	unsigned = await sealed(null);
});

afterAll(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("compliance report verification", () => {
	it("uses the same canonical JSON as the issuing server", () => {
		const { integrity: _drop, ...body } = signed;
		expect(canonicalJson(body)).toBe(server.canonicalJson(body));
	});

	it("verifies a signed report against the pinned issuer key", async () => {
		const result = await run(await file("signed.json", signed), {
			publicKey: await file("issuer.pem", issuerPem),
			requireSignature: true,
		});
		expect(result.code).toBe(COMPLIANCE_EXIT.verified);
		expect(result.stdout).toContain("SHA-256:   OK");
		expect(result.stdout).toContain(
			"Signature: valid key compliance-2026-09, matches --public-key",
		);
		expect(result.stdout).toContain("Result:    VERIFIED");
	});

	it("reports an embedded-key-only verification as such", async () => {
		const result = await run(await file("signed-embedded.json", signed));
		expect(result.code).toBe(COMPLIANCE_EXIT.verified);
		expect(result.stdout).toContain("embedded key only");
	});

	it("verifies a hash-only report unless a signature is required", async () => {
		const path = await file("unsigned.json", unsigned);
		expect((await run(path)).code).toBe(COMPLIANCE_EXIT.verified);
		const required = await run(path, { requireSignature: true });
		expect(required.code).toBe(COMPLIANCE_EXIT.failed);
		expect(required.stdout).toContain("the report is not signed");
		const pinned = await run(path, { publicKey: await file("issuer-2.pem", issuerPem) });
		expect(pinned.code).toBe(COMPLIANCE_EXIT.failed);
	});

	it("detects any alteration of the content", async () => {
		const tampered = structuredClone(signed);
		(tampered.sections.access_identity.admins as Array<Record<string, unknown>>)[1].mfa_verified =
			true;
		const result = await run(await file("tampered.json", tampered), {
			publicKey: await file("issuer-3.pem", issuerPem),
		});
		expect(result.code).toBe(COMPLIANCE_EXIT.failed);
		expect(result.stdout).toContain("MISMATCH");
		expect(result.stdout).toContain("the report was altered");
		expect(result.stdout).toContain("Signature: invalid");
		// Reordering keys or reformatting is not an alteration.
		const reversed = (value: unknown): unknown =>
			Array.isArray(value)
				? value.map(reversed)
				: value && typeof value === "object"
					? Object.fromEntries(
							Object.entries(value)
								.reverse()
								.map(([key, item]) => [key, reversed(item)]),
						)
					: value;
		const reformatted = JSON.parse(JSON.stringify(reversed(signed), null, 4));
		expect(verifyComplianceReport(reformatted)).toMatchObject({ ok: true, signature: "valid" });
	});

	it("rejects a report signed by a key other than the pinned issuer", async () => {
		const result = await run(await file("signed-other.json", signed), {
			publicKey: await file("other.pem", otherPem),
			json: true,
		});
		expect(result.code).toBe(COMPLIANCE_EXIT.failed);
		const json = JSON.parse(result.stdout);
		expect(json).toMatchObject({
			ok: false,
			keyPinned: false,
			signature: "invalid",
			sha256: { valid: true },
		});
		expect(json.problems).toContain("signer_key_not_pinned_key");
	});

	it("rejects a forged signature value and a swapped embedded key", async () => {
		const forged = structuredClone(signed);
		forged.integrity.signature = {
			...(forged.integrity.signature as Record<string, string>),
			value_b64: Buffer.alloc(64, 7).toString("base64"),
		};
		expect(verifyComplianceReport(forged)).toMatchObject({ ok: false, signature: "invalid" });
		const swapped = structuredClone(signed);
		swapped.integrity.signature = {
			...(swapped.integrity.signature as Record<string, string>),
			public_key_spki_b64: "AAAA",
		};
		expect(verifyComplianceReport(swapped).problems).toContain("malformed_signature");
	});

	it("accepts the Edge Function response envelope", async () => {
		const result = await run(await file("envelope.json", { ok: true, report: signed }));
		expect(result.code).toBe(COMPLIANCE_EXIT.verified);
	});

	it("exits 1 on unreadable input and 2 on a non-report document", async () => {
		expect((await run(join(dir, "missing.json"))).code).toBe(COMPLIANCE_EXIT.error);
		expect((await run(await file("broken.json", "{not json"))).code).toBe(COMPLIANCE_EXIT.error);
		const pem = await run(await file("pem-check.json", signed), {
			publicKey: join(dir, "missing.pem"),
		});
		expect(pem.code).toBe(COMPLIANCE_EXIT.error);
		const other = await run(await file("other.json", { hello: "world" }));
		expect(other.code).toBe(COMPLIANCE_EXIT.failed);
		expect(other.stdout).toContain("the report has no integrity section");
		const badKey = await run(await file("signed-badkey.json", signed), {
			publicKey: await file(
				"not-a-key.pem",
				"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
			),
		});
		expect(badKey.code).toBe(COMPLIANCE_EXIT.failed);
		expect(badKey.stdout).toContain("not an Ed25519 public key");
	});
});

describe("aidr compliance verify - built binary", () => {
	it("verifies a report and sets the process exit code", async () => {
		const good = await file("bin-good.json", signed);
		const ok = spawnSync(
			process.execPath,
			[CLI_ENTRY, "compliance", "verify", good, "--require-signature"],
			{
				encoding: "utf8",
			},
		);
		expect(ok.status).toBe(COMPLIANCE_EXIT.verified);
		expect(ok.stdout).toContain("VERIFIED");
		const tampered = structuredClone(signed);
		tampered.report_id = "00000000-0000-4000-8000-000000000000";
		const bad = spawnSync(
			process.execPath,
			[CLI_ENTRY, "compliance", "verify", await file("bin-bad.json", tampered), "--json"],
			{ encoding: "utf8" },
		);
		expect(bad.status).toBe(COMPLIANCE_EXIT.failed);
		expect(JSON.parse(bad.stdout).problems).toContain("hash_mismatch");
	});
});
