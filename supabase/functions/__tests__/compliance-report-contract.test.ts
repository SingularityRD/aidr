// Contract suite for the `compliance-report` Edge Function. It drives the real
// handler with an injected service-role client double and pins authorization
// (owner/admin, AAL2, identity barrier, cross-tenant), period bounds, the
// fail-closed mapping, the output schema (no sensitive content fields), the
// integrity envelope and its offline verification by `aidr compliance verify`.

import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyComplianceReport } from "../../../packages/cli/src/utils/compliance-verify.ts";
import { complianceDataFlowsSource } from "../../../scripts/sync-compliance-data-flows.mjs";
import {
	buildComplianceReportBody,
	COMPLIANCE_EVIDENCE_SPEC,
	COMPLIANCE_REPORT_BODY_SPEC,
	canonicalJson,
	type FieldSpec,
	parseComplianceRequest,
	sealComplianceReport,
} from "../_shared/compliance-report.ts";
import {
	COMPLIANCE_OWNER,
	COMPLIANCE_REPORT_ID,
	COMPLIANCE_TENANT,
	complianceEvidenceFixture,
} from "./compliance-fixtures.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through ComplianceReportDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260926000030_compliance_report.sql"),
	"utf8",
);
const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
const manifest = JSON.parse(
	readFileSync(join(ROOT, "docs", "production-readiness", "edge-function-contract-manifest.json"), "utf8"),
) as { functions: Record<string, { tests: string[] }> };

const OTHER_TENANT = "44444444-4444-4444-8444-444444444444";
const NOW = Date.parse("2026-09-25T10:00:00.000Z");
const URL_BASE = "https://project.supabase.co/functions/v1/compliance-report";
const PERIOD = { from: "2026-06-27T00:00:00.000Z", to: "2026-09-25T00:00:00.000Z" };

interface Options {
	/** Role of the caller in COMPLIANCE_TENANT (null = not a member). */
	role?: string | null;
	expiresAt?: string | null;
	tenantStatus?: string | null;
	assurance?: string;
	assuranceError?: boolean;
	requireMfa?: boolean;
	memberError?: boolean;
	rateAllowed?: boolean;
	rateError?: boolean;
	evidence?: unknown;
	evidenceError?: { code: string } | null;
	receiptError?: { code?: string; message: string } | null;
}

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const memberLookups: string[] = [];
	const assurance = vi.fn(async () => options.assuranceError
		? { data: null, error: new Error("auth_down") }
		: { data: { currentLevel: options.assurance ?? "aal2" }, error: null });
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "valid-token"
				? { data: { user: { id: COMPLIANCE_OWNER } }, error: null }
				: { data: { user: null }, error: new Error("invalid") }),
			mfa: { getAuthenticatorAssuranceLevel: assurance },
		},
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const builder = {
				select: () => builder,
				eq: (column: string, value: unknown) => {
					filters[column] = value;
					return builder;
				},
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") {
						return { data: { require_mfa: options.requireMfa ?? false, required_saml_provider_id: null }, error: null };
					}
					if (table === "tenant_members") {
						memberLookups.push(String(filters.tenant_id));
						if (options.memberError) return { data: null, error: new Error("db_down") };
						// The caller belongs to COMPLIANCE_TENANT only.
						if (filters.tenant_id !== COMPLIANCE_TENANT || options.role === null) return { data: null, error: null };
						return { data: { role: options.role ?? "owner", expires_at: options.expiresAt ?? null }, error: null };
					}
					if (table === "tenants") {
						if (options.tenantStatus === null) return { data: null, error: null };
						return { data: { id: filters.id, status: options.tenantStatus ?? "active" }, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				if (options.rateError) return { data: null, error: { message: "db_down" } };
				return { data: { allowed: options.rateAllowed ?? true, remaining: 2 }, error: null };
			}
			if (name === "compliance_report_evidence") {
				if (options.evidenceError) return { data: null, error: options.evidenceError };
				return { data: options.evidence === undefined ? complianceEvidenceFixture() : options.evidence, error: null };
			}
			if (name === "record_compliance_report") {
				return { data: null, error: options.receiptError ?? null };
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
	};
	return { db, rpcCalls, memberLookups, assurance };
}

function signingKey() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		pkcs8B64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
		publicPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
	};
}

async function handlerWith(options: Options = {}, env: Record<string, string> = {}) {
	const fake = database(options);
	const mod = await import("../compliance-report/index.ts");
	const handle = mod.createComplianceReportHandler({
		env: (name) => ({
			SUPABASE_URL: "https://project.supabase.co",
			SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
			...env,
		} as Record<string, string>)[name],
		client: () => fake.db as never,
		now: () => NOW,
		reportId: () => COMPLIANCE_REPORT_ID,
	});
	return { ...fake, handle };
}

function post(body: unknown, token: string | null = "valid-token", method = "POST"): Request {
	return new Request(URL_BASE, {
		method,
		headers: {
			...(token ? { Authorization: `Bearer ${token}` } : {}),
			"Content-Type": "application/json",
		},
		...(method === "GET" ? {} : { body: JSON.stringify(body) }),
	});
}

const validBody = (overrides: Record<string, unknown> = {}) => ({ tenant_id: COMPLIANCE_TENANT, ...PERIOD, ...overrides });
const businessRpcs = (calls: Array<{ name: string }>) =>
	calls.filter((call) => call.name !== "consume_tenant_rate_limit").map((call) => call.name);

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("compliance-report issuance", () => {
	it("returns a hash-sealed report to an owner at AAL2 and records the receipt first", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post(validBody()));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.ok).toBe(true);
		const report = body.report;
		expect(report).toMatchObject({
			schema: "aidr.compliance-report/v1",
			report_id: COMPLIANCE_REPORT_ID,
			generated_by: { user_id: COMPLIANCE_OWNER, role: "owner" },
			period: { from: PERIOD.from, to: PERIOD.to, days: 90 },
		});
		expect(report.statement).toMatch(/designed to support KVKK and GDPR/);
		expect(report.statement).toMatch(/not a certification/);
		expect(Object.keys(report.sections)).toEqual([
			"tenant_profile", "protection_coverage", "data_protection_activity", "policy_inventory",
			"access_identity", "incidents", "ai_security_posture", "data_flows", "retention_deletion",
			"control_mappings",
		]);
		const mappings = report.sections.control_mappings;
		expect(mappings.kind).toBe("vendor_mapping");
		expect(mappings.statement).toMatch(/not a certification, a regulatory approval or an audit result/);
		expect(mappings.frameworks.map((framework: { id: string }) => framework.id)).toEqual(
			expect.arrayContaining(["kvkk-gdpr", "iso-iec-27001", "bddk-bsebh", "cbddo-big"]),
		);
		const iso = mappings.frameworks.find((framework: { id: string }) => framework.id === "iso-iec-27001");
		expect(iso.controls.map((control: { id: string }) => control.id)).toEqual(
			expect.arrayContaining(["A.5.15", "A.5.25", "A.8.11", "A.8.12", "A.8.15"]),
		);
		for (const framework of mappings.frameworks) {
			for (const control of framework.controls) {
				expect(["full", "partial", "customer-responsibility"]).toContain(control.coverage);
				expect(control.note.length).toBeGreaterThan(40);
			}
		}
		expect(report.sections.policy_inventory.approval_settings).toEqual({
			model: "out_of_band_human_approval",
			agent_callable_approval: false,
			ask_defaults: ["command_default"],
			require_approval_servers: 2,
			require_approval_tools: 1,
		});
		expect(report.sections.data_flows.flows.length).toBeGreaterThan(0);
		expect(report.integrity).toMatchObject({
			canonicalization: "aidr-canonical-json/v1",
			hash_algorithm: "sha256",
			hashed_scope: "report_without_integrity",
			signature: null,
		});
		expect(verifyComplianceReport(report)).toMatchObject({ ok: true, signature: "absent" });
		expect(businessRpcs(rpcCalls)).toEqual(["compliance_report_evidence", "record_compliance_report"]);
		expect(rpcCalls.find((call) => call.name === "compliance_report_evidence")?.args).toEqual({
			p_tenant_id: COMPLIANCE_TENANT,
			p_actor_user_id: COMPLIANCE_OWNER,
			p_from: PERIOD.from,
			p_to: PERIOD.to,
		});
		expect(rpcCalls.find((call) => call.name === "record_compliance_report")?.args).toEqual({
			p_tenant_id: COMPLIANCE_TENANT,
			p_actor_user_id: COMPLIANCE_OWNER,
			p_report_id: COMPLIANCE_REPORT_ID,
			p_from: PERIOD.from,
			p_to: PERIOD.to,
			p_sha256: report.integrity.sha256,
			p_signature_key_id: null,
		});
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
			p_tenant_id: COMPLIANCE_TENANT,
			p_subject: COMPLIANCE_OWNER,
			p_endpoint: "compliance-report",
		});
	});

	it("signs with the configured Ed25519 key and the CLI verifier accepts it offline", async () => {
		const key = signingKey();
		// The role recorded in the report is the one the SQL re-read under lock.
		const evidence = { ...complianceEvidenceFixture(), actor_role: "admin" };
		const { handle, rpcCalls } = await handlerWith({ role: "admin", evidence }, {
			AIDR_COMPLIANCE_SIGNING_KEY_ID: "compliance-2026-09",
			AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64: key.pkcs8B64,
		});
		const response = await handle(post(validBody()));
		expect(response.status).toBe(200);
		const { report } = await response.json();
		expect(report.generated_by.role).toBe("admin");
		expect(report.integrity.signature).toMatchObject({ algorithm: "ed25519", key_id: "compliance-2026-09" });
		expect(verifyComplianceReport(report, { publicKeyPem: key.publicPem, requireSignature: true })).toMatchObject({
			ok: true,
			signature: "valid",
			keyPinned: true,
			keyId: "compliance-2026-09",
		});
		expect(rpcCalls.find((call) => call.name === "record_compliance_report")?.args.p_signature_key_id).toBe(
			"compliance-2026-09",
		);
		// A single altered count breaks both the hash and the signature.
		const tampered = structuredClone(report);
		tampered.sections.data_protection_activity.browser_guard.totals.blocked = 0;
		const result = verifyComplianceReport(tampered, { publicKeyPem: key.publicPem });
		expect(result.ok).toBe(false);
		expect(result.problems).toEqual(expect.arrayContaining(["hash_mismatch", "signature_invalid"]));
		// Re-sealing with an attacker key passes the embedded-key check but not the pinned key.
		const attacker = signingKey();
		const { integrity: _drop, ...body } = tampered;
		const resealed = await sealComplianceReport(body, { keyId: "compliance-2026-09", privateKeyPkcs8B64: attacker.pkcs8B64 });
		expect(verifyComplianceReport(resealed).ok).toBe(true);
		expect(verifyComplianceReport(resealed, { publicKeyPem: key.publicPem })).toMatchObject({
			ok: false,
			keyPinned: false,
		});
	});

	it("refuses to issue a report when the receipt cannot be recorded", async () => {
		const { handle } = await handlerWith({ receiptError: { message: "db_down" } });
		const response = await handle(post(validBody()));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "compliance_audit_unavailable" });
		const demoted = await handlerWith({ receiptError: { code: "42501", message: "forbidden" } });
		expect((await demoted.handle(post(validBody()))).status).toBe(403);
	});
});

describe("compliance-report authorization", () => {
	it("rejects missing and invalid sessions before any tenant read", async () => {
		const { handle, rpcCalls, memberLookups } = await handlerWith();
		expect((await handle(post(validBody(), null))).status).toBe(401);
		expect((await handle(post(validBody(), "forged"))).status).toBe(401);
		expect(rpcCalls).toEqual([]);
		expect(memberLookups).toEqual([]);
		expect((await handle(post(validBody(), "valid-token", "GET"))).status).toBe(405);
	});

	it("allows only owners and admins", async () => {
		for (const role of ["member", "viewer"]) {
			const { handle, rpcCalls } = await handlerWith({ role });
			const response = await handle(post(validBody()));
			expect(response.status, role).toBe(403);
			expect(await response.json()).toEqual({ error: "compliance_role_insufficient" });
			expect(rpcCalls, role).toEqual([]);
		}
		for (const options of [{ role: null }, { role: "support_jit" }, { expiresAt: "2026-09-25T09:00:00.000Z" }, { tenantStatus: null }, { tenantStatus: "closed" }] as Options[]) {
			const { handle, rpcCalls } = await handlerWith(options);
			const response = await handle(post(validBody()));
			expect(response.status, JSON.stringify(options)).toBe(403);
			expect(await response.json()).toEqual({ error: "workspace_forbidden" });
			expect(rpcCalls).toEqual([]);
		}
		const suspended = await handlerWith({ tenantStatus: "suspended" });
		expect((await suspended.handle(post(validBody()))).status).toBe(409);
	});

	it("never reads another tenant: membership is resolved for the requested tenant only", async () => {
		const { handle, rpcCalls, memberLookups } = await handlerWith({ role: "owner" });
		const response = await handle(post(validBody({ tenant_id: OTHER_TENANT })));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "workspace_forbidden" });
		expect(memberLookups).toEqual([OTHER_TENANT]);
		expect(rpcCalls).toEqual([]);
	});

	it("requires AAL2 even when the tenant MFA policy is optional, and fails closed on assurance errors", async () => {
		const aal1 = await handlerWith({ assurance: "aal1" });
		const response = await aal1.handle(post(validBody()));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(aal1.rpcCalls).toEqual([]);
		const broken = await handlerWith({ assuranceError: true });
		expect((await broken.handle(post(validBody()))).status).toBe(503);
		expect(broken.rpcCalls).toEqual([]);
		// The tenant identity barrier (require_mfa) also applies before membership.
		const barrier = await handlerWith({ requireMfa: true, assurance: "aal1" });
		expect(await (await barrier.handle(post(validBody()))).json()).toEqual({ error: "mfa_required" });
		expect(barrier.memberLookups).toEqual([]);
	});

	it("is rate limited per user and tenant and fails closed when the counter is unavailable", async () => {
		const limited = await handlerWith({ rateAllowed: false });
		const response = await limited.handle(post(validBody()));
		expect(response.status).toBe(429);
		expect(response.headers.get("Retry-After")).toBeTruthy();
		expect(businessRpcs(limited.rpcCalls)).toEqual([]);
		const broken = await handlerWith({ rateError: true });
		expect((await broken.handle(post(validBody()))).status).toBe(503);
		expect(businessRpcs(broken.rpcCalls)).toEqual([]);
		const unavailable = await handlerWith({ memberError: true });
		expect((await unavailable.handle(post(validBody()))).status).toBe(503);
	});

	it("maps SQL authorization and period refusals and never returns a partial report", async () => {
		for (const [error, status, code] of [
			[{ code: "42501" }, 403, "compliance_forbidden"],
			[{ code: "22023" }, 400, "invalid_period"],
			[{ code: "57014" }, 503, "compliance_report_unavailable"],
		] as const) {
			const { handle, rpcCalls } = await handlerWith({ evidenceError: error });
			const response = await handle(post(validBody()));
			expect(response.status).toBe(status);
			expect(await response.json()).toEqual({ error: code });
			expect(businessRpcs(rpcCalls)).toEqual(["compliance_report_evidence"]);
		}
	});
});

describe("compliance-report period bounds", () => {
	it("accepts up to 366 days and rejects longer, inverted, future, ancient and malformed periods", async () => {
		const cases: Array<[Record<string, unknown>, number, string | null]> = [
			[{ from: "2025-09-24T00:00:00.000Z", to: "2026-09-25T00:00:00.000Z" }, 200, null],
			[{ from: "2025-09-23T23:59:59.000Z", to: "2026-09-25T00:00:00.000Z" }, 400, "period_too_long"],
			[{ from: "2026-09-25T00:00:00.000Z", to: "2026-09-25T00:00:00.000Z" }, 400, "invalid_period"],
			[{ from: "2026-09-25T00:00:00.000Z", to: "2026-09-01T00:00:00.000Z" }, 400, "invalid_period"],
			[{ from: "2026-09-20T00:00:00.000Z", to: "2026-09-26T00:00:00.000Z" }, 400, "period_in_future"],
			[{ from: "2019-12-31T00:00:00.000Z", to: "2020-01-02T00:00:00.000Z" }, 400, "invalid_period"],
			[{ from: "last week", to: "2026-09-25T00:00:00.000Z" }, 400, "invalid_period"],
			[{ from: "2026-09-01", to: "2026-09-25" }, 200, null],
			[{ extra: "field" }, 400, "invalid_request"],
			[{ tenant_id: "not-a-uuid" }, 400, "invalid_request"],
		];
		for (const [overrides, status, error] of cases) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(post(validBody(overrides)));
			expect(response.status, JSON.stringify(overrides)).toBe(status);
			if (error) {
				expect(await response.json()).toEqual({ error });
				expect(rpcCalls).toEqual([]);
			}
		}
	});

	it("keeps the Edge and SQL bounds identical", () => {
		expect(parseComplianceRequest(validBody({ from: "2025-09-24T00:00:00.000Z" }), NOW).ok).toBe(true);
		expect(migration).toContain("p_to - p_from > interval '366 days'");
		expect(migration).toContain("p_from < timestamptz '2020-01-01 00:00:00+00'");
		expect(migration).toContain("p_to > now() + interval '5 minutes'");
	});
});

describe("compliance-report output schema", () => {
	// Free-text leaves are allowed only where the content is the product's own
	// fixed wording or the tenant's own administrative identity.
	const FREE_TEXT_PATHS = new Set([
		"statement",
		"limitations[]",
		"sections.tenant_profile.name",
		"sections.access_identity.admins[].email",
		"sections.data_flows.source",
		"sections.data_flows.matrix_status",
		"sections.data_flows.matrix_updated_at",
		"sections.data_flows.deployment_scope",
		"sections.data_flows.subprocessors[]",
		"sections.data_flows.limitations[]",
		// Control mappings: the product's own vendor mapping (governance/frameworks).
		...["statement", "source", "frameworks[].name", "frameworks[].version", "frameworks[].scope",
			"frameworks[].controls[].id", "frameworks[].controls[].group", "frameworks[].controls[].title",
			"frameworks[].controls[].capabilities[]", "frameworks[].controls[].note"].map(
			(field) => `sections.control_mappings.${field}`,
		),
		...["data_class", "fields[]", "purpose", "trigger", "destination", "destination_domain", "region",
			"subprocessor", "lawful_basis", "retention", "deletion", "access", "transfer_mechanism", "status",
			"unknowns[]"].map((field) => `sections.data_flows.flows[].${field}`),
	]);
	const SENSITIVE_KEY = /prompt|payload|content|body|text|value|secret|password|passwd|credential|reason|url|path|host|command|arg|keyword|regex|pattern|raw|match|detail|display|iid|cookie|session|ip_address|phone|address|file/i;
	const SENSITIVE_KEY_EXCEPTIONS = new Set(["sections.data_flows.flows[].fields", "sections.data_flows.source_sha256"]);

	function leaves(spec: FieldSpec, path: string, out: Array<{ path: string; spec: FieldSpec }>) {
		if (spec.kind === "object") {
			for (const [key, child] of Object.entries(spec.fields)) leaves(child, path ? `${path}.${key}` : key, out);
		} else if (spec.kind === "array") {
			leaves(spec.items, `${path}[]`, out);
		} else {
			out.push({ path, spec });
		}
		return out;
	}

	it("declares no field whose name suggests content, secrets or free text", () => {
		const all = leaves(COMPLIANCE_REPORT_BODY_SPEC, "", []);
		expect(all.length).toBeGreaterThan(150);
		for (const { path } of all) {
			const key = path.split(".").at(-1)?.replace("[]", "") ?? "";
			if (SENSITIVE_KEY_EXCEPTIONS.has(path.replace(/\[\]$/, ""))) continue;
			expect(SENSITIVE_KEY.test(key), path).toBe(false);
		}
	});

	it("bounds every string leaf by a pattern or enum unless it is an approved free-text field", () => {
		for (const { path, spec } of leaves(COMPLIANCE_REPORT_BODY_SPEC, "", [])) {
			if (spec.kind === "string" && !spec.pattern) expect(FREE_TEXT_PATHS.has(path), path).toBe(true);
			if (spec.kind === "map") {
				// Map keys are closed vocabularies (entity types, severities, actions).
				expect(spec.key.source.startsWith("^"), path).toBe(true);
				expect(spec.values.kind === "count" || spec.values.kind === "enum", path).toBe(true);
			}
		}
	});

	it("drops unknown evidence fields and refuses evidence that breaks the schema", async () => {
		const evidence = complianceEvidenceFixture() as Record<string, Record<string, unknown>>;
		const leaky = structuredClone(evidence);
		(leaky.browser_guard as Record<string, unknown>).recent_prompts = ["TCKN 10000000146 for Ahmet"];
		(leaky.policy_inventory.dlp as Record<string, unknown>).policy = { rules: [{ keyword: "Project Falcon" }] };
		(leaky.access_identity as Record<string, unknown>).members = [{ email: "member@acme.example" }];
		leaky.payload = { command: "cat ~/.ssh/id_rsa" };
		const body = buildComplianceReportBody({
			evidence: leaky,
			reportId: COMPLIANCE_REPORT_ID,
			actorUserId: COMPLIANCE_OWNER,
			from: new Date(PERIOD.from),
			to: new Date(PERIOD.to),
		});
		const text = JSON.stringify(body);
		for (const needle of ["10000000146", "Project Falcon", "member@acme.example", "id_rsa", "recent_prompts", '"payload"', '"policy":']) {
			expect(text).not.toContain(needle);
		}

		for (const mutate of [
			(e: Record<string, Record<string, unknown>>) => {
				(e.browser_guard.by_site as Array<Record<string, unknown>>)[0].site = "https://chat.example/c/123";
			},
			(e: Record<string, Record<string, unknown>>) => {
				(e.agent_decisions.totals as Record<string, unknown>).deny = -1;
			},
			(e: Record<string, Record<string, unknown>>) => {
				(e.browser_guard.by_entity_type as Array<Record<string, unknown>>)[0].entity_type = "ahmet@acme.example";
			},
			(e: Record<string, Record<string, unknown>>) => {
				delete e.retention_deletion;
			},
		]) {
			const broken = structuredClone(evidence);
			mutate(broken);
			const { handle } = await handlerWith({ evidence: broken });
			const response = await handle(post(validBody()));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "compliance_evidence_invalid" });
		}
	});

	it("keeps the evidence spec aligned with every section the SQL returns", () => {
		const specKeys = Object.keys((COMPLIANCE_EVIDENCE_SPEC as { fields: Record<string, unknown> }).fields);
		const sqlKeys = [...migration.matchAll(/^\s{4}'([a-z_]+)', v_[a-z]+,?$/gm)].map((match) => match[1]);
		const computed = ["generated_at", "actor_role"];
		expect(sqlKeys.filter((key) => !computed.includes(key)).sort()).toEqual(
			specKeys.filter((key) => !computed.includes(key)).sort(),
		);
		expect(migration).toContain("'generated_at', now()");
		expect(migration).toContain("'actor_role', v_role");
	});
});

describe("compliance-report integrity", () => {
	it("canonicalizes independently of key order and refuses non-JSON values", async () => {
		expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: "ç" } })).toBe('{"a":{"c":"ç","d":[3,{"y":2,"z":1}]},"b":1}');
		expect(() => canonicalJson({ a: Number.NaN })).toThrow();
		expect(() => canonicalJson({ a: undefined })).toThrow();
		const one = await sealComplianceReport({ b: 1, a: 2 }, null);
		const two = await sealComplianceReport({ a: 2, b: 1 }, null);
		expect(one.integrity.sha256).toBe(two.integrity.sha256);
	});

	it("fails closed on a half-configured or unusable signing key", async () => {
		const half = await handlerWith({}, { AIDR_COMPLIANCE_SIGNING_KEY_ID: "compliance-2026-09" });
		const response = await half.handle(post(validBody()));
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(half.rpcCalls).toEqual([]);
		const bad = await handlerWith({}, {
			AIDR_COMPLIANCE_SIGNING_KEY_ID: "compliance-2026-09",
			AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64: Buffer.from("not a key").toString("base64"),
		});
		const unsigned = await bad.handle(post(validBody()));
		expect(unsigned.status).toBe(503);
		expect(await unsigned.json()).toEqual({ error: "compliance_signing_unavailable" });
		expect(businessRpcs(bad.rpcCalls)).toEqual(["compliance_report_evidence"]);
	});
});

describe("compliance-report deployment contract", () => {
	it("keeps both RPCs service-role only, definer-hardened and role-rechecked", () => {
		for (const signature of [
			"public.compliance_report_evidence(uuid, uuid, timestamptz, timestamptz)",
			"public.record_compliance_report(uuid, uuid, uuid, timestamptz, timestamptz, text, text)",
		]) {
			expect(migration).toContain(`revoke all on function ${signature}\n  from public, anon, authenticated;`);
			expect(migration).toContain(`grant execute on function ${signature}\n  to service_role;`);
		}
		expect(migration.match(/security definer\nset search_path = pg_catalog, public, pg_temp/g)).toHaveLength(2);
		expect(migration.match(/m\.role in \('owner', 'admin'\)\n    and \(m\.expires_at is null or m\.expires_at > now\(\)\)\n    and t\.status = 'active'\n  for share of m, t;/g)).toHaveLength(2);
		expect(migration).toContain("'compliance_report.generated'");
		// Counts, digests and identifiers only: no raw payload or policy body is selected into the output.
		expect(migration).not.toMatch(/'payload',|'policy', [a-z]\.policy|'content',|'reason',|hold_reference/);
	});

	it("is registered for deployment and in the browser contract manifest", () => {
		expect(config).toMatch(/^\[functions\.compliance-report\]\n(?:#.*\n)*verify_jwt = true$/m);
		expect(manifest.functions["compliance-report"]?.tests).toContain(
			"supabase/functions/__tests__/compliance-report-contract.test.ts",
		);
	});

	it("embeds the current privacy data-flow matrix", () => {
		const embedded = readFileSync(join(ROOT, "supabase", "functions", "_shared", "compliance-data-flows.ts"), "utf8");
		expect(embedded.replaceAll("\r\n", "\n")).toBe(complianceDataFlowsSource());
	});
});
