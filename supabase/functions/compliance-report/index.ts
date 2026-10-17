// Compliance evidence report (docs/compliance-report.md).
//
// POST { tenant_id, from, to }   owner/admin/auditor at AAL2, period <= 366 days.
//
// Builds a tenant-scoped JSON report designed to support KVKK and GDPR
// accountability work: tenant profile, protection coverage, data-protection
// activity (counts only), policy inventory (versions and digests), access and
// identity, incidents, AI security posture, data flows and subprocessors, and
// retention/deletion evidence, plus the vendor control mappings (ISO/IEC
// 27001:2022 Annex A, BDDK information systems regulation, the Presidency's
// Information and Communication Security Guide and the other frameworks in
// governance/frameworks). It is never a certification, a regulatory approval
// or a statement of legal compliance.
//
// Integrity: the response carries the SHA-256 of the canonical JSON of the
// report (everything except `integrity`) and, when a signing key is
// configured, an Ed25519 signature over those same bytes. `aidr compliance
// verify <report.json>` checks both offline.
//
// Every control fails closed: an unreadable session, identity policy,
// membership, assurance level, rate-limit counter, evidence row, signing key
// or audit receipt refuses the request instead of returning a partial or
// unsigned report. Each issued report is recorded in the append-only admin
// audit log (`compliance_report.generated`) before it is returned.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import {
	buildComplianceReportBody,
	ComplianceEvidenceError,
	type ComplianceSigner,
	ComplianceSigningError,
	parseComplianceRequest,
	sealComplianceReport,
} from "../_shared/compliance-report.ts";
import {
	ConfigurationError,
	configFailure,
	type EnvReader,
	loadConfig,
	partialGroupError,
} from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import { isAuditReaderRole, isTenantReadRole } from "../_shared/tenant-roles.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const SIGNING_KEY_ID_ENV = "AIDR_COMPLIANCE_SIGNING_KEY_ID";
const SIGNING_KEY_ENV = "AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64";
const MAX_BODY_BYTES = 1024;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Report generation scans a whole period: a few per minute is plenty. */
export const COMPLIANCE_RATE_LIMIT = Object.freeze({ perSubject: 3, perTenant: 6 });

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface ComplianceReportDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
	reportId?: () => string;
}

function rpcFailure(req: Request, error: { code?: string } | null, headers: Record<string, string>): Response {
	if (error?.code === "42501") return corsJson(req, 403, { error: "compliance_forbidden" }, headers);
	if (error?.code === "22023") return corsJson(req, 400, { error: "invalid_period" }, headers);
	return corsJson(req, 503, { error: "compliance_report_unavailable" }, headers);
}

export function createComplianceReportHandler(deps: ComplianceReportDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const reportId = deps.reportId ?? (() => crypto.randomUUID());
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("compliance-report", config.error, (status, body) => corsJson(req, status, body));
		}
		// Signing is optional, but a half-configured key pair would silently
		// issue unsigned reports to an operator who believes they are signed.
		const signingKeyId = (runtimeEnv(SIGNING_KEY_ID_ENV) ?? "").trim();
		const signingKey = (runtimeEnv(SIGNING_KEY_ENV) ?? "").trim();
		const signingProblem = partialGroupError({ [SIGNING_KEY_ID_ENV]: signingKeyId, [SIGNING_KEY_ENV]: signingKey }) ??
			(signingKeyId && !KEY_ID.test(signingKeyId) ? new ConfigurationError({ invalid: [SIGNING_KEY_ID_ENV] }) : null);
		if (signingProblem) {
			return configFailure("compliance-report", signingProblem, (status, body) => corsJson(req, status, body));
		}
		const signer: ComplianceSigner | null = signingKeyId
			? { keyId: signingKeyId, privateKeyPkcs8B64: signingKey }
			: null;

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parseComplianceRequest(parsed.value, now());
		if (!request.ok) return corsJson(req, 400, { error: request.error });
		const { tenantId, from, to } = request.request;

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
				db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
				db.from("tenants").select("id,status").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!isTenantReadRole(role) || !tenant ||
				(tenant as { status?: unknown }).status === "closed") {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			// Owners, admins and the read-only auditor; the RPC re-checks the role.
			if (!isAuditReaderRole(role)) return corsJson(req, 403, { error: "compliance_role_insufficient" });
			if ((tenant as { status?: unknown }).status !== "active") {
				return corsJson(req, 409, { error: "workspace_not_active" });
			}
			// The report lists administrators and security posture: always require
			// step-up, even when the tenant's general MFA policy is optional.
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: "compliance-report",
				...COMPLIANCE_RATE_LIMIT,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);

			const { data: evidence, error: evidenceError } = await db.rpc("compliance_report_evidence", {
				p_tenant_id: tenantId,
				p_actor_user_id: userId,
				p_from: from.toISOString(),
				p_to: to.toISOString(),
			});
			if (evidenceError) return rpcFailure(req, evidenceError, headers);

			const id = reportId();
			let report;
			try {
				const body = buildComplianceReportBody({ evidence, reportId: id, actorUserId: userId, from, to });
				report = await sealComplianceReport(body, signer);
			} catch (cause) {
				if (cause instanceof ComplianceEvidenceError) {
					console.error("[compliance-report] evidence rejected", JSON.stringify({ path: cause.path }));
					return corsJson(req, 503, { error: "compliance_evidence_invalid" }, headers);
				}
				if (cause instanceof ComplianceSigningError) {
					return corsJson(req, 503, { error: "compliance_signing_unavailable" }, headers);
				}
				throw cause;
			}

			// The issuance receipt is written before the report leaves the
			// server; no receipt, no report.
			const { error: receiptError } = await db.rpc("record_compliance_report", {
				p_tenant_id: tenantId,
				p_actor_user_id: userId,
				p_report_id: id,
				p_from: from.toISOString(),
				p_to: to.toISOString(),
				p_sha256: report.integrity.sha256,
				p_signature_key_id: report.integrity.signature?.key_id ?? null,
			});
			if (receiptError) {
				if (receiptError.code === "42501") return corsJson(req, 403, { error: "compliance_forbidden" }, headers);
				return corsJson(req, 503, { error: "compliance_audit_unavailable" }, headers);
			}
			return corsJson(req, 200, { ok: true, report }, headers);
		} catch {
			return corsJson(req, 503, { error: "compliance_report_unavailable" });
		}
	};
}

const complianceReport = createComplianceReportHandler();
Deno.serve(complianceReport);
