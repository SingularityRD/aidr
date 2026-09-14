#!/usr/bin/env node
/**
 * verify-endpoint-auth-matrix.mjs — machine gate for the Edge Function authorization matrix.
 *
 * Acceptance criteria enforced here:
 *   "Every Edge Function that serves a protected route calls an authorization guard
 *    before it reads or mutates tenant data, or it is explicitly recorded as a public
 *    route with a written justification."
 *
 * Why this exists
 * ---------------
 * The guards exist (`supabase/functions/_shared/identity-barrier.ts` and
 * `supabase/functions/_shared/api-key-auth.ts`), but nothing enumerated the routes they
 * protect. An Edge Function runs with the service role, so it bypasses tenant RLS
 * entirely: a new `supabase/functions/<name>/index.ts` that forgets its guard compiles,
 * deploys and reads another tenant's rows. Contract suites pin individual functions
 * (`__tests__/identity-barrier.test.ts`, `__tests__/api-key-auth.test.ts`), but a function
 * that no test names ships silently. This gate derives the matrix from the tree instead
 * of from a hand-written list, so a new function is checked on the commit that adds it.
 *
 * Guard set
 * ---------
 * A route counts as guarded only when it calls one of the two shared guards *and* imports
 * it from its shared module — a local reimplementation cannot satisfy the gate by
 * coincidence:
 *
 *   - `checkIdentityBarrier(...)`      from `../_shared/identity-barrier.ts`
 *   - `authenticateTenantApiKey(...)`  from `../_shared/api-key-auth.ts`
 *
 * Everything else is either an explicit exemption (ALLOWLIST below) or a violation.
 *
 * Allowlist
 * ---------
 * Two exemption kinds, each with a one-line reason and in-file evidence:
 *
 *   - `public`            genuinely public by design (device bootstrap, waitlist intake,
 *                         provider webhooks). No caller identity or tenant exists.
 *   - `equivalent-guard`  protected, but authorized by a mechanism that cannot be one of
 *                         the two shared guards (a SCIM bearer token, an inline API-key
 *                         check that must also return the key's agent_id, a mixed public
 *                         recovery + authenticated admin surface).
 *
 * Every entry is SELF-CHECKED. The reason must be a real written explanation, the file it
 * names must exist and be the file that serves the route, and every `evidence` marker must
 * literally still be present in the file it names — so deleting the control that justified
 * an exemption fails the gate with a stale-exemption message instead of silently widening
 * the allowlist. An entry that no longer needs an exemption (the route now calls a shared
 * guard) is a violation too.
 *
 * Exit codes: 0 pass, 1 violations (including allowlist self-check problems), 2 the gate
 * itself could not run (bad usage, missing functions tree, missing shared guard module).
 *
 * Usage:  node scripts/verify-endpoint-auth-matrix.mjs [--json] [--repo <dir>]
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(MODULE_DIR, "..");

/** Repository-relative path of the Edge Functions tree that discovery enumerates. */
export const FUNCTIONS_DIR = "supabase/functions";

/** Minimum length for an allowlist reason before it can count as an explanation. */
export const MIN_ALLOWLIST_REASON_LENGTH = 24;

/** Minimum word count for an allowlist reason: a sentence, not a placeholder. */
export const MIN_ALLOWLIST_REASON_WORDS = 5;

/** The two shared authorization guards an Edge Function may rely on. */
export const GUARD_RULES = [
	{
		id: "identity_barrier",
		description: "shared user-session identity barrier (checkIdentityBarrier)",
		module: "../_shared/identity-barrier.ts",
		call: /\bcheckIdentityBarrier\s*\(/,
	},
	{
		id: "tenant_api_key",
		description: "shared hash-only tenant API-key guard (authenticateTenantApiKey)",
		module: "../_shared/api-key-auth.ts",
		call: /\bauthenticateTenantApiKey\s*\(/,
	},
];

/** The exemption kinds the allowlist may declare. */
export const EXEMPTION_KINDS = new Set(["public", "equivalent-guard"]);

/* ------------------------------------------------------------------ *
 * Allowlist
 * ------------------------------------------------------------------ */

/**
 * Routes that do not call one of the two shared guards, each with the reason it is still
 * safe and the in-file evidence that keeps the reason honest.
 *
 * Rules for adding an entry — an entry that fails any of these FAILS the gate's self-check:
 *   - "route"    the Edge Function route id (the `supabase/functions/<id>/` directory name).
 *   - "file"     the repository-relative `index.ts` that serves the route; it must exist
 *                and it must be the file discovery attributes to the route.
 *   - "kind"     "public" (no caller identity exists) or "equivalent-guard" (protected by
 *                another named mechanism).
 *   - "reason"   one written sentence explaining why this route is exempt.
 *   - "evidence" one or more literal source markers that prove the justification is still
 *                true. `"path/to/file.ts#marker"` checks another file of the function.
 *
 * "It is public" is not sufficient by itself: a public entry must also name the control
 * that makes public exposure deliberate (a signed ingress, a one-time token, an origin
 * allowlist, a provider signature). A new route with no guard and no justified entry is a
 * violation, and must be fixed or justified — never waved through.
 */
export const ALLOWLIST = [
	{
		route: "device-start",
		file: "supabase/functions/device-start/index.ts",
		kind: "public",
		reason:
			"Anonymous device-code bootstrap: no account exists yet, and the handler admits only an HMAC-signed trusted-ingress IP and fails closed when the abuse rate limit is unavailable.",
		evidence: [
			"verifiedIngressIp(req, AIDR_DEVICE_START_INGRESS_SECRET)",
			'"trusted_ingress_required"',
			"device_start:v2:client:",
			"if (error) return false",
		],
	},
	{
		route: "device-poll",
		file: "supabase/functions/device-poll/index.ts",
		kind: "public",
		reason:
			"Anonymous device-code poll: the 256-bit device code is the bearer secret, and an enrollment token is issued only for an authorized session of an approved pilot tenant.",
		evidence: [
			"readDeviceCode(req)",
			'eq("device_code_hash", deviceHash)',
			'"pilot_not_approved"',
			'supabase.rpc("issue_device_enrollment_token"',
		],
	},
	{
		route: "enroll",
		file: "supabase/functions/enroll/index.ts",
		kind: "public",
		reason:
			"First-run enrollment exchange: the bearer is a one-time enrollment token rather than a user session, and the atomic RPC consumes it before any API key exists.",
		evidence: [
			"getBearerToken(req)",
			'"missing_enrollment_token"',
			"rateLimitKey(supabase",
			'supabase.rpc("exchange_enrollment_token"',
		],
	},
	{
		route: "waitlist-signup",
		file: "supabase/functions/waitlist-signup/index.ts",
		kind: "public",
		reason:
			"Public marketing intake with no account, tenant or session: the handler is origin-restricted, rate-limited per client IP, and writes only the validated signup columns.",
		evidence: [
			"resolveAllowedOrigin(origin, ALLOWED_ORIGINS)",
			"rateLimitWaitlist(supabase, ip)",
			'supabase.rpc("increment_rate_limit"',
			'from("waitlist_signups")',
		],
	},
	{
		route: "paddle-webhook",
		file: "supabase/functions/paddle-webhook/index.ts",
		kind: "public",
		reason:
			"Paddle billing webhook: no user session exists, and the handler rejects any delivery whose Paddle-Signature HMAC does not verify in constant time inside the replay window.",
		evidence: [
			'PADDLE_SIGNATURE_HEADER = "Paddle-Signature"',
			"timingSafeEqual(a, b)",
			'"invalid_signature"',
			'"disabled_for_direct_ga"',
		],
	},
	{
		route: "stripe-webhook",
		file: "supabase/functions/stripe-webhook/index.ts",
		kind: "public",
		reason:
			"Stripe billing webhook: no user session exists, and the raw body is signature-verified with Stripe-Signature before any event is claimed or written.",
		evidence: [
			"verifyStripeWebhookSignature(",
			'STRIPE_SIGNATURE_HEADER = "Stripe-Signature"',
			'"invalid_signature"',
			'"disabled_for_direct_ga"',
		],
	},
	{
		route: "policy",
		file: "supabase/functions/policy/index.ts",
		kind: "equivalent-guard",
		reason:
			"Agent policy read endpoint: it re-implements the shared hash-only API-key check inline so it can also return the key's agent_id, refusing a revoked key and an inactive membership or tenant.",
		evidence: [
			'from("api_keys")',
			'eq("key_hash", await sha256(token))',
			"key.revoked",
			"membershipActive(member)",
			'state?.status !== "active"',
		],
	},
	{
		route: "identity-security",
		file: "supabase/functions/identity-security/index.ts",
		kind: "equivalent-guard",
		reason:
			"Mixed recovery and MFA administration: the public recovery actions are rate-limited one-time-code flows, and every authenticated action re-runs the shared revocation barrier with membership, tenant and MFA policy checks.",
		evidence: [
			"sessionPassesRevocationBarrier(token, state?.revoked_before)",
			"db.auth.getUser(token)",
			'db.rpc("consume_identity_recovery_code"',
			'db.rpc("increment_rate_limit"',
			"policyAllowsAssurance(",
		],
	},
	{
		route: "scim",
		file: "supabase/functions/scim/index.ts",
		kind: "equivalent-guard",
		reason:
			"SCIM 2.0 provisioning for an identity provider: the tenant is resolved from a hash-only SCIM bearer token before any read or write, and every handler rejects an unauthenticated request.",
		evidence: [
			'this.db.rpc("scim_resolve_token"',
			"createScimHandler(new SupabaseScimStore(db))",
			"supabase/functions/scim/scim.ts#store.authenticate(token)",
		],
	},
];

/* ------------------------------------------------------------------ *
 * Route discovery
 * ------------------------------------------------------------------ */

/** Extract the guard ids a handler source actually calls through the shared modules. */
export function detectGuards(source) {
	return GUARD_RULES.filter(
		(rule) => source.includes(`from "${rule.module}"`) && rule.call.test(source),
	).map((rule) => rule.id);
}

/**
 * Extract the method/path pairs documented in one header comment line (or block).
 * A bare `Supabase Edge Function: /v1/x` line has no method and yields the path only.
 */
function parseSurfacePairs(text) {
	const order = [];
	const methods = new Map();
	const pair = /\b(GET|POST|PUT|PATCH|DELETE|OPTIONS)\b\s+(\/[^\s,;)'"`]*)/g;
	let match;
	while ((match = pair.exec(text)) !== null) {
		const path = match[2].split("?")[0].replace(/[.]+$/, "");
		if (!path) continue;
		if (!methods.has(path)) {
			methods.set(path, new Set());
			order.push(path);
		}
		methods.get(path).add(match[1]);
	}
	if (order.length > 0) return order.map((path) => ({ path, methods: [...methods.get(path)].sort() }));
	const named = /Supabase Edge Function:\s*(\/[^\s,;)'"`]*)/.exec(text);
	if (named && named[1]) return [{ path: named[1].replace(/[.]+$/, ""), methods: [] }];
	return [];
}

/**
 * Read the HTTP surface a function documents in its leading `//` header comment.
 * Only the `Supabase Edge Function:` line is authoritative, so prose elsewhere in the
 * header (for example device-poll's "exchanged via POST /v1/enroll") cannot invent a route.
 * Purely a report label: the guard decision never depends on it.
 */
export function parseSurface(source) {
	const header = [];
	for (const line of String(source).split(/\r?\n/)) {
		const match = /^\s*\/\/(.*)$/.exec(line);
		if (!match) break;
		header.push(match[1]);
	}
	const declared = header.find((line) => /Supabase Edge Function:/i.test(line));
	const primary = declared ? parseSurfacePairs(declared) : [];
	if (primary.length > 0) return primary;
	return parseSurfacePairs(header.join("\n"));
}

/** Render a route's documented surface for the report, falling back to its endpoint. */
export function surfaceLabel(route) {
	if (!route.surface || route.surface.length === 0) return route.endpoint;
	return route.surface
		.map((entry) => `${entry.methods.length > 0 ? `${entry.methods.join(",")} ` : ""}${entry.path}`)
		.join(" + ");
}

/** True when a path exists and is a regular file. */
function isFile(path) {
	try {
		return statSync(path).isFile();
	} catch {
		return false;
	}
}

/**
 * Fail the gate (exit 2) when the shared guards it checks against are not in the tree.
 * Without them a "guarded" verdict cannot be interpreted at all.
 */
export function assertGuardModules(repoRoot) {
	const missing = GUARD_RULES.map((rule) => rule.module.replace(/^\.\.\//, `${FUNCTIONS_DIR}/`)).filter(
		(file) => !isFile(join(repoRoot, file)),
	);
	if (missing.length > 0) {
		throw new Error(`shared guard module(s) missing: ${missing.join(", ")}`);
	}
}

/**
 * Enumerate every Edge Function entrypoint (`supabase/functions/<name>/index.ts`).
 * Directories starting with `_` (`_shared`, `__tests__`) are not deployable functions.
 */
export function discoverRoutes(repoRoot = REPO_ROOT) {
	const functionsDir = join(repoRoot, FUNCTIONS_DIR);
	let entries;
	try {
		entries = readdirSync(functionsDir, { withFileTypes: true });
	} catch (error) {
		throw new Error(`cannot enumerate ${FUNCTIONS_DIR} (${error?.message ?? error})`);
	}

	const routes = [];
	const problems = [];
	for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
		if (!entry.isDirectory() || entry.name.startsWith("_")) continue;
		const file = `${FUNCTIONS_DIR}/${entry.name}/index.ts`;
		let source;
		try {
			source = readFileSync(join(repoRoot, file), "utf8");
		} catch {
			problems.push({
				kind: "missing-index",
				route: entry.name,
				file,
				message: `Edge Function directory ${FUNCTIONS_DIR}/${entry.name}/ has no readable index.ts, so its routes cannot be authorized`,
			});
			continue;
		}
		routes.push({
			route: entry.name,
			file,
			endpoint: `/functions/v1/${entry.name}`,
			surface: parseSurface(source),
			guards: detectGuards(source),
		});
	}
	return { routes, problems };
}

/* ------------------------------------------------------------------ *
 * Allowlist handling
 * ------------------------------------------------------------------ */

/** Split an evidence marker into the file it must appear in and the literal marker. */
export function splitEvidence(spec, entryFile) {
	const index = String(spec).indexOf("#");
	if (index === -1) return { file: String(entryFile).replace(/\\/g, "/"), marker: String(spec) };
	return { file: String(spec).slice(0, index).replace(/\\/g, "/"), marker: String(spec).slice(index + 1) };
}

/**
 * Allowlist entries that carry a route, a file, a known kind, a written reason and at least
 * one evidence marker. Only these entries can exempt a route; everything else is inert and
 * is reported by the self-check, which is what actually fails the gate.
 */
export function validAllowlistEntries(allowlist = ALLOWLIST) {
	return (allowlist ?? []).filter(
		(entry) =>
			entry &&
			typeof entry.route === "string" &&
			entry.route.trim() !== "" &&
			typeof entry.file === "string" &&
			entry.file.trim() !== "" &&
			EXEMPTION_KINDS.has(entry.kind) &&
			typeof entry.reason === "string" &&
			entry.reason.trim().length >= MIN_ALLOWLIST_REASON_LENGTH &&
			entry.reason.trim().split(/\s+/).length >= MIN_ALLOWLIST_REASON_WORDS &&
			Array.isArray(entry.evidence) &&
			entry.evidence.length > 0 &&
			entry.evidence.every((spec) => typeof spec === "string" && spec.trim() !== ""),
	);
}

/** Resolve the allowlist entry covering a route id, or null. */
export function matchAllowlistEntry(routeId, allowlist = ALLOWLIST) {
	const wanted = typeof routeId === "string" ? routeId : routeId?.route;
	return validAllowlistEntries(allowlist).find((entry) => entry.route === wanted) ?? null;
}

/**
 * Self-check the allowlist itself. Each entry must name a real explanation and a file that
 * exists and serves the route, and every evidence marker must still be present. A blank
 * reason, a missing file or a stale marker is a gate failure, not a silent skip.
 */
export function checkAllowlistSelfCheck(allowlist = ALLOWLIST, { repoRoot = REPO_ROOT, routes } = {}) {
	const problems = [];
	const known = new Map((routes ?? []).map((route) => [route.route, route]));
	const seen = new Set();

	for (const [index, entry] of (allowlist ?? []).entries()) {
		const label = entry?.route ? String(entry.route) : `<entry ${index}>`;
		if (!entry || typeof entry.route !== "string" || entry.route.trim() === "") {
			problems.push({
				kind: "allowlist-missing-route",
				entry: label,
				message: `allowlist entry ${index} does not name a route`,
			});
			continue;
		}
		if (seen.has(entry.route)) {
			problems.push({
				kind: "allowlist-duplicate-route",
				entry: label,
				message: `allowlist route ${label} is listed more than once`,
			});
		}
		seen.add(entry.route);

		if (!EXEMPTION_KINDS.has(entry.kind)) {
			problems.push({
				kind: "allowlist-invalid-kind",
				entry: label,
				message: `allowlist entry ${label} declares kind ${JSON.stringify(entry.kind)}; expected one of ${[...EXEMPTION_KINDS].join(", ")}`,
			});
		}

		const reason = typeof entry.reason === "string" ? entry.reason.trim() : "";
		if (reason.length < MIN_ALLOWLIST_REASON_LENGTH || reason.split(/\s+/).length < MIN_ALLOWLIST_REASON_WORDS) {
			problems.push({
				kind: "allowlist-missing-reason",
				entry: label,
				message: `allowlist entry ${label} must carry a written reason of at least ${MIN_ALLOWLIST_REASON_LENGTH} characters and ${MIN_ALLOWLIST_REASON_WORDS} words`,
			});
		}

		const route = known.get(entry.route);
		if (routes && !route) {
			problems.push({
				kind: "allowlist-unknown-route",
				entry: label,
				message: `allowlist entry ${label} does not match any discovered Edge Function route (stale entry)`,
			});
		}

		if (typeof entry.file !== "string" || entry.file.trim() === "") {
			problems.push({
				kind: "allowlist-missing-file",
				entry: label,
				message: `allowlist entry ${label} must name the index.ts that serves the route`,
			});
		} else {
			const file = entry.file.replace(/\\/g, "/");
			if (route && file !== route.file) {
				problems.push({
					kind: "allowlist-file-mismatch",
					entry: label,
					message: `allowlist entry ${label} names ${file} but the route is served by ${route.file}`,
				});
			}
			if (!isFile(join(repoRoot, file))) {
				problems.push({
					kind: "allowlist-missing-file",
					entry: label,
					message: `allowlist entry ${label} names a file that does not exist: ${file}`,
				});
			}
		}

		if (!Array.isArray(entry.evidence) || entry.evidence.length === 0) {
			problems.push({
				kind: "allowlist-missing-evidence",
				entry: label,
				message: `allowlist entry ${label} must name at least one source marker that proves the justification is still true`,
			});
			continue;
		}
		for (const spec of entry.evidence) {
			if (typeof spec !== "string" || spec.trim() === "") {
				problems.push({
					kind: "allowlist-missing-evidence",
					entry: label,
					message: `allowlist entry ${label} has an empty evidence marker`,
				});
				continue;
			}
			const { file, marker } = splitEvidence(spec, entry.file);
			let source;
			try {
				source = readFileSync(join(repoRoot, file), "utf8");
			} catch {
				problems.push({
					kind: "allowlist-evidence-file-missing",
					entry: label,
					message: `allowlist entry ${label} cites evidence in ${file}, which does not exist`,
				});
				continue;
			}
			if (marker.trim() === "" || !source.includes(marker)) {
				problems.push({
					kind: "allowlist-evidence-missing",
					entry: label,
					message: `allowlist entry ${label} cites ${JSON.stringify(marker)} in ${file}, but that marker is gone — the exemption is stale`,
				});
			}
		}
	}
	return problems;
}

/* ------------------------------------------------------------------ *
 * Orchestration
 * ------------------------------------------------------------------ */

/** Run the gate and return a machine-readable report. */
export function runGate({ repoRoot = REPO_ROOT, allowlist = ALLOWLIST, routes, now } = {}) {
	const root = isAbsolute(repoRoot) ? repoRoot : resolve(repoRoot);
	const discovery = routes ? null : discoverRoutes(root);
	assertGuardModules(root);
	const discovered = routes ?? discovery.routes;
	const routeProblems = discovery ? discovery.problems : [];
	const allowlistProblems = checkAllowlistSelfCheck(allowlist, { repoRoot: root, routes: discovered });
	const violations = [...routeProblems];
	const results = [];

	for (const route of discovered) {
		const label = surfaceLabel(route);
		const entry = matchAllowlistEntry(route.route, allowlist);
		if (entry) {
			results.push({
				route: route.route,
				file: route.file,
				endpoint: route.endpoint,
				surface: label,
				status: "exempt",
				exemptionKind: entry.kind,
				guards: [],
			});
			if (route.guards.length > 0) {
				violations.push({
					kind: "stale-exemption",
					route: route.route,
					file: route.file,
					message: `route ${route.route} (${label}) now calls ${route.guards.join(", ")} and no longer needs its allowlist exemption`,
				});
			}
			continue;
		}
		if (route.guards.length === 0) {
			results.push({
				route: route.route,
				file: route.file,
				endpoint: route.endpoint,
				surface: label,
				status: "unguarded",
				exemptionKind: null,
				guards: [],
			});
			violations.push({
				kind: "unguarded-route",
				route: route.route,
				file: route.file,
				message: `route ${route.route} (${label}) is served by ${route.file} without calling checkIdentityBarrier or authenticateTenantApiKey, and is not an allowlisted public route`,
			});
			continue;
		}
		results.push({
			route: route.route,
			file: route.file,
			endpoint: route.endpoint,
			surface: label,
			status: "guarded",
			exemptionKind: null,
			guards: route.guards,
		});
	}

	const exempt = results.filter((result) => result.status === "exempt");
	const ok = violations.length === 0 && allowlistProblems.length === 0;

	return {
		ok,
		gate: "verify-endpoint-auth-matrix",
		generatedAt: now ?? new Date().toISOString(),
		repoRoot: root,
		summary: {
			functions: discovered.length,
			routes: results.length,
			guardedRoutes: results.filter((result) => result.status === "guarded").length,
			exemptRoutes: exempt.length,
			publicExemptions: exempt.filter((result) => result.exemptionKind === "public").length,
			equivalentGuardExemptions: exempt.filter((result) => result.exemptionKind === "equivalent-guard").length,
			allowlistEntries: (allowlist ?? []).length,
			violations: violations.length,
			allowlistProblems: allowlistProblems.length,
		},
		guardRules: GUARD_RULES.map((rule) => ({ id: rule.id, description: rule.description })),
		results,
		allowlist: (allowlist ?? []).map((entry) => ({
			route: entry?.route ?? null,
			file: entry?.file ?? null,
			kind: entry?.kind ?? null,
			reason: entry?.reason ?? null,
			evidence: Array.isArray(entry?.evidence) ? entry.evidence : [],
		})),
		violations,
		allowlistProblems,
	};
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function parseArgs(argv) {
	const options = { json: false, repo: null, help: false };
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--json") options.json = true;
		else if (arg === "--repo") options.repo = argv[++i] ?? null;
		else if (arg.startsWith("--repo=")) options.repo = arg.slice("--repo=".length);
		else if (arg === "--help" || arg === "-h") options.help = true;
		else throw new Error(`unknown argument: ${arg}`);
	}
	return options;
}

function printHumanReport(report) {
	const { summary } = report;
	console.log(report.ok ? "endpoint auth matrix OK" : "endpoint auth matrix FAILED");
	console.log(
		`  routes: ${summary.routes} in ${summary.functions} Edge Function(s) | guarded: ${summary.guardedRoutes} | exempt: ${summary.exemptRoutes} (public: ${summary.publicExemptions}, equivalent-guard: ${summary.equivalentGuardExemptions}) | allowlist entries: ${summary.allowlistEntries}`,
	);
	const state = (result) =>
		result.status === "guarded" ? "guarded" : result.status === "exempt" ? `exempt:${result.exemptionKind}` : "unguarded";
	const guardText = (result) => (result.guards.length > 0 ? result.guards.join(",") : result.status === "exempt" ? "-" : "none");
	const stateWidth = Math.max(...report.results.map((result) => state(result).length), 5);
	const routeWidth = Math.max(...report.results.map((result) => result.route.length), 5);
	const guardWidth = Math.max(...report.results.map((result) => guardText(result).length), 6);
	for (const result of report.results) {
		const verdict = result.status === "unguarded" ? "FAIL" : "PASS";
		console.log(
			`  ${verdict} ${state(result).padEnd(stateWidth)} ${guardText(result).padEnd(guardWidth)} ${result.route.padEnd(routeWidth)} ${result.surface}`,
		);
	}
	if (report.allowlistProblems.length > 0) {
		console.log(`  allowlist self-check problems: ${report.allowlistProblems.length}`);
		for (const problem of report.allowlistProblems) console.log(`    - [${problem.kind}] ${problem.message}`);
	}
	if (report.violations.length > 0) {
		console.log(`  violations: ${report.violations.length}`);
		for (const violation of report.violations) console.log(`    - [${violation.kind}] ${violation.message}`);
	}
	console.log(report.ok ? "  result: PASS" : "  result: FAIL");
}

function main(argv) {
	let options;
	try {
		options = parseArgs(argv);
	} catch (error) {
		console.error(`verify-endpoint-auth-matrix: ${error.message}`);
		console.error("Usage: node scripts/verify-endpoint-auth-matrix.mjs [--json] [--repo <dir>]");
		return 2;
	}
	if (options.help) {
		console.log("Usage: node scripts/verify-endpoint-auth-matrix.mjs [--json] [--repo <dir>]");
		return 0;
	}

	let report;
	try {
		report = runGate(options.repo === null ? {} : { repoRoot: options.repo });
	} catch (error) {
		console.error(`verify-endpoint-auth-matrix: gate could not run: ${error.message}`);
		return 2;
	}

	if (options.json) console.log(JSON.stringify(report, null, 2));
	else printHumanReport(report);
	return report.ok ? 0 : 1;
}

const invokedDirectly = process.argv[1] ? resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url)) : false;
if (invokedDirectly) process.exit(main(process.argv.slice(2)));

export { main, printHumanReport };
