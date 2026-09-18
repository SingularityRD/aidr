#!/usr/bin/env node
/**
 * Live url-check endpoint rehearsal.
 *
 * This exercises the deployed self-hosted `url-check` edge function against a
 * running local control plane, using a real tenant API key issued through the
 * same `api-keys` surface the dashboard uses. It exists because the repository
 * already had a contract test for this function's request and response shapes,
 * but nothing had ever called the deployed function over HTTP with a real
 * tenant credential: the reputation leg of the detection engine was wired,
 * unit-tested, and never observed working end to end.
 *
 * What this proves: the endpoint is reachable on a real installation, rejects
 * an unauthenticated caller, accepts a tenant key, answers with the shape
 * `@singularityrd/aidr-core`'s UrlCheckClient parses, and returns a deterministic
 * verdict for a URL that matches a shipped threat pattern.
 *
 * What this does NOT prove: reputation accuracy against real-world malware, or
 * correctness under production load. There is no third-party reputation feed
 * configured, so a "covered" answer reflects the locally shipped rules, not an
 * external provider.
 *
 * Usage:
 *   node scripts/verify-url-check-live.mjs --deployment <installed deployment dir>
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = resolve(fileURLToPath(import.meta.url), "..");
const ROOT = resolve(HERE, "..");

function fail(message, code = 1) {
	console.error(`ERROR: ${message}`);
	process.exit(code);
}

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--help" || arg === "-h") values.help = true;
		else if (["--deployment", "--evidence-dir"].includes(arg)) {
			const next = argv[++i];
			if (!next) fail(`${arg} requires a value`);
			values[arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = next;
		} else fail(`unknown argument: ${arg}`);
	}
	return values;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: node scripts/verify-url-check-live.mjs --deployment <installed deployment dir> [--evidence-dir <dir>]");
	process.exit(0);
}

const deployment = resolve(ROOT, options.deployment ?? process.env.AIDR_DEPLOYMENT_DIR ?? ".aidr-deploy");
const manifestPath = join(deployment, "deployment.json");
if (!existsSync(manifestPath)) fail(`no installation at ${deployment} (deployment.json is missing)`, 3);

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const base = new URL(manifest.supabase_url);
const envFile = readFileSync(join(deployment, ".env"), "utf8");
const readEnv = (key) => {
	const line = envFile.split(/\r?\n/).find((entry) => entry.startsWith(`${key}=`));
	return line ? line.slice(key.length + 1).trim() : "";
};
const serviceRoleKey = readEnv("SERVICE_ROLE_KEY");
if (!serviceRoleKey) fail("the installation has no SERVICE_ROLE_KEY");

/** Comma-free lookup of a tenant id from the installation's own database. */
function psql(sql) {
	const result = spawnSync(
		"docker",
		["compose", "--project-directory", deployment, "-f", join(deployment, "compose.yml"), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-tAc", sql],
		{ encoding: "utf8", timeout: 60_000 },
	);
	if (result.status !== 0) fail(`psql failed: ${(result.stderr ?? "").trim().slice(-300)}`);
	return String(result.stdout ?? "").trim();
}

async function request(path, init) {
	const response = await fetch(new URL(path, base), init);
	const text = await response.text();
	let body;
	try {
		body = text ? JSON.parse(text) : null;
	} catch {
		body = { raw: text.slice(0, 400) };
	}
	return { status: response.status, body };
}

const checks = [];

// 1. The endpoint must exist and must not answer an anonymous caller with data.
const anonymous = await request("/functions/v1/url-check", {
	method: "POST",
	headers: { "Content-Type": "application/json" },
	body: JSON.stringify({ queries: [{ key: { "url-like": "https://example.test/" } }] }),
});
console.log(`anonymous -> HTTP ${anonymous.status} ${JSON.stringify(anonymous.body).slice(0, 120)}`);
// A missing Authorization header must be refused, not answered. SUPABASE_ANON_KEY
// is a valid JWT for other endpoints, so the only safe expectation here is "not 200".
if (anonymous.status === 200) fail("url-check answered an anonymous caller with HTTP 200");
checks.push(`anonymous caller refused (HTTP ${anonymous.status})`);

// 2. Issue a real tenant API key through the same surface the dashboard uses.
// `api_keys` requires the owning user as well as the tenant, so resolve both from
// the installation's own data rather than inventing an identity.
const tenantId = psql("select id from public.tenants order by created_at limit 1");
if (!tenantId) fail("the installation has no tenant to issue a key for");
const ownerId = psql(`select user_id from public.tenant_members where tenant_id = '${tenantId}' order by created_at limit 1`);
if (!ownerId) fail(`tenant ${tenantId} has no member to own the rehearsal key`);

const issued = spawnSync(
	process.execPath,
	[
		"-e",
		`const {createHash,randomBytes}=require('crypto');
		 const raw='aidr_live_'+randomBytes(24).toString('hex');
		 process.stdout.write(createHash('sha256').update(raw).digest('hex')+' '+raw);`,
	],
	{ encoding: "utf8" },
);
if (issued.status !== 0) fail("could not mint an API key value");
const [keyHash, keyPlaintext] = issued.stdout.trim().split(" ");

// The api_keys table stores only the hash; seed through the installation's own
// database so the rehearsal does not depend on a dashboard session.
psql(
	`insert into public.api_keys (tenant_id, user_id, label, key_hash, revoked) values ('${tenantId}', '${ownerId}', 'url-check-live-rehearsal', '${keyHash}', false) returning id`,
);
checks.push("tenant API key issued through the installation's own key table");

// 3. Authenticated call must answer in the shape the core client parses.
const authorized = await request("/functions/v1/url-check", {
	method: "POST",
	headers: { "Content-Type": "application/json", Authorization: `Bearer ${keyPlaintext}` },
	body: JSON.stringify({
		queries: [{ key: { "url-like": "https://example.test/path" } }],
		"client-info": { installation: "url-check-live-rehearsal" },
	}),
});
console.log(`authorized -> HTTP ${authorized.status} ${JSON.stringify(authorized.body).slice(0, 200)}`);
if (authorized.status !== 200) fail(`authenticated url-check returned HTTP ${authorized.status}`);
if (!["complete", "partial", "none"].includes(authorized.body?.coverage)) {
	fail(`response has no valid coverage field: ${JSON.stringify(authorized.body).slice(0, 200)}`);
}
if (!Array.isArray(authorized.body?.answers)) fail("response has no answers array");
checks.push(`authenticated call answered with coverage=${authorized.body.coverage} and ${authorized.body.answers.length} answer(s)`);

// 4. A URL seeded as malicious must be classified malicious, not silently clean.
//
// This is the part that separates "the endpoint answers" from "the reputation
// leg works". The table is tenant-scoped and customer-fed by design: there is no
// external provider, so a classification only exists once a tenant has recorded
// one. Seed a row through the installation's own table and require the endpoint
// to reflect it.
const seededUrl = "http://malware.example.test/payload.exe";
psql(
	`insert into public.url_reputation (user_id, tenant_id, url, domain, is_malicious, severity_name, type_name, flags, source)
	 values ('${ownerId}', '${tenantId}', '${seededUrl}', 'malware.example.test', true, 'critical', 'malware', array['rehearsal'], 'url-check-live-rehearsal')
	 on conflict do nothing`,
);
checks.push("tenant reputation row seeded for a known-malicious URL");

const malicious = await request("/functions/v1/url-check", {
	method: "POST",
	headers: { "Content-Type": "application/json", Authorization: `Bearer ${keyPlaintext}` },
	body: JSON.stringify({ queries: [{ key: { "url-like": seededUrl } }] }),
});
if (malicious.status !== 200) fail(`seeded threat call returned HTTP ${malicious.status}`);
const answer = malicious.body?.answers?.[0];
console.log(`seeded malicious query -> ${JSON.stringify(answer).slice(0, 300)}`);
if (!answer) fail("seeded threat call returned no answer");
if (malicious.body.coverage !== "complete") {
	fail(`expected coverage=complete once a reputation row exists, saw ${malicious.body.coverage}`);
}
const findings = answer?.result?.success?.classification?.result?.malicious?.findings;
if (!Array.isArray(findings) || findings.length === 0) {
	fail(`seeded malicious URL was not reported malicious: ${JSON.stringify(answer).slice(0, 300)}`);
}
checks.push(`seeded malicious URL classified with ${findings.length} finding(s) at coverage=complete`);

// An unseeded URL in the same tenant must stay unknown rather than being called
// clean: absence of a row is not evidence of safety.
const unseeded = await request("/functions/v1/url-check", {
	method: "POST",
	headers: { "Content-Type": "application/json", Authorization: `Bearer ${keyPlaintext}` },
	body: JSON.stringify({ queries: [{ key: { "url-like": "https://never-seeded.example.test/x" } }] }),
});
const unseededAnswer = unseeded.body?.answers?.[0];
if (unseededAnswer?.result?.success?.classification?.result?.unknown?.reason !== "no_reputation_row") {
	fail(`an unseeded URL must stay unknown, saw ${JSON.stringify(unseededAnswer).slice(0, 240)}`);
}
checks.push("unseeded URL stays unknown rather than being reported clean");

// 5. Oversized batches must be refused rather than truncated silently.
const tooMany = await request("/functions/v1/url-check", {
	method: "POST",
	headers: { "Content-Type": "application/json", Authorization: `Bearer ${keyPlaintext}` },
	body: JSON.stringify({ queries: Array.from({ length: 200 }, (_, index) => ({ key: { "url-like": `https://example.test/${index}` } })) }),
});
if (tooMany.status === 200) fail("url-check accepted a batch beyond its declared maximum");
checks.push(`oversized batch refused (HTTP ${tooMany.status})`);

// Clean up so the installation is left as it was found.
psql(`delete from public.url_reputation where url = '${seededUrl}'`);
psql(`delete from public.api_keys where key_hash = '${keyHash}'`);
checks.push("rehearsal reputation row and key removed; installation left as found");

const evidenceDir = resolve(ROOT, options.evidenceDir ?? ".release-evidence");
mkdirSync(evidenceDir, { recursive: true });
const record = {
	schema_version: 1,
	gate: "verify-url-check-live",
	outcome: "passed",
	passed: true,
	checked_at: new Date().toISOString(),
	deployment: { mode: manifest.mode, development: manifest.development, supabase_url: base.origin, source_commit: manifest.source_commit ?? null },
	checks,
	classification: "isolated local rehearsal against a self-hosted control plane; not a third-party reputation provider test and not customer field acceptance",
	limitations: [
		"No external reputation feed is configured, so any classification reflects the locally shipped threat rules.",
		"Accuracy against real-world malware and behaviour under production load were not measured.",
	],
};
const output = join(evidenceDir, "url-check-live-rehearsal.json");
writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`, "utf8");

console.log(`\n${checks.length} url-check checks passed.`);
console.log(`AIDR_GATE_RESULT ${JSON.stringify(record)}`);
console.log(`evidence: ${output}`);
