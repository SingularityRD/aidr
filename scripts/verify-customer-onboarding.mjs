#!/usr/bin/env node
/**
 * First-customer onboarding gate: empty state, install, policy, incident,
 * response, export and support on a real isolated loopback control plane.
 *
 * Fixture model
 * -------------
 * The customer rehearsal never reuses state left behind by a previous run:
 *
 *   --deployment <dir> / AIDR_DEPLOYMENT_DIR
 *     The operator-supplied *live installation*. Only `deployment.json`,
 *     `.env`, `.env.ingress` and `ingress/` are read from it, and the manifest
 *     shape is the one `scripts/deployment-prepare.mjs` writes; this gate never
 *     invents a second format.
 *
 *   the fixture
 *     A disposable copy of that installation, created outside the repository
 *     (OS temp directory by default, `--fixture-dir` to choose) and removed on
 *     exit unless `--keep-env` is set. `deployment-bootstrap.mjs`, the
 *     device-start ingress signer and every rehearsal credential live here, so
 *     nothing is written into the installation and a leftover `.aidr-deploy/`
 *     directory cannot make this gate pass.
 *
 * `deployment-prepare.mjs` is deliberately not invoked to mint the fixture: it
 * generates fresh secrets bound to fresh volumes, which a running loopback host
 * rejects, and its self-hosted path needs a bundled Supabase upstream that is
 * not part of this repository. Only the operator can supply a live installation
 * together with the credentials that installation's own host accepts.
 *
 * Outcomes (one machine-readable `AIDR_GATE_RESULT {json}` line is always printed)
 * ---------
 *   exit 0  every onboarding check passed against a live isolated installation
 *   exit 1  this deployment/repository is misconfigured, or an acceptance check
 *           failed: a real defect to fix
 *   exit 3  a required external input is missing (recorded blocker, never PASS)
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const GATE = "verify-customer-onboarding";
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bootstrapScript = join(repositoryRoot, "scripts", "deployment-bootstrap.mjs");
const EXIT_ACCEPTANCE_FAILURE = 1;
const EXIT_EXTERNAL_INPUT_REQUIRED = 3;
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1"];

const { values } = parseArgs({ options: {
	deployment: { type: "string" },
	"fixture-dir": { type: "string" },
	"evidence-dir": { type: "string" },
	"keep-env": { type: "boolean", default: false },
	help: { type: "boolean", default: false },
} });

const usage = `Customer onboarding gate (isolated loopback rehearsal only).

  node scripts/verify-customer-onboarding.mjs --deployment <installed deployment dir> [--fixture-dir <dir>] [--keep-env] [--evidence-dir <dir>]

  --deployment / AIDR_DEPLOYMENT_DIR   live installation to rehearse against (read-only); never defaulted to .aidr-deploy
  --fixture-dir / AIDR_ONBOARDING_FIXTURE_DIR
                                       where the disposable fixture is created; must not already exist and must be outside the repository
  --keep-env                           keep the fixture (credentials and evidence) instead of removing it
  --evidence-dir / AIDR_ONBOARDING_EVIDENCE_DIR
                                       also write credentials-free evidence outside the fixture

Exit codes: 0 all checks passed, 1 misconfiguration or acceptance failure, 3 required external input missing.`;

class GateOutcome extends Error {
	constructor(outcome, code, detail, requirement) {
		super(detail);
		this.outcome = outcome;
		this.code = code;
		this.detail = detail;
		this.requirement = requirement;
	}
}
function stopBlocked(code, detail, requirement) { throw new GateOutcome("blocked", code, detail, requirement); }
function stopInvalid(code, detail) { throw new GateOutcome("failed", code, detail, undefined); }

const keepEnv = Boolean(values["keep-env"]);
let fixtureDirectory = null;
const checks = [];

function removeFixture() {
	if (!fixtureDirectory || keepEnv) return;
	rmSync(fixtureDirectory, { recursive: true, force: true });
}
process.once("exit", removeFixture);
for (const signal of ["SIGINT", "SIGTERM"]) {
	process.once(signal, () => { removeFixture(); process.exit(130); });
}

function parseEnvFile(path) {
	return Object.fromEntries(readFileSync(path, "utf8").split(/\r?\n/).filter((line) => line.includes("=")).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
}
function copyTree(source, destination) {
	// Node's recursive cp binding fails on Windows paths with non-ASCII characters,
	// which this checkout has; copy explicitly like deployment-prepare.mjs does.
	if (statSync(source).isDirectory()) {
		mkdirSync(destination, { recursive: true });
		for (const entry of readdirSync(source)) copyTree(join(source, entry), join(destination, entry));
	} else {
		mkdirSync(dirname(destination), { recursive: true });
		copyFileSync(source, destination);
	}
}
function displayPath(path) {
	// The OS temp directory can be an 8.3 short path on Windows, which some
	// shells cannot hand back to Remove-Item; show the resolved path instead.
	try { return realpathSync.native(path); } catch { return path; }
}
function isInside(parent, child) {
	const relativePath = relative(parent, child);
	return relativePath === "" || (!relativePath.startsWith("..") && !isAbsolute(relativePath));
}
function writeEvidence(record) {
	if (!fixtureDirectory) return;
	const body = `${JSON.stringify(record, null, 2)}\n`;
	writeFileSync(join(fixtureDirectory, "customer-onboarding-evidence.json"), body, { mode: 0o600 });
	const target = (values["evidence-dir"] ?? process.env.AIDR_ONBOARDING_EVIDENCE_DIR ?? "").trim();
	if (target) {
		mkdirSync(resolve(target), { recursive: true });
		writeFileSync(join(resolve(target), "customer-onboarding-evidence.json"), body, { mode: 0o600 });
	}
}
function record(outcome, code, detail, extra = {}) {
	return { schema_version: 1, gate: GATE, outcome, reason_code: code, detail, exit_code: outcome === "blocked" ? EXIT_EXTERNAL_INPUT_REQUIRED : EXIT_ACCEPTANCE_FAILURE, checks, checked_at: new Date().toISOString(), ...extra };
}
function reportFailure(error) {
	const known = error instanceof GateOutcome;
	const outcome = known ? error.outcome : "failed";
	const code = known ? error.code : "CUSTOMER_ACCEPTANCE_FAILED";
	const detail = known ? error.detail : (error?.message ?? String(error));
	const entry = record(outcome, code, detail, known && error.requirement ? { requirement: error.requirement } : {});
	try { writeEvidence(entry); } catch { /* evidence is best effort when the run already failed */ }
	console.error(`${outcome === "blocked" ? "BLOCKED" : "FAIL"} ${code}: ${detail}`);
	if (entry.requirement) console.error(`REQUIRED: ${entry.requirement}`);
	if (outcome === "blocked") console.error(`No onboarding PASS is reported without ${entry.requirement}.`);
	console.log(`AIDR_GATE_RESULT ${JSON.stringify(entry)}`);
	process.exitCode = entry.exit_code;
}

async function main() {
	const requested = (values.deployment ?? process.env.AIDR_DEPLOYMENT_DIR ?? "").trim();
	if (!requested) {
		stopBlocked(
			"CUSTOMER_DEPLOYMENT_REQUIRED",
			"no customer installation was supplied, and this gate never assumes a .aidr-deploy/ directory left behind by an earlier manual run",
			"an operator-supplied live loopback installation (--deployment <installed deployment dir> or AIDR_DEPLOYMENT_DIR)",
		);
	}
	const installation = resolve(requested);
	if (!existsSync(installation)) {
		stopBlocked(
			"CUSTOMER_DEPLOYMENT_NOT_FOUND",
			`no prepared installation exists at ${installation}`,
			"a prepared, running loopback installation (node scripts/deployment-prepare.mjs --development --output <dir>, then start the stack)",
		);
	}
	const files = {
		"deployment.json": join(installation, "deployment.json"),
		".env": join(installation, ".env"),
		".env.ingress": join(installation, ".env.ingress"),
		"ingress/device-start.mjs": join(installation, "ingress", "device-start.mjs"),
	};
	const missing = Object.entries(files).filter(([, path]) => !existsSync(path)).map(([name]) => name);
	if (missing.length > 0) {
		stopInvalid("CUSTOMER_DEPLOYMENT_INCOMPLETE", `${installation} is not a prepared installation; missing ${missing.join(", ")}. Prepare the installation before rehearsing onboarding.`);
	}
	let manifest;
	try { manifest = JSON.parse(readFileSync(files["deployment.json"], "utf8")); }
	catch (error) { stopInvalid("CUSTOMER_DEPLOYMENT_INVALID", `${files["deployment.json"]} is not readable JSON: ${error.message}`); }
	let base;
	try { base = new URL(manifest?.supabase_url ?? ""); }
	catch { stopInvalid("CUSTOMER_DEPLOYMENT_INVALID", `deployment.json supabase_url is not an absolute URL: ${JSON.stringify(manifest?.supabase_url ?? null)}`); }
	if (manifest.development !== true || !LOOPBACK_HOSTS.includes(base.hostname)) {
		stopInvalid("CUSTOMER_DEPLOYMENT_NOT_ISOLATED", `Only isolated loopback development installations may receive fixtures (development=${JSON.stringify(manifest.development)}, host=${base.hostname})`);
	}
	const env = parseEnvFile(files[".env"]);
	const ingressEnv = parseEnvFile(files[".env.ingress"]);
	for (const [name, value] of [["ANON_KEY", env.ANON_KEY], ["SERVICE_ROLE_KEY", env.SERVICE_ROLE_KEY]]) {
		if (!value || value.startsWith("REPLACE_")) stopInvalid("CUSTOMER_DEPLOYMENT_INCOMPLETE", `${name} in ${files[".env"]} is empty or a placeholder; fill the customer project's credentials before rehearsing onboarding`);
	}
	for (const name of ["AIDR_DEVICE_START_INGRESS_SECRET", "AIDR_DEVICE_START_PROXY_TOKEN", "AIDR_DEVICE_START_UPSTREAM_URL", "AIDR_DEVICE_START_ANON_KEY"]) {
		if (!ingressEnv[name]) stopInvalid("CUSTOMER_DEPLOYMENT_INCOMPLETE", `${files[".env.ingress"]} is missing ${name}`);
	}

	// A live host answering with the installation's own credentials is an external
	// input this repository cannot manufacture; its absence is a recorded blocker.
	let health;
	try {
		health = await fetch(new URL("/auth/v1/health", base), { headers: { apikey: env.ANON_KEY }, signal: AbortSignal.timeout(10000) });
	} catch (error) {
		stopBlocked(
			"CUSTOMER_CONTROL_PLANE_UNREACHABLE",
			`no live control plane answered ${base.origin}/auth/v1/health (${error?.message ?? String(error)})`,
			"a running loopback customer control plane",
		);
	}
	if (health.status === 401 || health.status === 403) {
		stopInvalid("CUSTOMER_DEPLOYMENT_CREDENTIALS_REJECTED", `${base.origin} rejected the credentials in ${files[".env"]} (HTTP ${health.status}); the installation and the running host do not match`);
	}
	if (!health.ok) stopInvalid("CUSTOMER_CONTROL_PLANE_UNHEALTHY", `${base.origin}/auth/v1/health returned HTTP ${health.status}`);

	const requestedFixture = (values["fixture-dir"] ?? process.env.AIDR_ONBOARDING_FIXTURE_DIR ?? "").trim();
	try {
		if (requestedFixture) {
			fixtureDirectory = resolve(requestedFixture);
			if (existsSync(fixtureDirectory)) stopInvalid("CUSTOMER_FIXTURE_DIR_EXISTS", `fixture directory ${fixtureDirectory} already exists; remove it or choose a fresh path so the gate can never depend on leftover rehearsal state`);
			mkdirSync(fixtureDirectory, { recursive: true, mode: 0o700 });
		} else {
			fixtureDirectory = mkdtempSync(join(tmpdir(), "aidr-customer-onboarding-"));
		}
		const insideRepository = isInside(repositoryRoot, fixtureDirectory);
		const insideInstallation = isInside(installation, fixtureDirectory);
		if (insideRepository || insideInstallation) {
			stopInvalid("CUSTOMER_FIXTURE_NOT_ISOLATED", `fixture directory ${fixtureDirectory} is inside ${insideRepository ? "the repository" : "the installation"}; the customer rehearsal fixture must be disposable state outside both`);
		}
		for (const file of ["deployment.json", ".env", ".env.ingress"]) {
			copyFileSync(files[file], join(fixtureDirectory, file));
			chmodSync(join(fixtureDirectory, file), 0o600);
		}
		copyTree(join(installation, "ingress"), join(fixtureDirectory, "ingress"));
	} catch (error) {
		if (error instanceof GateOutcome) throw error;
		stopInvalid("CUSTOMER_FIXTURE_UNBUILDABLE", `the disposable fixture could not be built from ${installation}: ${error?.message ?? String(error)}`);
	}

	const email = `customer-${randomBytes(8).toString("hex")}@example.test`;
	const password = randomBytes(32).toString("base64url");
	const args = [bootstrapScript, "--deployment", fixtureDirectory, "--email", email, "--name", "Customer acceptance fixture", "--seats", "5"];
	function bootstrap(extra = [], expected = 0) {
		const run = spawnSync(process.execPath, [...args, ...extra], { input: password, encoding: "utf8", timeout: 60000 });
		assert.equal(run.status, expected, run.stderr || run.error?.message || `bootstrap exited with ${run.status}`); assert.ok(!`${run.stdout}${run.stderr}`.includes(password));
	}
	async function request(path, token = env.SERVICE_ROLE_KEY, body, extraHeaders = {}) {
		const response = await fetch(new URL(path, base), { method: body === undefined ? "GET" : "POST", headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...extraHeaders }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
		return { status: response.status, data: await response.json() };
	}
	async function signedDeviceStart() {
		const { createDeviceStartIngress } = await import(pathToFileURL(join(fixtureDirectory, "ingress/device-start.mjs")).href);
		const server = createDeviceStartIngress({
			signingSecret: ingressEnv.AIDR_DEVICE_START_INGRESS_SECRET,
			proxyToken: ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN,
			upstreamUrl: ingressEnv.AIDR_DEVICE_START_UPSTREAM_URL,
			trustedPeers: "127.0.0.1",
			anonKey: ingressEnv.AIDR_DEVICE_START_ANON_KEY,
		});
		await new Promise((resolveListen, rejectListen) => {
			server.once("error", rejectListen);
			server.listen(0, "127.0.0.1", resolveListen);
		});
		try {
			const response = await fetch(`http://127.0.0.1:${server.address().port}/functions/v1/device-start`, {
				method: "POST",
				headers: { "Content-Type": "application/json", "X-AIDR-Proxy-Token": ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN, "X-AIDR-Proxy-Client-IP": "127.0.0.1" },
				body: "{}",
				signal: AbortSignal.timeout(10000),
			});
			return { status: response.status, data: await response.json() };
		} finally {
			await new Promise((done) => server.close(done));
		}
	}
	bootstrap();
	const receipt = JSON.parse(readFileSync(join(fixtureDirectory, "bootstrap-receipt.json"), "utf8"));
	assert.equal(receipt.state, "complete"); assert.notEqual(receipt.tenant_id, receipt.user_id);
	checks.push("first owner provisioned with a separate enterprise tenant");
	bootstrap(["--resume"]); bootstrap([], 1); bootstrap(["--resume", "--seats", "6"], 1);
	checks.push("resume is idempotent; duplicate and changed configuration refused");
	const login = await request("/auth/v1/token?grant_type=password", env.ANON_KEY, { email, password });
	assert.equal(login.status, 200); const token = login.data.access_token;
	checks.push("provisioned owner signs in without SMTP or OAuth");
	const status = await request("/functions/v1/pilot-status", token, undefined, { "X-AIDR-Tenant-ID": receipt.tenant_id });
	assert.equal(status.status, 200); assert.equal(status.data.status, "approved"); assert.equal(status.data.tenant_id, receipt.tenant_id);
	checks.push("browser onboarding sees the enterprise enrollment approval");
	const forbidden = await request("/rest/v1/rpc/bootstrap_customer", token, { p_user_id: receipt.user_id, p_bootstrap_id: receipt.bootstrap_id, p_name: receipt.name, p_seats: 100 });
	assert.equal(forbidden.status, 403); checks.push("ordinary authenticated session cannot provision or increase seats");
	const pilot = await request(`/rest/v1/pilot_applications?user_id=eq.${receipt.user_id}&tenant_id=eq.${receipt.tenant_id}&select=tenant_id,status`);
	assert.equal(pilot.data[0].tenant_id, receipt.tenant_id);
	const ent = await request(`/rest/v1/entitlements?tenant_id=eq.${receipt.tenant_id}&select=included_agents`);
	assert.equal(ent.data[0].included_agents, 5); checks.push("approval and seat allocation bound to enterprise tenant");
	const started = await signedDeviceStart();
	assert.equal(started.status, 200, "signed ingress must bootstrap the customer's device");
	const device = started.data;
	assert.equal((await request("/functions/v1/device-verify", token, { user_code: device.user_code }, { "X-AIDR-Tenant-ID": receipt.tenant_id })).status, 200);
	await new Promise((done) => setTimeout(done, (device.interval_seconds + 1) * 1000));
	const exchange = (await request("/functions/v1/device-poll", token, { device_code: device.device_code })).data;
	const enrolled = await request("/functions/v1/enroll", exchange.enrollment_token, { iid: `customer-${randomBytes(8).toString("hex")}`, agent_runtime: "claude-code" });
	assert.equal(enrolled.status, 200); assert.ok(enrolled.data.entitlement_signed);
	const agent = await request(`/rest/v1/agents?user_id=eq.${receipt.user_id}&select=tenant_id`);
	assert.equal(agent.data.length, 1); assert.equal(agent.data[0].tenant_id, receipt.tenant_id);
	checks.push("device flow enrolls agent in the customer's enterprise tenant");
	const initial = await request("/functions/v1/policy-management", token, { tenant_id: receipt.tenant_id, action: "read" });
	assert.equal(initial.data.version, 1);
	checks.push("new customer has a published central policy before its first tool call");
	const publish = await request("/functions/v1/policy-management", token, { tenant_id: receipt.tenant_id, action: "publish", expected_version: 1, policy: { mcp_deny_tools: ["customer.exfiltrate"] } });
	assert.equal(publish.status, 200);
	const policy = await request("/functions/v1/policy", enrolled.data.api_key);
	assert.equal(policy.status, 200); assert.deepEqual(policy.data.runtime_policy, { mcp_deny_tools: ["customer.exfiltrate"] });
	checks.push("enrolled API key receives the enterprise team's published policy");
	mkdirSync(join(fixtureDirectory, "private-ui-fixture"), { recursive: true, mode: 0o700 });
	writeFileSync(join(fixtureDirectory, "private-ui-fixture/login.json"), JSON.stringify({ email, password, tenant_id: receipt.tenant_id }), { mode: 0o600 });
	const entry = {
		schema_version: 1, gate: GATE, outcome: "passed", passed: true, checked_at: new Date().toISOString(), checks,
		deployment: { mode: manifest.mode, development: manifest.development, supabase_url: base.origin, source_commit: manifest.source_commit ?? null },
		fixture: { disposable: true, kept: keepEnv, ...(keepEnv ? { path: displayPath(fixtureDirectory) } : {}) },
		scope: "Isolated local rehearsal; not customer field acceptance",
	};
	writeEvidence(entry);
	if (keepEnv) console.log(`${checks.length} customer onboarding checks passed; credentials remain in the private rehearsal directory (${displayPath(fixtureDirectory)}), which sibling rehearsal gates accept as their deployment argument.`);
	else console.log(`${checks.length} customer onboarding checks passed; the disposable rehearsal fixture was removed and ${installation} was left untouched.`);
	console.log(`AIDR_GATE_RESULT ${JSON.stringify(entry)}`);
}

if (values.help) {
	console.log(usage);
} else {
	try { await main(); }
	catch (error) { reportFailure(error); }
	finally { removeFixture(); }
}
