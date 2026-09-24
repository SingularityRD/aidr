import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { parse } = createRequire(join(root, "packages/core/package.json"))("yaml");
const compose = parse(readFileSync(join(root, "docker-compose.aig.yml"), "utf8"));
const environment = (service) => Object.fromEntries(compose.services[service].environment.map((entry) => [entry.slice(0, entry.indexOf("=")), entry.slice(entry.indexOf("=") + 1)]));
const docker = spawnSync("docker", ["compose", "version"], { encoding: "utf8", timeout: 30_000 });
const dockerComposeAvailable = !docker.error && docker.status === 0;

test("AIG compose defaults to a single-host bridge that needs no external database or proxy", () => {
	const bridge = environment("aig-bridge");
	assert.equal(bridge.BRIDGE_TASK_BACKEND, "${BRIDGE_TASK_BACKEND:-sqlite}");
	assert.equal(bridge.BRIDGE_HA_REQUIRED, "${BRIDGE_HA_REQUIRED:-false}");
	assert.equal(bridge.BRIDGE_TASK_DB, "${BRIDGE_TASK_DB:-/app/state/tasks.db}");
	assert.equal(bridge.BRIDGE_EGRESS_PROXY_URL, "${BRIDGE_EGRESS_PROXY_URL:-http://aig-egress:3128}");
	assert.equal(bridge.BRIDGE_RUNTIME_EGRESS_REQUIRED, "${BRIDGE_RUNTIME_EGRESS_REQUIRED:-true}", "egress enforcement must stay on");
	assert.equal(bridge.BRIDGE_AUTH_REQUIRED, "${BRIDGE_AUTH_REQUIRED:-true}");
	const agent = environment("aig-agent");
	assert.equal(agent.HTTP_PROXY, "${BRIDGE_EGRESS_PROXY_URL:-http://aig-egress:3128}");
	assert.equal(agent.HTTPS_PROXY, "${BRIDGE_EGRESS_PROXY_URL:-http://aig-egress:3128}");
	assert.equal(compose.services["aig-agent"].depends_on["aig-egress"].condition, "service_healthy");

	const example = readFileSync(join(root, ".env.aig.example"), "utf8");
	assert.match(example, /^BRIDGE_TASK_BACKEND=sqlite$/m);
	assert.match(example, /^BRIDGE_HA_REQUIRED=false$/m);
	assert.match(example, /^BRIDGE_EGRESS_PROXY_URL=http:\/\/aig-egress:3128$/m);
	// The PostgreSQL HA switch is documented but never active by default.
	assert.match(example, /^# BRIDGE_HA_REQUIRED=true$/m);
	assert.match(example, /^# BRIDGE_TASK_BACKEND=postgres$/m);
	assert.match(example, /^# BRIDGE_TASK_POSTGRES_DSN=postgresql:\/\//m);
});

test("only the pinned egress gateway reaches the Internet and only the bridge publishes a port", () => {
	const networks = compose.networks;
	assert.equal(networks["aidr-aig-network"].internal, true);
	assert.equal(networks["aidr-aig-edge"].driver_opts["com.docker.network.bridge.enable_ip_masquerade"], "false");
	assert.notEqual(networks["aidr-aig-egress"].internal, true);
	const attached = (service) => compose.services[service].networks;
	assert.deepEqual(attached("aig-server"), ["aidr-aig-network"]);
	assert.deepEqual(attached("aig-agent"), ["aidr-aig-network"]);
	assert.deepEqual(attached("aig-bridge"), ["aidr-aig-network", "aidr-aig-edge"]);
	assert.deepEqual(attached("aig-egress"), ["aidr-aig-network", "aidr-aig-egress"]);
	for (const [name, service] of Object.entries(compose.services)) {
		if (name === "aig-bridge") assert.deepEqual(service.ports, ["${AIG_BIND_ADDRESS:-127.0.0.1}:${AIG_BRIDGE_PORT:-8099}:8099"]);
		else assert.equal(Object.hasOwn(service, "ports"), false, `${name} must not publish a port`);
	}

	const egress = compose.services["aig-egress"];
	assert.match(egress.image, /^ubuntu\/squid:[^@\s]+@sha256:[a-f0-9]{64}$/, "the egress gateway image must be digest-pinned");
	assert.equal(egress.read_only, true);
	assert.deepEqual(egress.cap_drop, ["ALL"]);
	assert.deepEqual(egress.cap_add, ["SETUID", "SETGID"]);
	assert.deepEqual(egress.security_opt, ["no-new-privileges:true"]);
	for (const name of ["aig-server", "aig-agent", "aig-bridge"]) assert.match(compose.services[name].image, /^aidr-aig-/, `${name} needs a stable local image tag for air-gap bundles`);
});

test("the shipped egress policy denies by default and refuses non-public destinations first", () => {
	const squid = readFileSync(join(root, "deploy/onprem/egress/squid.conf"), "utf8");
	const rules = squid.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith("http_access"));
	assert.equal(rules.at(-1), "http_access deny all");
	const allow = rules.indexOf("http_access allow aidr_allowlist");
	assert.ok(allow > 0, "the allowlist is the only allow rule");
	assert.equal(rules.filter((rule) => rule.startsWith("http_access allow")).length, 1);
	for (const deny of ["http_access deny !aig_clients", "http_access deny CONNECT !SSL_ports", "http_access deny to_localhost", "http_access deny non_public_dst"]) {
		assert.ok(rules.indexOf(deny) !== -1 && rules.indexOf(deny) < allow, `${deny} must precede the allowlist`);
	}
	const blocked = squid.split(/\r?\n/).filter((line) => line.startsWith("acl non_public_dst dst")).flatMap((line) => line.split(/\s+/).slice(3));
	for (const range of ["10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "::1", "fc00::/7", "fe80::/10"]) {
		assert.ok(blocked.includes(range), `${range} must be refused`);
	}
	assert.match(squid, /^cache deny all$/m);
	assert.match(squid, /^forwarded_for delete$/m);
	const allowlist = readFileSync(join(root, "deploy/onprem/egress/allowlist.txt"), "utf8").split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
	assert.deepEqual(allowlist, [], "the shipped allowlist must not pre-authorize any scan destination");
});

test("docker compose accepts the standalone AIG stack with the example environment", { skip: !dockerComposeAvailable && "docker compose is not installed" }, (t) => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-aig-compose-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const envFile = join(directory, ".env.aig");
	const filled = {
		AIG_AGENT_SHARED_SECRET: "a".repeat(64),
		AIG_SIGNING_PUBLIC_KEY_HOST_PATH: join(directory, "aig-release-public.pem"),
		AIG_TRUSTED_SIGNING_KEY_ID: "fixture-key",
		AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256: "b".repeat(64),
		AIG_EXPECTED_DATA_BUNDLE_ID: "c".repeat(64),
		AIG_EXPECTED_SOURCE_COMMIT: "d".repeat(40),
		BRIDGE_API_KEY: "e".repeat(64),
	};
	const example = readFileSync(join(root, ".env.aig.example"), "utf8").replace(/^([A-Z][A-Z0-9_]*)=$/gm, (line, name) => (filled[name] ? `${name}=${filled[name]}` : line));
	writeFileSync(envFile, example);
	const args = ["compose", "--env-file", envFile, "-f", join(root, "docker-compose.aig.yml")];
	const quiet = spawnSync("docker", [...args, "config", "--quiet"], { encoding: "utf8", timeout: 60_000 });
	assert.equal(quiet.status, 0, quiet.stderr);
	const resolved = parse(spawnSync("docker", [...args, "config"], { encoding: "utf8", timeout: 60_000 }).stdout);
	assert.equal(resolved.services["aig-bridge"].environment.BRIDGE_TASK_BACKEND, "sqlite");
	assert.equal(resolved.services["aig-bridge"].environment.BRIDGE_HA_REQUIRED, "false");
	assert.equal(resolved.services["aig-agent"].environment.HTTPS_PROXY, "http://aig-egress:3128");

	// Missing trust material still fails closed at configuration time.
	writeFileSync(envFile, example.replace(/^AIG_AGENT_SHARED_SECRET=.*$/m, "AIG_AGENT_SHARED_SECRET="));
	const missing = spawnSync("docker", [...args, "config", "--quiet"], { encoding: "utf8", timeout: 60_000 });
	assert.notEqual(missing.status, 0);
	assert.match(missing.stderr, /AIG_AGENT_SHARED_SECRET/);
});
