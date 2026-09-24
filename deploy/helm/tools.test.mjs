// Tests for the Helm operator tools: build-images.mjs and generate-secrets.mjs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const { parse } = createRequire(join(root, "packages/core/package.json"))("yaml");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function scratch(t) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-helm-tools-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	return dir;
}

function node(script, args, env = {}) {
	return spawnSync(process.execPath, [join(here, script), ...args], { encoding: "utf8", env: { ...process.env, ...env } });
}

test("build-images stages the migrations image with a checksum-bound atomic plan", (t) => {
	const dir = scratch(t);
	const output = join(dir, "images");
	const result = node("build-images.mjs", ["--output", output, "--only", "migrations", "--registry", "registry.example.internal", "--tag", "0.6.0"]);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /docker build -f \S+migrations\/Dockerfile -t registry\.example\.internal\/aidr\/migrations:0\.6\.0/);
	const context = join(output, "migrations");
	const plan = readFileSync(join(context, "migrate.sql"), "utf8");
	const manifest = JSON.parse(readFileSync(join(context, "migrations.manifest.json"), "utf8"));
	assert.equal(manifest.plan_sha256, sha256(plan));
	assert.ok(manifest.migration_count > 100);
	assert.match(plan, /^BEGIN;\nSELECT pg_advisory_xact_lock\(9112026\);/);
	assert.match(plan, /NOTIFY pgrst, 'reload schema';\nCOMMIT;\n$/);
	let previous = -1;
	for (const entry of manifest.migrations) {
		const source = readFileSync(join(root, "supabase/migrations", entry.name), "utf8");
		assert.equal(entry.sha256, sha256(source));
		const at = plan.indexOf(`VALUES('${entry.name}','${entry.sha256}')`);
		assert.ok(at > previous, `${entry.name} recorded in filename order`);
		previous = at;
	}
	assert.equal(statSync(join(context, "aidr-migrate.sh")).mode & 0o777, 0o755);
	const images = JSON.parse(readFileSync(join(output, "images.json"), "utf8"));
	assert.deepEqual(images.images.map((image) => image.ref), ["registry.example.internal/aidr/migrations:0.6.0"]);
});

test("aidr-migrate waits for storage, verifies the plan and applies it through psql", (t) => {
	const dir = scratch(t);
	const output = join(dir, "images");
	assert.equal(node("build-images.mjs", ["--output", output, "--only", "migrations"]).status, 0);
	const context = join(output, "migrations");
	const bin = join(dir, "bin");
	mkdirSync(bin);
	const log = join(dir, "psql.log");
	// Test double for psql: storage becomes ready on the second probe.
	writeFileSync(join(bin, "psql"), `#!/bin/sh
echo "$*" >> "${log}"
case "$*" in
  *"-tAc"*) n=$(grep -c -- "-tAc" "${log}"); if [ "$n" -ge 2 ]; then echo t; else echo f; fi ;;
  *) [ -f "$5" ] && echo applied ;;
esac
`);
	chmodSync(join(bin, "psql"), 0o755);
	writeFileSync(join(bin, "sleep"), "#!/bin/sh\nexit 0\n");
	chmodSync(join(bin, "sleep"), 0o755);
	const env = { PATH: `${bin}:${process.env.PATH}`, PGHOST: "db", PGPASSWORD: "fixture-only", AIDR_MIGRATION_ROOT: context, AIDR_MIGRATION_STORAGE_WAIT_SECONDS: "30" };
	const run = spawnSync("sh", [join(context, "aidr-migrate.sh")], { encoding: "utf8", env });
	assert.equal(run.status, 0, run.stderr);
	assert.match(run.stdout, /Verified\/applied \d+ migrations atomically/);
	const calls = readFileSync(log, "utf8").trim().split("\n");
	assert.equal(calls.filter((line) => line.includes("-tAc")).length, 2);
	assert.equal(calls.at(-1), `-X -v ON_ERROR_STOP=1 -f ${context}/migrate.sql`);

	writeFileSync(join(context, "migrate.sql"), `${readFileSync(join(context, "migrate.sql"), "utf8")}-- tampered\n`);
	const tampered = spawnSync("sh", [join(context, "aidr-migrate.sh")], { encoding: "utf8", env });
	assert.notEqual(tampered.status, 0);
	assert.match(tampered.stderr, /checksum mismatch/);

	const missing = spawnSync("sh", [join(context, "aidr-migrate.sh")], { encoding: "utf8", env: { ...env, PGPASSWORD: "" } });
	assert.notEqual(missing.status, 0);
});

test("build-images refuses an unreviewed upstream, unsafe tags and existing output", (t) => {
	const dir = scratch(t);
	const upstream = join(dir, "upstream");
	mkdirSync(join(upstream, "docker/volumes/functions/main"), { recursive: true });
	writeFileSync(join(upstream, "docker/volumes/functions/main/index.ts"), "Deno.serve(() => new Response('x'))\n");
	const unreviewed = node("build-images.mjs", ["--output", join(dir, "a"), "--only", "edge-functions", "--upstream-dir", upstream]);
	assert.notEqual(unreviewed.status, 0);
	assert.match(unreviewed.stderr, /not the reviewed Supabase commit 8c7a4d9dbbaf8b552893822e89d7bf06f33f9220/);
	const latest = node("build-images.mjs", ["--output", join(dir, "b"), "--only", "migrations", "--tag", "latest"]);
	assert.match(latest.stderr, /immutable version tag/);
	const noRegistry = node("build-images.mjs", ["--output", join(dir, "c"), "--only", "migrations", "--build"]);
	assert.match(noRegistry.stderr, /require --registry/);
	mkdirSync(join(dir, "d"));
	const exists = node("build-images.mjs", ["--output", join(dir, "d"), "--only", "migrations"]);
	assert.match(exists.stderr, /already exists/);
	const unknown = node("build-images.mjs", ["--output", join(dir, "e"), "--only", "studio"]);
	assert.match(unknown.stderr, /Unknown component "studio"/);
});

test("build-images stages the dashboard context the Dockerfile expects", { skip: existsSync(join(root, "packages/dashboard/dist/index.html")) ? false : "dashboard dist not built" }, (t) => {
	const dir = scratch(t);
	const output = join(dir, "images");
	const result = node("build-images.mjs", ["--output", output, "--only", "dashboard,aig-agent"]);
	assert.equal(result.status, 0, result.stderr);
	for (const file of ["Dockerfile", "server.mjs", "monitoring.mjs", "saml-config.mjs", "auth-templates/recovery.html", "public/index.html"]) {
		assert.ok(existsSync(join(output, "dashboard", file)), file);
	}
	assert.ok(existsSync(join(output, "aig-agent/aig_compat")));
	assert.match(result.stdout, /--build-arg AIG_AGENT_BASE=<registry>\/aidr\/aig-agent-base:0\.6\.0/);
});

function generate(t, extra = []) {
	const dir = scratch(t);
	const { publicKey } = generateKeyPairSync("ed25519");
	const keyFile = join(dir, "release.pub.pem");
	writeFileSync(keyFile, publicKey.export({ type: "spki", format: "pem" }));
	const output = join(dir, "creds");
	const result = node("generate-secrets.mjs", [
		"--output", output, "--namespace", "aidr-prod",
		"--dashboard-url", "https://aidr.example.com", "--api-url", "https://api.aidr.example.com",
		"--artifact-verification-public-key-file", keyFile, ...extra,
	]);
	return { dir, output, result, keyFile };
}

test("generate-secrets writes strong, private Kubernetes Secrets without printing them", (t) => {
	const { output, result } = generate(t);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(statSync(output).mode & 0o777, 0o700);
	const platform = parse(readFileSync(join(output, "platform-secret.yaml"), "utf8"));
	const functions = parse(readFileSync(join(output, "functions-secret.yaml"), "utf8"));
	for (const file of ["platform-secret.yaml", "functions-secret.yaml", ".env", "deployment.json", "agent-config.json", "readiness.env"]) {
		assert.equal(statSync(join(output, file)).mode & 0o777, 0o600, file);
	}
	assert.equal(platform.kind, "Secret");
	assert.equal(platform.metadata.name, "aidr-platform");
	assert.equal(platform.metadata.namespace, "aidr-prod");
	const data = platform.stringData;
	assert.deepEqual(Object.keys(data).sort(), ["anon-key", "jwt-secret", "metrics-token", "postgres-password", "service-role-key"]);
	for (const key of ["postgres-password", "jwt-secret", "metrics-token"]) assert.match(data[key], /^[a-f0-9]{64}$/);
	for (const [key, role] of [["anon-key", "anon"], ["service-role-key", "service_role"]]) {
		const [header, payload, signature] = data[key].split(".");
		assert.equal(createHmac("sha256", data["jwt-secret"]).update(`${header}.${payload}`).digest("base64url"), signature);
		const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
		assert.equal(claims.role, role);
		assert.ok(claims.exp - claims.iat >= 364 * 86400);
	}
	for (const secret of Object.values(data)) assert.ok(!result.stdout.includes(secret), "no secret printed");

	const env = functions.stringData;
	assert.equal(functions.metadata.name, "aidr-functions");
	const signingKey = createPrivateKey({ key: Buffer.from(env.AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64, "base64"), format: "der", type: "pkcs8" });
	assert.equal(signingKey.asymmetricKeyType, "ed25519");
	assert.equal(Buffer.from(env.AIDR_PACK_MASTER_KEY_B64, "base64").length, 32);
	assert.ok(Buffer.byteLength(env.AIDR_DEVICE_START_INGRESS_SECRET) >= 32);
	const delegation = createPrivateKey({ key: Buffer.from(env.AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64, "base64"), format: "der", type: "pkcs8" });
	const delegationPublic = createPublicKey({ key: Buffer.from(env.AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64, "base64"), format: "der", type: "spki" });
	assert.ok(verify(null, Buffer.from("probe"), delegationPublic, sign(null, Buffer.from("probe"), delegation)));

	const agentConfig = JSON.parse(readFileSync(join(output, "agent-config.json"), "utf8"));
	assert.equal(agentConfig.control_plane.endpoint, "https://api.aidr.example.com/functions/v1");
	const licensing = createPublicKey(agentConfig.licensing.public_keys_pem[0]);
	assert.ok(verify(null, Buffer.from("entitlement"), licensing, sign(null, Buffer.from("entitlement"), signingKey)));
	const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
	assert.equal(deployment.mode, "self-hosted");
	assert.equal(deployment.supabase_url, "https://api.aidr.example.com");
	assert.equal(readFileSync(join(output, ".env"), "utf8"), `ANON_KEY=${data["anon-key"]}\nSERVICE_ROLE_KEY=${data["service-role-key"]}\n`);
});

test("generate-secrets refuses insecure or ambiguous input", (t) => {
	const cases = [
		[["--api-url", "http://api.aidr.example.com"], /--api-url must be an https:\/\/ origin/],
		[["--dashboard-url", "https://aidr.example.com/app"], /--dashboard-url must be an https:\/\/ origin/],
		[["--namespace", "Bad_Name"], /--namespace must be a DNS-1123 label/],
	];
	for (const [extra, message] of cases) {
		const { result } = generate(t, extra);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, message);
	}
	const dir = scratch(t);
	const privateKey = join(dir, "private.pem");
	writeFileSync(privateKey, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }));
	const withPrivate = node("generate-secrets.mjs", ["--output", join(dir, "x"), "--dashboard-url", "https://a.example.com", "--api-url", "https://b.example.com", "--artifact-verification-public-key-file", privateKey]);
	assert.match(withPrivate.stderr, /Ed25519 SPKI public key/);
	const withoutKey = node("generate-secrets.mjs", ["--output", join(dir, "y"), "--dashboard-url", "https://a.example.com", "--api-url", "https://b.example.com"]);
	assert.match(withoutKey.stderr, /artifact-verification-public-key-file is required/);
	const { output, keyFile } = generate(t);
	const again = node("generate-secrets.mjs", ["--output", output, "--dashboard-url", "https://a.example.com", "--api-url", "https://b.example.com", "--artifact-verification-public-key-file", keyFile]);
	assert.match(again.stderr, /generated exactly once/);
});
