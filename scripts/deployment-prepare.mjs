#!/usr/bin/env node
import { createHash, createHmac, generateKeyPairSync, randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requireCore = createRequire(join(root, "packages/core/package.json"));
const { parse, stringify } = existsSync(join(root, "deploy/vendor/yaml.cjs")) ? requireCore(join(root, "deploy/vendor/yaml.cjs")) : requireCore("yaml");
// Avoid Node's recursive cp binding failing on Windows paths with non-ASCII characters.
function cpSync(source, destination, options = {}) {
	if (options.filter && !options.filter(source)) return;
	if (statSync(source).isDirectory()) {
		mkdirSync(destination, { recursive: true });
		for (const entry of readdirSync(source)) cpSync(join(source, entry), join(destination, entry), options);
	} else { mkdirSync(dirname(destination), { recursive: true }); copyFileSync(source, destination); }
}
const { values } = parseArgs({ options: {
	mode: { type: "string", default: "self-hosted" }, output: { type: "string", default: ".aidr-deploy" },
	"upstream-dir": { type: "string" }, "dashboard-url": { type: "string" }, "supabase-url": { type: "string" }, development: { type: "boolean", default: false },
	"project-name": { type: "string" }, "device-start-upstream-url": { type: "string" },
	region: { type: "string" }, "tenant-region": { type: "string" }, "regions-manifest": { type: "string" },
} });
if (!["self-hosted", "cloud"].includes(values.mode)) throw new Error("mode must be self-hosted or cloud");
const output = resolve(values.output);
if (existsSync(output)) throw new Error("Output already exists; reuse its secrets and data. Choose a new output for a separate installation.");
function origin(value, fallback) {
	const url = new URL(value || (values.development ? fallback : ""));
	if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("Deployment URLs must be origins without credentials or paths");
	const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (url.protocol !== "https:" && !(values.development && local && url.protocol === "http:")) throw new Error("HTTPS required; --development permits loopback HTTP only");
	return url.origin;
}
const dashboardUrl = origin(values["dashboard-url"], "http://localhost:8080");
const supabaseUrl = origin(values["supabase-url"], "http://localhost:8000");
const projectName = values["project-name"] || `aidr-${randomBytes(6).toString("hex")}`;
if (!/^[a-z][a-z0-9_-]{0,62}$/.test(projectName)) throw new Error("Invalid Compose project name");
// Region and residency entries are operator declarations, not verified legal or
// provider facts. Preparation refuses an undeclared region, a tenant region that
// differs from the deployment region, a placeholder residency location and a
// region whose declared public API origin is not this installation's origin.
const regionsManifestPath = resolve(values["regions-manifest"] || join(root, "deploy/regions.manifest.json"));
if (!existsSync(regionsManifestPath)) throw new Error("Deployment region manifest is missing; declare the regions this installation may use before preparing deployment");
let regionManifest;
try {
	regionManifest = JSON.parse(readFileSync(regionsManifestPath, "utf8"));
} catch {
	throw new Error("Deployment region manifest is not valid JSON");
}
const regions = regionManifest.regions;
if (regionManifest.schema_version !== 1 || !regions || typeof regions !== "object" || Array.isArray(regions) || Object.keys(regions).length === 0) {
	throw new Error("Deployment region manifest must declare schema_version 1 and a non-empty regions object");
}
if (Object.keys(regions).some((id) => !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id))) throw new Error("Deployment region manifest contains an invalid region id");
function declaredRegion(id, kind) {
	if (typeof id !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) {
		throw new Error(`${kind} region must be a lowercase identifier declared in the deployment region manifest`);
	}
	const entry = regions[id];
	if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
		throw new Error(`${kind} region "${id}" is not declared in the deployment region manifest; declare it before preparing this installation`);
	}
	if (entry.supabase_url !== null && (typeof entry.supabase_url !== "string" || origin(entry.supabase_url) !== entry.supabase_url)) {
		throw new Error(`Deployment region "${id}" must declare supabase_url as null or as an HTTPS origin without credentials or paths`);
	}
	const { residency } = entry;
	if (!residency || typeof residency !== "object" || Array.isArray(residency) || typeof residency.declared !== "boolean" || typeof residency.location !== "string" || residency.location.length === 0) {
		throw new Error(`Deployment region "${id}" must declare residency with a declared flag and a location`);
	}
	if (/^REPLACE/i.test(residency.location)) throw new Error(`Deployment region "${id}" still holds a placeholder residency location; declare the real location before preparing this installation`);
	return entry;
}
const regionId = values.region ?? "unassigned";
const tenantRegionId = values["tenant-region"] ?? regionId;
const deploymentRegion = declaredRegion(regionId, "Deployment");
declaredRegion(tenantRegionId, "Tenant");
if (deploymentRegion.supabase_url !== null && deploymentRegion.supabase_url !== supabaseUrl) {
	throw new Error(`Deployment region "${regionId}" declares public API origin ${deploymentRegion.supabase_url}, which is not this installation's --supabase-url origin`);
}
if (tenantRegionId !== regionId) {
	throw new Error(`Tenant declared region "${tenantRegionId}" does not match deployment region "${regionId}"; refusing to prepare a cross-region installation`);
}
const deviceUpstream = values.mode === "self-hosted"
	? "http://127.0.0.1:8000/functions/v1/device-start"
	: (values["device-start-upstream-url"] ?? "REPLACE_WITH_PROVIDER_DEVICE_START_URL");
if (values["device-start-upstream-url"]) {
	if (values.mode !== "cloud") throw new Error("Custom device-start upstream is only valid in cloud mode");
	const parsed = new URL(deviceUpstream);
	if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/functions/v1/device-start" || parsed.origin === supabaseUrl) {
		throw new Error("Cloud device-start upstream must use a provider HTTPS origin distinct from the public API proxy and the exact /functions/v1/device-start path");
	}
}
if (!existsSync(join(root, "packages/dashboard/dist/index.html"))) throw new Error("Build the dashboard before preparing deployment");
const upstreamSha = "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220";
const bundledUpstream = !values["upstream-dir"] && existsSync(join(root, "deploy/upstream-manifest.json"));
const upstream = resolve(values["upstream-dir"] || (bundledUpstream ? join(root, "deploy/upstream") : join(output, "upstream")));
if (values.mode === "self-hosted" && bundledUpstream) {
	const template = JSON.parse(readFileSync(join(root, "deploy/upstream-manifest.json"), "utf8"));
	if (template.commit !== upstreamSha || !Array.isArray(template.files) || template.files.length === 0) throw new Error("Invalid bundled upstream provenance");
	for (const entry of template.files) {
		if (!/^docker\/[a-zA-Z0-9_./-]+$/.test(entry.path) || entry.path.split("/").includes("..")) throw new Error("Invalid template path");
		if (createHash("sha256").update(readFileSync(join(upstream, entry.path))).digest("hex") !== entry.sha256) throw new Error(`Bundled upstream changed: ${entry.path}`);
	}
} else if (values.mode === "self-hosted") {
	if (!values["upstream-dir"]) {
		mkdirSync(output, { recursive: true, mode: 0o700 });
		execFileSync("git", ["clone", "--depth", "1", "--branch", "self-hosted/v0.8.1", "--filter=blob:none", "--sparse", "https://github.com/supabase/supabase.git", upstream], { stdio: "inherit" });
		execFileSync("git", ["-C", upstream, "sparse-checkout", "set", "docker"], { stdio: "inherit" });
	}
	const actual = execFileSync("git", ["-C", upstream, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
	if (actual !== upstreamSha) throw new Error("Upstream commit does not match the reviewed Supabase release");
	if (execFileSync("git", ["-C", upstream, "status", "--porcelain", "--", "docker"], { encoding: "utf8" }).trim()) throw new Error("Upstream Docker configuration has local changes");
}
mkdirSync(output, { recursive: true, mode: 0o700 });
const compose = values.mode === "self-hosted" ? parse(readFileSync(join(upstream, "docker/docker-compose.yml"), "utf8")) : { services: {}, volumes: {} };
compose.name = projectName;
if (values.mode === "self-hosted") cpSync(join(upstream, "docker/volumes"), join(output, "volumes"), { recursive: true });
const secret = (bytes = 32) => randomBytes(bytes).toString("hex");
const deviceIngressSecret = secret(32);
const deviceProxyToken = secret(32);
const env = values.mode === "self-hosted" ? Object.fromEntries(readFileSync(join(upstream, "docker/.env.example"), "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)])) : {};
const signing = generateKeyPairSync("ed25519");
const delegationSigning = generateKeyPairSync("ed25519");
const keyId = `aidr-${secret(6)}`;
const delegationKeyId = `aidr-delegation-${secret(6)}`;
Object.assign(env, {
	COMPOSE_FILE: "compose.yml",
	SUPABASE_PUBLIC_URL: supabaseUrl, API_EXTERNAL_URL: `${supabaseUrl}/auth/v1`, SITE_URL: dashboardUrl,
	ADDITIONAL_REDIRECT_URLS: `${dashboardUrl}/auth/callback`, DISABLE_SIGNUP: "true", ENABLE_ANONYMOUS_USERS: "false", ENABLE_PHONE_SIGNUP: "false", ENABLE_PHONE_AUTOCONFIRM: "false",
	POSTGRES_PASSWORD: secret(), JWT_SECRET: secret(), DASHBOARD_PASSWORD: secret(), SECRET_KEY_BASE: secret(64), VAULT_ENC_KEY: secret(16), REALTIME_DB_ENC_KEY: secret(8), PG_META_CRYPTO_KEY: secret(),
	LOGFLARE_PUBLIC_ACCESS_TOKEN: secret(), LOGFLARE_PRIVATE_ACCESS_TOKEN: secret(), POOLER_TENANT_ID: `aidr-${secret(8)}`, MINIO_ROOT_PASSWORD: secret(),
	S3_PROTOCOL_ACCESS_KEY_ID: secret(16), S3_PROTOCOL_ACCESS_KEY_SECRET: secret(),
	OPENAI_API_KEY: "", SMTP_HOST: "", SMTP_USER: "", SMTP_PASS: "", SMTP_ADMIN_EMAIL: "", SMTP_SENDER_NAME: "AIDR", FUNCTIONS_VERIFY_JWT: "false",
});
const jwt = (role) => {
	const now = Math.floor(Date.now() / 1000);
	const unsigned = `${Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify({ role, iss: "supabase", iat: now, exp: now + 365 * 86400 })).toString("base64url")}`;
	return `${unsigned}.${createHmac("sha256", env.JWT_SECRET).update(unsigned).digest("base64url")}`;
};
env.ANON_KEY = values.mode === "cloud" ? "REPLACE_WITH_PROJECT_ANON_KEY" : jwt("anon");
env.SERVICE_ROLE_KEY = values.mode === "cloud" ? "REPLACE_WITH_PROJECT_SERVICE_ROLE_KEY" : jwt("service_role");
const functionEnv = {
	AIDR_ALLOWED_ORIGINS: dashboardUrl, AIDR_DASHBOARD_URL: dashboardUrl, AIDR_DASHBOARD_VERIFY_URL: `${dashboardUrl}/verify`,
	AIDR_ENTITLEMENT_SIGNING_KEY_ID: keyId, AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: signing.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
	AIDR_REVOCATION_SIGNING_KEY_ID: keyId, AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: signing.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
	AIDR_DELEGATION_ISSUER: supabaseUrl, AIDR_DELEGATION_SIGNING_KEY_ID: delegationKeyId,
	AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64: delegationSigning.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
	AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64: delegationSigning.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
	AIDR_PACK_MASTER_KEY_B64: randomBytes(32).toString("base64"), AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "false",
	AIDR_DEVICE_START_INGRESS_SECRET: deviceIngressSecret,
};
for (const service of Object.values(compose.services)) {
	delete service.container_name; delete service.ports;
	service.logging = { driver: "json-file", options: { "max-size": "20m", "max-file": "3" } };
}
if (values.mode === "self-hosted") {
	delete compose.services.supavisor;
	compose.services["api-gw"].ports = ["127.0.0.1:8000:8000"];
	compose.services.functions.env_file = [".env.functions"];
	compose.services.db.volumes = compose.services.db.volumes.map((v) => v.startsWith("./volumes/db/data:") ? "aidr-db:/var/lib/postgresql/data" : v);
	compose.services.storage.volumes = ["aidr-storage:/var/lib/storage"];
	compose.services.imgproxy.volumes = ["aidr-storage:/var/lib/storage:ro"];
	compose.volumes["aidr-db"] = {};
	compose.volumes["aidr-storage"] = {};
}
compose.services.dashboard = {
	build: "./dashboard", restart: "unless-stopped", ports: ["127.0.0.1:8080:8080"], read_only: true,
	cap_drop: ["ALL"], security_opt: ["no-new-privileges:true"],
	environment: { VITE_SUPABASE_URL: supabaseUrl, VITE_SUPABASE_ANON_KEY: "${ANON_KEY}", AIDR_AUTH_METHODS: "${AIDR_AUTH_METHODS:-password}" },
};
cpSync(join(root, "deploy/dashboard"), join(output, "dashboard"), { recursive: true });
cpSync(join(root, "deploy/ingress"), join(output, "ingress"), { recursive: true, filter: (p) => !p.includes(".test.") });
cpSync(join(root, "packages/dashboard/dist"), join(output, "dashboard/public"), { recursive: true });
cpSync(join(root, "supabase/functions"), join(output, "volumes/functions"), { recursive: true, filter: (p) => !p.includes("__tests__") });
cpSync(join(root, "supabase/migrations"), join(output, "migrations"), { recursive: true });
const write = (path, content) => writeFileSync(join(output, path), content, { mode: 0o600, flag: "wx" });
const envText = (items) => Object.entries(items).map(([name, value]) => `${name}=${value}`).join("\n") + "\n";
write(".env", envText(env));
write(".env.functions", envText(functionEnv));
write(".env.ingress", envText({
	AIDR_DEVICE_START_INGRESS_SECRET: deviceIngressSecret,
	AIDR_DEVICE_START_PROXY_TOKEN: deviceProxyToken,
	AIDR_DEVICE_START_UPSTREAM_URL: deviceUpstream,
	AIDR_DEVICE_START_ANON_KEY: env.ANON_KEY,
	AIDR_DEVICE_START_LISTEN_HOST: "127.0.0.1",
	AIDR_DEVICE_START_TRUSTED_PEERS: "127.0.0.1,::1",
	AIDR_DEVICE_START_LISTEN_PORT: "8191",
}));
write("compose.yml", stringify(compose));
write("agent-config.json", JSON.stringify({ mode: "managed", control_plane: { enabled: true, endpoint: `${supabaseUrl}/functions/v1`, timeout_seconds: 5, remote_policy_required: true, remote_policy_offline_grace_seconds: 3600 }, licensing: { require_signed_entitlements: true, public_keys_pem: [signing.publicKey.export({ type: "spki", format: "pem" })] } }, null, 2));
const migrations = readdirSync(join(output, "migrations")).filter((name) => name.endsWith(".sql")).sort().map((name) => ({ name, sha256: createHash("sha256").update(readFileSync(join(output, "migrations", name))).digest("hex") }));
function inventory(dir, prefix = "") {
	return readdirSync(dir).sort().flatMap((name) => {
		const path = join(dir, name);
		const relative = prefix ? `${prefix}/${name}` : name;
		return statSync(path).isDirectory() ? inventory(path, relative) : [{ path: relative, sha256: createHash("sha256").update(readFileSync(path)).digest("hex") }];
	});
}
const artifacts = [...inventory(join(output, "dashboard"), "dashboard"), ...inventory(join(output, "ingress"), "ingress"), ...inventory(join(output, "volumes/functions"), "volumes/functions")];
const source = existsSync(join(root, "release-source.json")) ? JSON.parse(readFileSync(join(root, "release-source.json"), "utf8")) : { commit: execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(), dirty: !!execFileSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" }).trim() };
write("deployment.json", JSON.stringify({ schema_version: 1, project_name: compose.name, mode: values.mode, development: values.development, prepared_at: new Date().toISOString(), source_commit: source.commit, source_has_changes: source.dirty, upstream_sha: values.mode === "self-hosted" ? upstreamSha : null, dashboard_url: dashboardUrl, supabase_url: supabaseUrl, region: regionId, tenant_region: tenantRegionId, regions, migrations, artifacts, note: "Prepared configuration, not a deployment acceptance record. Region and residency fields are operator declarations, not evidence of provider placement. The TLS renewal unit is prepared but not installed or enabled. TLS, authentication, backups and live smoke evidence required." }, null, 2));
console.log(`Prepared ${values.mode} installation at ${output}. Secrets written to private .env files; none printed.`);
