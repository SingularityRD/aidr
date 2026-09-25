#!/usr/bin/env node
/**
 * Generate the credentials a Kubernetes AIDR installation needs, once, into a
 * new private directory. The Helm chart never generates secrets; it only
 * references the two Secrets this script writes.
 *
 *   node deploy/helm/generate-secrets.mjs --output <new-dir> \
 *     --dashboard-url https://aidr.example.com --api-url https://api.aidr.example.com \
 *     --artifact-verification-public-key-file release-signing.pub.pem [--namespace aidr]
 *
 * Output (every file 0600, directory 0700, nothing printed):
 *   platform-secret.yaml    Secret: postgres-password, jwt-secret, anon-key,
 *                           service-role-key, metrics-token
 *   functions-secret.yaml   Secret: edge-function signing keys, pack keys,
 *                           device-start ingress secret
 *   deployment.json + .env  operator record for scripts/deployment-bootstrap.mjs
 *   agent-config.json       managed endpoint configuration for enrolled agents
 *   readiness.env           signing-key expiries for the readiness evidence worker
 *
 * Keep the directory in your secret manager or offline vault. Re-running with a
 * new directory creates a DIFFERENT installation identity; never do that for an
 * existing database.
 */
import { createHmac, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const { stringify } = createRequire(join(root, "packages/core/package.json"))("yaml");

const hex = (bytes) => randomBytes(bytes).toString("hex");
const KEY_LIFETIME_SECONDS = 365 * 86400;

function httpsOrigin(value, flag) {
	if (!value) throw new Error(`${flag} is required`);
	let url;
	try {
		url = new URL(value);
	} catch {
		throw new Error(`${flag} must be an absolute https:// origin`);
	}
	if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/" || value.endsWith("/")) {
		throw new Error(`${flag} must be an https:// origin without credentials, path or trailing slash`);
	}
	return url.origin;
}

function kubernetesName(value, flag) {
	if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) throw new Error(`${flag} must be a DNS-1123 label`);
	return value;
}

function artifactVerificationKey(path) {
	if (!path) throw new Error("--artifact-verification-public-key-file is required: agents verify signed release artifacts with it");
	let pem;
	try {
		pem = readFileSync(resolve(path), "utf8");
	} catch {
		throw new Error("Artifact verification public key file is missing or unreadable");
	}
	try {
		if (!pem.includes("-----BEGIN PUBLIC KEY-----") || pem.includes("PRIVATE KEY")) throw new Error();
		const key = createPublicKey(pem);
		if (key.asymmetricKeyType !== "ed25519") throw new Error();
		return key.export({ type: "spki", format: "pem" }).toString();
	} catch {
		throw new Error("Artifact verification public key must be an Ed25519 SPKI public key");
	}
}

/** HS256 Supabase API key for `role`, signed with the installation JWT secret. */
export function supabaseApiKey(role, jwtSecret, now = Math.floor(Date.now() / 1000)) {
	const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const unsigned = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ role, iss: "supabase", iat: now, exp: now + KEY_LIFETIME_SECONDS })}`;
	return `${unsigned}.${createHmac("sha256", jwtSecret).update(unsigned).digest("base64url")}`;
}

function secretManifest(name, namespace, stringData, component) {
	return stringify({
		apiVersion: "v1",
		kind: "Secret",
		metadata: {
			name,
			namespace,
			labels: { "app.kubernetes.io/part-of": "aidr", "app.kubernetes.io/component": component },
		},
		type: "Opaque",
		stringData,
	});
}

export function main(argv = process.argv.slice(2)) {
	const { values } = parseArgs({
		args: argv,
		options: {
			output: { type: "string" },
			namespace: { type: "string", default: "aidr" },
			"dashboard-url": { type: "string" },
			"api-url": { type: "string" },
			"platform-secret-name": { type: "string", default: "aidr-platform" },
			"functions-secret-name": { type: "string", default: "aidr-functions" },
			"artifact-verification-public-key-file": { type: "string" },
		},
	});
	if (!values.output) throw new Error("--output is required (a new directory)");
	const dashboardUrl = httpsOrigin(values["dashboard-url"], "--dashboard-url");
	const apiUrl = httpsOrigin(values["api-url"], "--api-url");
	const namespace = kubernetesName(values.namespace, "--namespace");
	const platformName = kubernetesName(values["platform-secret-name"], "--platform-secret-name");
	const functionsName = kubernetesName(values["functions-secret-name"], "--functions-secret-name");
	const artifactKeyPem = artifactVerificationKey(values["artifact-verification-public-key-file"]);
	const output = resolve(values.output);
	if (existsSync(output)) throw new Error("Output already exists; an installation's credentials are generated exactly once");

	mkdirSync(output, { recursive: true, mode: 0o700 });
	chmodSync(output, 0o700);
	if (process.platform !== "win32" && (statSync(output).mode & 0o077) !== 0) throw new Error("Output directory permits group or world access");
	const write = (name, content) => writeFileSync(join(output, name), content, { mode: 0o600, flag: "wx" });

	const now = Math.floor(Date.now() / 1000);
	const jwtSecret = hex(32);
	const anonKey = supabaseApiKey("anon", jwtSecret, now);
	const serviceRoleKey = supabaseApiKey("service_role", jwtSecret, now);
	const signing = generateKeyPairSync("ed25519");
	const delegation = generateKeyPairSync("ed25519");
	const signingPkcs8 = signing.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
	const keyId = `aidr-${hex(6)}`;
	const keysExpireAt = new Date((now + KEY_LIFETIME_SECONDS) * 1000).toISOString();

	write("platform-secret.yaml", secretManifest(platformName, namespace, {
		// Hex keeps the password safe inside the postgres:// URLs the chart builds.
		"postgres-password": hex(32),
		"jwt-secret": jwtSecret,
		"anon-key": anonKey,
		"service-role-key": serviceRoleKey,
		"metrics-token": hex(32),
	}, "platform-credentials"));
	write("functions-secret.yaml", secretManifest(functionsName, namespace, {
		AIDR_ENTITLEMENT_SIGNING_KEY_ID: keyId,
		AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: signingPkcs8,
		AIDR_REVOCATION_SIGNING_KEY_ID: keyId,
		AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: signingPkcs8,
		AIDR_DELEGATION_SIGNING_KEY_ID: `aidr-delegation-${hex(6)}`,
		AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64: delegation.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
		AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64: delegation.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
		AIDR_PACK_MASTER_KEY_B64: randomBytes(32).toString("base64"),
		AIDR_PACK_DOWNLOAD_GRANT_SECRET: randomBytes(32).toString("base64url"),
		AIDR_APPROVAL_SIGNING_WRAP_KEY_B64: randomBytes(32).toString("base64"),
		AIDR_DEVICE_START_INGRESS_SECRET: hex(32),
	}, "functions-credentials"));
	write(".env", `ANON_KEY=${anonKey}\nSERVICE_ROLE_KEY=${serviceRoleKey}\n`);
	write("deployment.json", `${JSON.stringify({
		schema_version: 1,
		mode: "self-hosted",
		platform: "kubernetes",
		development: false,
		namespace,
		dashboard_url: dashboardUrl,
		supabase_url: apiUrl,
		prepared_at: new Date(now * 1000).toISOString(),
		secrets: { platform: platformName, functions: functionsName },
		note: "Kubernetes credential record for scripts/deployment-bootstrap.mjs. Not a deployment acceptance record.",
	}, null, 2)}\n`);
	write("agent-config.json", `${JSON.stringify({
		mode: "managed",
		control_plane: { enabled: true, endpoint: `${apiUrl}/functions/v1`, timeout_seconds: 5, remote_policy_required: true, remote_policy_offline_grace_seconds: 3600 },
		integrity: { enabled: true, verify_on_start: true, public_keys_pem: [artifactKeyPem] },
		licensing: { require_signed_entitlements: true, public_keys_pem: [signing.publicKey.export({ type: "spki", format: "pem" })] },
	}, null, 2)}\n`);
	write("readiness.env", `AIDR_SIGNING_KEY_EXPIRES_AT=${keysExpireAt}\nAIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT=${keysExpireAt}\n`);
	console.log([
		`Generated credentials in ${output} (0600 files; no secret was printed).`,
		`Apply them before installing the chart:`,
		`  kubectl create namespace ${namespace} --dry-run=client -o yaml | kubectl apply -f -`,
		`  kubectl apply -f ${join(output, "platform-secret.yaml")} -f ${join(output, "functions-secret.yaml")}`,
		`Then set secrets.existingSecret=${platformName} and secrets.functionsExistingSecret=${functionsName}.`,
	].join("\n"));
	return output;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		main();
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exit(1);
	}
}
