import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import ts from "typescript";
const root = process.cwd();
const failures = [];

async function sourceFiles(directory) {
	const files = [];
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		if (entry.name === "__tests__" || entry.name === "dist") continue;
		const file = path.join(directory, entry.name);
		if (entry.isDirectory()) files.push(...await sourceFiles(file));
		else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith(".d.ts")) files.push(file);
	}
	return files;
}

function literalNames(argument, call) {
	if (ts.isStringLiteralLike(argument)) return [argument.text];
	if (ts.isTemplateExpression(argument)
		&& argument.templateSpans.length === 1
		&& argument.templateSpans[0].literal.text === ""
		&& /^[a-z0-9-]+\?$/.test(argument.head.text)) {
		return [argument.head.text.slice(0, -1)];
	}
	if (ts.isConditionalExpression(argument)) {
		const yes = literalNames(argument.whenTrue, call);
		const no = literalNames(argument.whenFalse, call);
		return yes && no ? [...new Set([...yes, ...no])] : null;
	}
	if (!ts.isIdentifier(argument)) return null;
	for (let parent = call.parent; parent; parent = parent.parent) {
		if (!ts.isArrowFunction(parent) && !ts.isFunctionExpression(parent) && !ts.isFunctionDeclaration(parent)) continue;
		const parameter = parent.parameters.find((item) => ts.isIdentifier(item.name) && item.name.text === argument.text);
		if (!parameter?.type) continue;
		const types = ts.isUnionTypeNode(parameter.type) ? parameter.type.types : [parameter.type];
		if (!types.every((type) => ts.isLiteralTypeNode(type) && ts.isStringLiteralLike(type.literal))) return null;
		return types.map((type) => type.literal.text);
	}
	return null;
}

const browserFunctionReferences = new Map();
for (const file of await sourceFiles(path.join(root, "packages", "dashboard", "src"))) {
	const source = await readFile(file, "utf8");
	const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
	function visit(node) {
		if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
			&& node.expression.name.text === "invoke"
			&& ts.isPropertyAccessExpression(node.expression.expression)
			&& node.expression.expression.name.text === "functions"
			&& node.expression.expression.expression.getText(tree) === "supabase") {
			const location = `${path.relative(root, file)}:${tree.getLineAndCharacterOfPosition(node.getStart(tree)).line + 1}`;
			const names = node.arguments[0] && literalNames(node.arguments[0], node);
			if (!names?.length) failures.push(`${location}: dynamic Edge function name cannot be checked`);
			else for (const name of names) {
				if (!browserFunctionReferences.has(name)) browserFunctionReferences.set(name, []);
				browserFunctionReferences.get(name).push(location);
			}
		}
		ts.forEachChild(node, visit);
	}
	visit(tree);
}
const browserFunctions = [...browserFunctionReferences.keys()].sort();
const functionConfig = await readFile(path.join(root, "supabase", "config.toml"), "utf8");
for (const name of browserFunctions) {
	if (!new RegExp(`^\\[functions\\.${name}\\]$`, "m").test(functionConfig)) {
		failures.push(`${name}: missing supabase/config.toml deployment entry (${browserFunctionReferences.get(name).join(", ")})`);
	}
}

// --- AIDR-019: every browser-invoked function has a named contract test ----
//
// The browser call sites above are discovered from the AST, so this section
// cannot be satisfied by editing a list: adding an `invoke()` call without a
// manifest entry fails the gate. A manifest entry with an empty test list is a
// recorded, reported gap rather than a silent pass.
const manifestPath = path.join(root, "docs", "production-readiness", "edge-function-contract-manifest.json");
let contractManifest = null;
try {
	contractManifest = JSON.parse(await readFile(manifestPath, "utf8"));
} catch (error) {
	failures.push(
		`edge-function contract manifest is missing or unreadable (${error instanceof Error ? error.message : String(error)})`,
	);
}
const uncovered = [];
if (contractManifest) {
	const entries = contractManifest.functions ?? {};
	for (const name of browserFunctions) {
		const entry = entries[name];
		if (!entry) {
			failures.push(`${name}: is invoked from browser code but has no contract manifest entry`);
			continue;
		}
		const tests = Array.isArray(entry.tests) ? entry.tests : [];
		if (tests.length === 0) {
			uncovered.push(name);
			continue;
		}
		for (const test of tests) {
			try {
				await readFile(path.join(root, test), "utf8");
			} catch {
				failures.push(`${name}: declared contract test does not exist (${test})`);
			}
		}
	}
	for (const name of Object.keys(entries)) {
		if (!browserFunctions.includes(name)) {
			failures.push(`${name}: contract manifest entry has no browser call site (stale entry)`);
		}
	}
}
// Discovery accepts an operator JWT or a collector-bound machine key. The
// gateway cannot require a Supabase JWT for the latter, so the handler must
// retain both authentication branches and reject an unverified credential.
const discoveryStart = functionConfig.indexOf("[functions.discovery]");
const discoveryConfig = discoveryStart < 0 ? "" : functionConfig.slice(discoveryStart).split(/\r?\n\[/)[0];
if (!/^verify_jwt\s*=\s*false\s*$/m.test(discoveryConfig)) {
	failures.push("discovery: gateway JWT verification must be disabled for machine credentials");
}
const discoverySource = await readFile(path.join(root, "supabase", "functions", "discovery", "index.ts"), "utf8");
for (const required of [
	"getBearerToken(req.headers.get(\"Authorization\"))",
	"validCollectorCredential(token)",
	"collectorCredentialHash(token)",
	"read_tenant_discovery_collector_cursor",
	"ingest_tenant_discovery_cycle_machine",
	"db.auth.getUser(token)",
	"checkIdentityBarrier(db, token",
	"invalid_collector_credential",
]) {
	if (!discoverySource.includes(required)) failures.push(`discovery: missing handler authentication guard ${required}`);
}
const failClosedRateLimitFunctions = ["device-start", "api-keys", "enrollment-tokens", "enroll", "waitlist-signup"];

/**
 * AIDR-011: every Edge Function must validate its required configuration through
 * `supabase/functions/_shared/config.ts` instead of reading it as
 * `Deno.env.get("X") ?? ""`, which does not fail fast and produces an opaque
 * downstream failure. The behavioural proof lives in
 * `supabase/functions/__tests__/config.test.ts`; this check keeps the contract
 * enforced by the repository gate.
 */
const REQUIRED_PLATFORM_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];

for (const name of browserFunctions) {
	const file = path.join(root, "supabase", "functions", name, "index.ts");
	let source;
	try {
		source = await readFile(file, "utf8");
	} catch (error) {
		failures.push(`${name}: dashboard calls missing Edge function (${browserFunctionReferences.get(name).join(", ")}; ${error instanceof Error ? error.message : String(error)})`);
		continue;
	}
	if (!source.includes('from "../_shared/cors.ts"')) {
		failures.push(`${name}: missing shared CORS import`);
	}
	if (!source.includes("handleCors(req)")) {
		failures.push(`${name}: missing preflight/origin guard`);
	}
	if (!source.includes("corsJson(req")) {
		failures.push(`${name}: responses do not use request-scoped CORS headers`);
	}
}

for (const name of failClosedRateLimitFunctions) {
	const file = path.join(root, "supabase", "functions", name, "index.ts");
	const source = await readFile(file, "utf8");
	if (/fail\s+open/i.test(source)) failures.push(`${name}: rate-limit path still contains a fail-open marker`);
	const explicitEnrollGuard = name === "enroll"
		&& source.includes("if (rateUpdateError) return json(503")
		&& source.includes("if (rateReadError) return json(503")
		&& source.includes("!Number.isSafeInteger(count)");
	if (!explicitEnrollGuard && !source.includes("if (error) return false") && !source.includes("if (updErr) return false")) {
		failures.push(`${name}: rate-limit storage failure is not fail-closed`);
	}
}

const cors = await readFile(path.join(root, "supabase", "functions", "_shared", "cors.ts"), "utf8");
const origin = await readFile(path.join(root, "supabase", "functions", "_shared", "origin.ts"), "utf8");
for (const required of ["AIDR_ALLOWED_ORIGINS", "origin_not_allowed", "OPTIONS", "buildCorsHeaders"]) {
	if (!cors.includes(required)) failures.push(`shared CORS helper: missing ${required}`);
}
if (!origin.includes("Access-Control-Allow-Methods")) {
	failures.push("shared origin helper: missing Access-Control-Allow-Methods");
}

// --- AIDR-011: fail-fast configuration validation -------------------------

const functionsDir = path.join(root, "supabase", "functions");
const edgeLock = JSON.parse(await readFile(path.join(functionsDir, "deno.lock"), "utf8"));
const edgeSdkSpecifiers = Object.keys(edgeLock.specifiers ?? {}).filter((name) => name.startsWith("npm:@supabase/supabase-js@"));
if (edgeSdkSpecifiers.length !== 1 || !/^npm:@supabase\/supabase-js@\d+\.\d+\.\d+$/.test(edgeSdkSpecifiers[0])) {
	failures.push("Edge Supabase client must have one exact version in deno.lock");
} else {
	for (const file of await sourceFiles(functionsDir)) {
		const source = await readFile(file, "utf8");
		for (const match of source.matchAll(/npm:@supabase\/supabase-js@[^\s"'`]+/g)) {
			if (match[0] !== edgeSdkSpecifiers[0]) failures.push(`${path.relative(root, file)}: Edge Supabase client import differs from deno.lock`);
		}
	}
}
const functionNames = (await readdir(functionsDir, { withFileTypes: true }))
	.filter((entry) => entry.isDirectory() && !entry.name.startsWith("_"))
	.map((entry) => entry.name)
	.sort();

let guardedFunctions = 0;
for (const name of functionNames) {
	const file = path.join(functionsDir, name, "index.ts");
	let source;
	try {
		source = await readFile(file, "utf8");
	} catch (error) {
		failures.push(`${name}: cannot read function (${error instanceof Error ? error.message : String(error)})`);
		continue;
	}
	if (!source.includes('from "../_shared/config.ts"')) {
		failures.push(`${name}: required configuration is not validated through the shared config helper`);
		continue;
	}
	guardedFunctions += 1;
	if (!source.includes("loadConfig(runtimeEnv,")) {
		failures.push(`${name}: missing loadConfig(runtimeEnv, ...) validation`);
	}
	if (!source.includes("configFailure(")) {
		failures.push(`${name}: configuration failure is not answered through the shared helper`);
	}
	if (!/"SUPABASE_URL"/.test(source) || !/"SUPABASE_SERVICE_ROLE_KEY"/.test(source)) {
		failures.push(`${name}: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must both be validated`);
	}
	if (!/const config = loadConfig\(runtimeEnv,/.test(source)) {
		failures.push(`${name}: configuration guard must run at request time, before any client or DB work`);
	}
	for (const variable of REQUIRED_PLATFORM_ENV) {
		const fallback = new RegExp(`Deno\\.env\\.get\\(\\s*"${variable}"\\s*\\)\\s*\\?\\?\\s*""`);
		if (fallback.test(source)) {
			failures.push(`${name}: ${variable} still uses the empty-string fallback`);
		}
		if (source.includes(`Deno.env.get("${variable}")`)) {
			failures.push(`${name}: ${variable} is read outside the shared config helper`);
		}
	}
}

const sharedConfig = await readFile(path.join(functionsDir, "_shared", "config.ts"), "utf8");
for (const required of [
	"server_misconfigured",
	"export function loadConfig",
	"export function configFailure",
	"export const runtimeEnv",
]) {
	if (!sharedConfig.includes(required)) failures.push(`shared config helper: missing ${required}`);
}
if (/\?\?\s*""/.test(sharedConfig)) {
	failures.push("shared config helper: contains an empty-string fallback");
}

if (failures.length) {
	console.error("Supabase Edge browser contract failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	process.exitCode = 1;
} else {
	console.log(
		`Supabase Edge browser contract passed (${browserFunctions.length} functions + shared helper, ${guardedFunctions}/${functionNames.length} functions config-guarded).`,
	);
	if (uncovered.length) {
		console.warn(
			`AIDR-019 recorded gaps: ${uncovered.length} browser-invoked function(s) have no contract test yet: ${uncovered.join(", ")}`,
		);
	}
}
