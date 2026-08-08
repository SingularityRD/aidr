import { readFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const browserFunctions = [
	"pilot-status",
	"pilot-apply",
	"device-start",
	"device-poll",
	"device-verify",
	"api-keys",
	"enrollment-tokens",
	"billing-checkout",
];
const failClosedRateLimitFunctions = ["device-start", "api-keys", "enrollment-tokens", "enroll", "waitlist-signup"];

const failures = [];
for (const name of browserFunctions) {
	const file = path.join(root, "supabase", "functions", name, "index.ts");
	let source;
	try {
		source = await readFile(file, "utf8");
	} catch (error) {
		failures.push(`${name}: cannot read function (${error instanceof Error ? error.message : String(error)})`);
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
	if (!source.includes("if (error) return false") && !source.includes("if (updErr) return false")) {
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

if (failures.length) {
	console.error("Supabase Edge browser contract failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	process.exitCode = 1;
} else {
	console.log(`Supabase Edge browser contract passed (${browserFunctions.length} functions + shared helper).`);
}
