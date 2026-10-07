import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../../..");

type HeaderPair = [string, string];
interface HeadersModule {
	securityHeaders(options?: {
		connectSources?: readonly string[];
		upgradeInsecureRequests?: boolean;
	}): HeaderPair[];
	contentSecurityPolicy(options: {
		connectSources: readonly string[];
		upgradeInsecureRequests?: boolean;
	}): string;
}
interface GeneratorModule {
	driftedFiles(): string[];
	expectedFiles(): Record<string, string>;
}

// Plain .mjs modules shared with the Node container; imported by URL so the
// dashboard TypeScript project does not need to type-check them.
async function load<T>(relative: string): Promise<T> {
	return (await import(/* @vite-ignore */ pathToFileURL(join(repoRoot, relative)).href)) as T;
}

describe("dashboard security headers have one source of truth", () => {
	it("vercel.json and public/_headers match deploy/dashboard/security-headers.mjs", async () => {
		const generator = await load<GeneratorModule>("scripts/dashboard-security-headers.mjs");
		// On failure run: node scripts/dashboard-security-headers.mjs --write
		expect(generator.driftedFiles()).toEqual([]);
	});

	it("every hosting target sends the same headers", async () => {
		const { securityHeaders } = await load<HeadersModule>("deploy/dashboard/security-headers.mjs");
		const expected = Object.fromEntries(securityHeaders());

		const vercel = JSON.parse(
			readFileSync(join(repoRoot, "packages/dashboard/vercel.json"), "utf8"),
		);
		const vercelAll = vercel.headers.find((rule: { source: string }) => rule.source === "/(.*)");
		expect(
			Object.fromEntries(
				vercelAll.headers.map((header: { key: string; value: string }) => [
					header.key,
					header.value,
				]),
			),
		).toEqual(expected);

		const cloudflare = readFileSync(join(repoRoot, "packages/dashboard/public/_headers"), "utf8");
		const block = (cloudflare.split(/\r?\n\r?\n/)[0] ?? "").split(/\r?\n/).slice(1);
		expect(
			Object.fromEntries(
				block.map((line) => {
					const [name, ...value] = line.trim().split(": ");
					return [name, value.join(": ")];
				}),
			),
		).toEqual(expected);

		const server = readFileSync(join(repoRoot, "deploy/dashboard/server.mjs"), "utf8");
		expect(server).toContain('from "./security-headers.mjs"');
		expect(server).not.toMatch(
			/setHeader\("(Content-Security-Policy|Referrer-Policy|X-Frame-Options)"/,
		);
	});

	it("uses the strictest values the dashboard still works with", async () => {
		const { securityHeaders, contentSecurityPolicy } = await load<HeadersModule>(
			"deploy/dashboard/security-headers.mjs",
		);
		const headers = Object.fromEntries(securityHeaders());
		expect(headers["Strict-Transport-Security"]).toMatch(/^max-age=63072000; includeSubDomains$/);
		expect(headers["Referrer-Policy"]).toBe("no-referrer");
		expect(headers["X-Frame-Options"]).toBe("DENY");
		const csp = headers["Content-Security-Policy"];
		for (const directive of [
			"default-src 'self'",
			"base-uri 'self'",
			"object-src 'none'",
			"frame-ancestors 'none'",
			"form-action 'self'",
			"img-src 'self' data: blob:",
			"script-src 'self' https://challenges.cloudflare.com",
			"frame-src https://challenges.cloudflare.com",
			"upgrade-insecure-requests",
		])
			expect(csp).toContain(directive);
		// Social sign-in is a Supabase redirect; no IdP script/frame and no arbitrary https: images.
		expect(csp).not.toContain("accounts.google.com");
		expect(csp).not.toMatch(/img-src[^;]*https:/);
		expect(csp).not.toMatch(/wss:|unsafe-eval/);
		// Route smoke requires both Sentry hosts on remote deployments.
		expect(csp).toContain("https://*.sentry.io");
		expect(csp).toContain("https://*.ingest.sentry.io");
		expect(
			contentSecurityPolicy({
				connectSources: ["'self'", "http://127.0.0.1:8000"],
				upgradeInsecureRequests: false,
			}),
		).not.toContain("upgrade-insecure-requests");
		expect(() =>
			contentSecurityPolicy({ connectSources: ["https://evil.example; script-src *"] }),
		).toThrow();
	});
});
