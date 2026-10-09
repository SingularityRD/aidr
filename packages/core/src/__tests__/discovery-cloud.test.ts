import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, request as httpsRequest, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { Readable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseCloudDiscoveryConfig } from "../discovery-cloud-config.js";
import { DiscoveryHttpClient } from "../discovery-cloud-http.js";
import { cloudDiscoveryScopeHash } from "../discovery-cloud-provider.js";
import { createDiscoveryProvider } from "../discovery-provider.js";
import { loadFleetInventory, saveFleetInventory } from "../fleet-inventory.js";
import { selfSignedLoopbackTls } from "./self-signed-tls.js";

const TENANT = "tenant-a";
const DIRECTORY = "123e4567-e89b-42d3-a456-426614174000";
const SUB = "123e4567-e89b-42d3-a456-426614174001";
const CLIENT = "123e4567-e89b-42d3-a456-426614174002";
const DEVICE = "123e4567-e89b-42d3-a456-426614174003";
const now = Date.UTC(2026, 9, 6, 12);
const azure = {
	schemaVersion: 1,
	provider: "azure",
	tenantId: TENANT,
	directoryTenantId: DIRECTORY,
	subscriptionIds: [SUB],
	resourceGroups: ["sensitive-rg"],
	credentials: { clientId: CLIENT, clientSecret: { env: "AIDR_AZURE_SECRET" } },
};
const intune = {
	schemaVersion: 1,
	provider: "intune",
	tenantId: TENANT,
	directoryTenantId: DIRECTORY,
	deviceIds: [DEVICE],
	credentials: azure.credentials,
};
const gcp = {
	schemaVersion: 1,
	provider: "gcp",
	tenantId: TENANT,
	projectNumbers: ["123456789012"],
	assetTypes: ["compute.googleapis.com/Instance"],
	credentials: {
		serviceAccountEmail: "collector@project-fixture.iam.gserviceaccount.com",
		privateKey: { env: "AIDR_GCP_KEY" },
	},
};
const request = {
	tenantId: TENANT,
	collectorId: "collector-a",
	targets: [],
	options: { now: () => now },
};
const token = { access_token: "fixture-access-token", token_type: "Bearer", expires_in: 3600 };
const azureRow = {
	id: `/subscriptions/${SUB}/resourceGroups/sensitive-rg/providers/Microsoft.Compute/virtualMachines/vm1`,
	type: "microsoft.compute/virtualmachines",
	location: "westeurope",
	subscriptionId: SUB,
	resourceGroup: "sensitive-rg",
};
const gcpRow = {
	name: "//compute.googleapis.com/projects/project-fixture/zones/europe-west1-a/instances/vm1",
	assetType: "compute.googleapis.com/Instance",
	project: "projects/123456789012",
	location: "europe-west1-a",
};
const servers: Server[] = [];

afterEach(async () => {
	for (const server of servers.splice(0)) {
		server.closeAllConnections();
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
	vi.unstubAllEnvs();
	vi.restoreAllMocks();
});

/** Minted once per run in memory; the test never reads a key from disk. */
const LOOPBACK_TLS = selfSignedLoopbackTls();

/** Real loopback TLS only; the injected test fetch never changes production host validation. */
async function tlsFixture(
	handler: (
		url: URL,
		body: string,
		headers: Record<string, string | string[] | undefined>,
	) => { status?: number; body?: unknown; headers?: Record<string, string>; stall?: boolean },
) {
	const calls: Array<{ url: URL; body: string }> = [];
	const server = createServer(LOOPBACK_TLS, (req, res) => {
		let body = "";
		req.on("data", (chunk: Buffer) => {
			body += chunk.toString("utf8");
		});
		req.on("end", () => {
			const url = new URL(String(req.headers["x-fixture-url"]));
			calls.push({ url, body });
			const result = handler(url, body, req.headers);
			if (result.stall) return;
			res.writeHead(result.status ?? 200, {
				"content-type": "application/json",
				...result.headers,
			});
			res.end(typeof result.body === "string" ? result.body : JSON.stringify(result.body ?? {}));
		});
	});
	servers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("fixture_address_missing");
	const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
		const url = new URL(String(input));
		const headers = Object.fromEntries(new Headers(init?.headers));
		return await new Promise<Response>((resolve, reject) => {
			const req = httpsRequest(
				{
					hostname: "127.0.0.1",
					port: address.port,
					path: url.pathname + url.search,
					method: init?.method ?? "GET",
					headers: { ...headers, "x-fixture-url": url.toString() },
					// The per-run self-signed certificate is trusted only by this test transport.
					rejectUnauthorized: false,
					signal: init?.signal ?? undefined,
				},
				(incoming) => {
					const responseHeaders = new Headers();
					for (const [key, value] of Object.entries(incoming.headers))
						if (value) responseHeaders.set(key, Array.isArray(value) ? value.join(",") : value);
					resolve(
						new Response(Readable.toWeb(incoming) as ReadableStream<Uint8Array>, {
							status: incoming.statusCode,
							headers: responseHeaders,
						}),
					);
				},
			);
			req.on("error", reject);
			req.end(init?.body ? String(init.body) : undefined);
		});
	}) as typeof fetch;
	return { fetchImpl, calls };
}

describe("real read-only cloud discovery", () => {
	it("consumes the configured Azure adapter over HTTPS, paginates and drops labels/names", async () => {
		const fixture = await tlsFixture((url, body, headers) => {
			if (url.hostname === "login.microsoftonline.com") {
				const form = new URLSearchParams(body);
				expect(url.pathname).toBe(`/${DIRECTORY}/oauth2/v2.0/token`);
				expect(form.get("scope")).toBe("https://management.azure.com/.default");
				expect(form.get("client_secret")).toBe("fixture-client-secret");
				return { body: token };
			}
			expect(headers.authorization).toBe("Bearer fixture-access-token");
			const input = JSON.parse(body);
			expect(input.subscriptions).toEqual([SUB]);
			return {
				body: input.options.$skipToken
					? {
							count: 1,
							totalRecords: 2,
							data: [{ ...azureRow, id: azureRow.id.replace("vm1", "vm2") }],
							resultTruncated: "false",
						}
					: {
							count: 1,
							totalRecords: 2,
							data: [
								{ ...azureRow, tags: { secret: "discard-this-tag" }, name: "discard-this-name" },
							],
							resultTruncated: "true",
							$skipToken: "next-page",
						},
			};
		});
		const result = await createDiscoveryProvider("azure", azure, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-client-secret",
		}).collect(request);
		expect(result).toMatchObject({
			status: "ready",
			freshness: "fresh",
			inventory: { items: [], providerEvidence: { complete: true, coverage: "resource_groups" } },
		});
		expect(result.inventory?.providerEvidence?.resources).toHaveLength(2);
		expect(JSON.stringify(result)).not.toMatch(
			/discard-this|fixture-client-secret|fixture-access-token/,
		);
		expect(fixture.calls).toHaveLength(3);
	});

	it.each([
		[
			"outside subscription",
			{ ...azureRow, subscriptionId: "123e4567-e89b-42d3-a456-426614174099" },
		],
		["outside group", { ...azureRow, resourceGroup: "outside" }],
		[
			"inconsistent resource ID",
			{
				...azureRow,
				id: "/subscriptions/outside/resourceGroups/outside/providers/Microsoft.Compute/virtualMachines/vm1",
			},
		],
	])("rejects Azure %s without claiming healthy coverage", async (_label, row) => {
		const fixture = await tlsFixture((url) => ({
			body:
				url.hostname === "login.microsoftonline.com"
					? token
					: { count: 1, totalRecords: 1, data: [row], resultTruncated: "false" },
		}));
		const result = await createDiscoveryProvider("azure", azure, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-secret",
		}).collect(request);
		expect(result).toMatchObject({
			status: "degraded",
			freshness: "never_seen",
			reason: "discovery_resource_scope_mismatch",
			inventory: { providerEvidence: { complete: false, resources: [], lastSuccessfulAt: null } },
		});
	});

	it.each([
		[
			"missing continuation",
			{ count: 1, totalRecords: 2, data: [azureRow], resultTruncated: "true" },
		],
		[
			"false truncation claim",
			{ count: 1, totalRecords: 2, data: [azureRow], resultTruncated: "false" },
		],
		["invalid shape", { count: 1, totalRecords: 1, data: "wrong", resultTruncated: "false" }],
	])("keeps Azure %s partial", async (_label, page) => {
		const fixture = await tlsFixture((url) => ({
			body: url.hostname === "login.microsoftonline.com" ? token : page,
		}));
		const result = await createDiscoveryProvider("azure", azure, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-secret",
		}).collect(request);
		expect(result.status).toBe("degraded");
		expect(result.inventory?.providerEvidence?.complete).toBe(false);
	});

	it("reads only explicitly allowed Intune device IDs with Graph application credentials", async () => {
		const fixture = await tlsFixture((url, body) => {
			if (url.hostname === "login.microsoftonline.com") {
				expect(new URLSearchParams(body).get("scope")).toBe("https://graph.microsoft.com/.default");
				return { body: token };
			}
			expect(url.pathname).toBe(`/v1.0/deviceManagement/managedDevices/${DEVICE}`);
			expect(url.searchParams.get("$select")).toBe("id,operatingSystem");
			return {
				body: {
					id: DEVICE,
					deviceName: "private-device-name",
					userPrincipalName: "private-user@example.test",
					serialNumber: "private-serial",
				},
			};
		});
		const result = await createDiscoveryProvider("mdm", intune, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-secret",
		}).collect(request);
		expect(result).toMatchObject({ provider: "intune", status: "ready" });
		expect(result.inventory?.providerEvidence?.resources).toEqual([
			{
				id: DEVICE,
				type: "mdm.managed_device",
				scope: `intune:${DIRECTORY}`,
				observedAt: new Date(now).toISOString(),
			},
		]);
		expect(JSON.stringify(result)).not.toMatch(/private-device|private-user|private-serial/);
	});

	it("marks a missing Intune device incomplete rather than silently dropping it", async () => {
		const fixture = await tlsFixture((url) =>
			url.hostname === "login.microsoftonline.com"
				? { body: token }
				: { status: 404, body: { error: "private-error" } },
		);
		const result = await createDiscoveryProvider("intune", intune, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-secret",
		}).collect(request);
		expect(result).toMatchObject({
			status: "degraded",
			inventory: { providerEvidence: { complete: false } },
		});
		expect(JSON.stringify(result)).not.toContain("private-error");
	});

	it("signs the real GCP OAuth assertion and consumes paginated Cloud Asset resources", async () => {
		const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const fixture = await tlsFixture((url, body) => {
			if (url.hostname === "oauth2.googleapis.com") {
				const assertion = new URLSearchParams(body).get("assertion")!;
				const [header, payload, signature] = assertion.split(".");
				expect(
					verify(
						"RSA-SHA256",
						Buffer.from(`${header}.${payload}`),
						keys.publicKey,
						Buffer.from(signature!, "base64url"),
					),
				).toBe(true);
				expect(JSON.parse(Buffer.from(payload!, "base64url").toString())).toMatchObject({
					iss: gcp.credentials.serviceAccountEmail,
					aud: "https://oauth2.googleapis.com/token",
					exp: now / 1000 + 3600,
				});
				return { body: token };
			}
			expect(url.pathname).toBe("/v1/projects/123456789012:searchAllResources");
			expect(url.searchParams.getAll("assetTypes")).toEqual(gcp.assetTypes);
			expect(url.searchParams.get("readMask")).toBe("name,assetType,project,location");
			return {
				body: url.searchParams.has("pageToken")
					? { results: [{ ...gcpRow, name: gcpRow.name.replace("vm1", "vm2") }] }
					: {
							results: [{ ...gcpRow, labels: { secret: "discard-label" } }],
							nextPageToken: "next-page",
						},
			};
		});
		const result = await createDiscoveryProvider("cloud", gcp, {
			fetch: fixture.fetchImpl,
			secret: () => keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		}).collect(request);
		expect(result).toMatchObject({
			provider: "gcp",
			status: "ready",
			inventory: { providerEvidence: { complete: true } },
		});
		expect(result.inventory?.providerEvidence?.resources).toHaveLength(2);
		expect(JSON.stringify(result)).not.toContain("discard-label");
	});

	it.each(["project", "assetType", "replay"])("rejects GCP %s violations", async (kind) => {
		const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const fixture = await tlsFixture((url) => ({
			body:
				url.hostname === "oauth2.googleapis.com"
					? token
					: {
							results: [
								{
									...gcpRow,
									...(kind === "project"
										? { project: "projects/999999999999" }
										: kind === "assetType"
											? { assetType: "storage.googleapis.com/Bucket" }
											: {}),
								},
							],
							...(kind === "replay" ? { nextPageToken: "same-page" } : {}),
						},
		}));
		const result = await createDiscoveryProvider("gcp", gcp, {
			fetch: fixture.fetchImpl,
			secret: () => keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		}).collect(request);
		expect(result.status).toBe("degraded");
		expect(result.inventory?.providerEvidence?.complete).toBe(false);
	});

	it("retains last positive resources on failure without advancing successful freshness", async () => {
		let fail = false;
		const fixture = await tlsFixture((url) => ({
			status: fail ? 403 : 200,
			body: url.hostname === "login.microsoftonline.com" ? token : { id: DEVICE },
		}));
		const provider = createDiscoveryProvider("intune", intune, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-secret",
		});
		const first = await provider.collect(request);
		fail = true;
		const second = await provider.collect({
			...request,
			previous: first.inventory,
			options: { now: () => now + 901_000 },
		});
		expect(second).toMatchObject({
			status: "degraded",
			freshness: "stale",
			inventory: {
				providerEvidence: { complete: false, lastSuccessfulAt: new Date(now).toISOString() },
			},
		});
		expect(second.inventory?.providerEvidence?.resources).toEqual(
			first.inventory?.providerEvidence?.resources,
		);
		const changed = createDiscoveryProvider(
			"intune",
			{ ...intune, deviceIds: [CLIENT] },
			{ fetch: fixture.fetchImpl, secret: () => "fixture-secret" },
		);
		const third = await changed.collect({ ...request, previous: first.inventory });
		expect(third.inventory?.providerEvidence?.resources).toEqual([]);
	});

	it("enforces tenant binding before any credential or network access", async () => {
		const network = vi.fn();
		const secret = vi.fn();
		const result = await createDiscoveryProvider("intune", intune, {
			fetch: network,
			secret,
		}).collect({ ...request, tenantId: "tenant-b" });
		expect(result).toMatchObject({ failClosed: true, reason: "discovery_tenant_scope_mismatch" });
		expect(network).not.toHaveBeenCalled();
		expect(secret).not.toHaveBeenCalled();
	});

	it("persists typed provider evidence and rejects corrupted metadata on reload", async () => {
		const fixture = await tlsFixture((url) => ({
			body: url.hostname === "login.microsoftonline.com" ? token : { id: DEVICE },
		}));
		const result = await createDiscoveryProvider("intune", intune, {
			fetch: fixture.fetchImpl,
			secret: () => "fixture-secret",
		}).collect(request);
		if (!result.inventory) throw new Error("fixture_inventory_missing");
		const directory = await mkdtemp(join(tmpdir(), "aidr-cloud-evidence-"));
		try {
			const path = join(directory, "inventory.json");
			await saveFleetInventory(path, result.inventory);
			expect(await loadFleetInventory(path)).toEqual(result.inventory);
			await writeFile(
				path,
				JSON.stringify({
					...result.inventory,
					providerEvidence: { ...result.inventory.providerEvidence, scopeHash: "invalid" },
				}),
			);
			await expect(loadFleetInventory(path)).rejects.toThrow(
				"fleet_inventory_provider_evidence_invalid",
			);
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});

	it("refreshes referenced credentials and OAuth on every collection cycle", async () => {
		let current = "first-secret";
		const seen: string[] = [];
		const fixture = await tlsFixture((url, body) => {
			if (url.hostname === "login.microsoftonline.com")
				seen.push(new URLSearchParams(body).get("client_secret")!);
			return { body: url.hostname === "login.microsoftonline.com" ? token : { id: DEVICE } };
		});
		vi.stubEnv("AIDR_AZURE_SECRET", current);
		const provider = createDiscoveryProvider("intune", intune, { fetch: fixture.fetchImpl });
		await provider.collect(request);
		current = "rotated-secret";
		vi.stubEnv("AIDR_AZURE_SECRET", current);
		await provider.collect(request);
		expect(seen).toEqual(["first-secret", "rotated-secret"]);
	});

	it.each([
		{ ...intune, endpoint: "https://169.254.169.254/latest/meta-data" },
		{ ...intune, deviceIds: [] },
		{ ...intune, credentials: { clientId: CLIENT, clientSecret: "plaintext-secret" } },
		{
			...intune,
			credentials: {
				clientId: CLIENT,
				clientSecret: { vault: { store: "file-acl", id: "fixture" } },
			},
		},
	])("rejects untrusted/incomplete provider config %#", (config) => {
		expect(() => parseCloudDiscoveryConfig(config)).toThrow("discovery_provider_config_invalid");
	});

	it("binds grants to all normalized scopes while allowing credential rotation", () => {
		const config = parseCloudDiscoveryConfig(azure);
		expect(cloudDiscoveryScopeHash(config)).toBe(
			cloudDiscoveryScopeHash(
				parseCloudDiscoveryConfig({
					...azure,
					resourceGroups: ["SENSITIVE-RG", "sensitive-rg"],
					credentials: { clientId: CLIENT, clientSecret: { env: "ROTATED_SECRET" } },
				}),
			),
		);
		expect(cloudDiscoveryScopeHash(config)).not.toBe(
			cloudDiscoveryScopeHash(parseCloudDiscoveryConfig({ ...azure, resourceGroups: ["outside"] })),
		);
		expect(() => createDiscoveryProvider("aws", azure)).toThrow(
			"discovery_provider_config_mismatch",
		);
	});
});

describe("bounded provider HTTPS transport", () => {
	it("refuses production credentials over globally disabled TLS verification", async () => {
		vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"]).json(
				"https://graph.microsoft.com/v1.0/devices",
			),
		).rejects.toThrow("discovery_insecure_tls_not_allowed");
	});
	it.each([
		"http://graph.microsoft.com/v1.0/devices",
		"https://169.254.169.254/latest/meta-data",
		"https://graph.microsoft.com:444/v1.0/devices",
		"https://user:secret@graph.microsoft.com/v1.0/devices",
	])("rejects non-allowlisted endpoint %s", async (url) => {
		const network = vi.fn();
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: network }).json(url),
		).rejects.toThrow("discovery_endpoint_not_allowed");
		expect(network).not.toHaveBeenCalled();
	});

	it("bounds rate retries and respects capped Retry-After", async () => {
		let attempts = 0;
		const fixture = await tlsFixture(() =>
			++attempts < 3 ? { status: 429, headers: { "retry-after": "1" } } : { body: { ok: true } },
		);
		const sleep = vi.fn(async () => {});
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: fixture.fetchImpl, sleep }).json(
				"https://graph.microsoft.com/v1.0/devices",
			),
		).resolves.toEqual({ ok: true });
		expect(attempts).toBe(3);
		expect(sleep.mock.calls).toHaveLength(2);
		const tooLong = await tlsFixture(() => ({ status: 429, headers: { "retry-after": "60" } }));
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: tooLong.fetchImpl, sleep }).json(
				"https://graph.microsoft.com/v1.0/devices",
			),
		).rejects.toThrow("discovery_rate_limited");
	});

	it("rejects redirects and oversized responses", async () => {
		const redirect = await tlsFixture(() => ({
			status: 302,
			headers: { location: "https://169.254.169.254/" },
		}));
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: redirect.fetchImpl }).json(
				"https://graph.microsoft.com/v1.0/devices",
			),
		).rejects.toThrow("discovery_provider_http_failed");
		expect(redirect.calls).toHaveLength(1);
		const huge = await tlsFixture(() => ({ body: "a".repeat(2 * 1024 * 1024 + 1) }));
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: huge.fetchImpl }).json(
				"https://graph.microsoft.com/v1.0/devices",
			),
		).rejects.toThrow("discovery_response_limit_exceeded");
	});

	it("aborts an actual stalled HTTPS request at the configured timeout", async () => {
		const fixture = await tlsFixture(() => ({ stall: true }));
		await expect(
			new DiscoveryHttpClient(["graph.microsoft.com"], {
				fetch: fixture.fetchImpl,
				timeoutMs: 100,
			}).json("https://graph.microsoft.com/v1.0/devices"),
		).rejects.toThrow("discovery_request_failed");
	});

	it("limits response bytes across the whole cycle and stops expired cycles before network access", async () => {
		const fixture = await tlsFixture(() => ({ body: { text: "a".repeat(2 * 1024 * 1024 - 100) } }));
		const client = new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: fixture.fetchImpl });
		for (let index = 0; index < 4; index++)
			await client.json("https://graph.microsoft.com/v1.0/devices");
		await expect(client.json("https://graph.microsoft.com/v1.0/devices")).rejects.toThrow(
			"discovery_response_limit_exceeded",
		);
		const clock = vi.spyOn(performance, "now").mockReturnValue(0);
		const network = vi.fn();
		const expired = new DiscoveryHttpClient(["graph.microsoft.com"], { fetch: network });
		clock.mockReturnValue(120_000);
		await expect(expired.json("https://graph.microsoft.com/v1.0/devices")).rejects.toThrow(
			"discovery_cycle_timeout",
		);
		expect(network).not.toHaveBeenCalled();
	});
});
