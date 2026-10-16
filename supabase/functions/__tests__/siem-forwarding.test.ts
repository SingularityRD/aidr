// Central SIEM forwarding (E3/E4): configuration policy, encryption, the
// forwarded-event allow-list, CEF/LEEF/JSON syslog formats and every
// transport over REAL sockets (TLS with a throwaway private CA, plain TCP,
// UDP, HTTPS for Splunk HEC, Elastic, Sentinel and webhooks), plus the
// forwarder loop's claim/complete contract.
import { createSocket } from "node:dgram";
import { createServer as createHttpsServer, type IncomingMessage, type ServerResponse } from "node:https";
import { type AddressInfo, createServer as createTcpServer, type Server } from "node:net";
import { createServer as createTlsServer } from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackTls } from "../../../packages/core/src/__tests__/self-signed-tls.ts";
import type { Incident } from "../../../packages/core/src/incidents/types.ts";
import { exportToCEF, exportToLEEF } from "../../../packages/core/src/siem-export.ts";
import { verifySignature } from "../_shared/notification-delivery.ts";
import { parseKeyring } from "../_shared/notification-targets.ts";
import {
	classifySiemAddress,
	decryptSiemConfig,
	encryptSiemConfig,
	formatAllowed,
	parseSiemConfig,
	resolveCollector,
	type SiemDestinationConfig,
	siemTargetHint,
} from "../_shared/siem-config.ts";
import {
	buildForwardedEvent,
	type ClaimedSiemDelivery,
	deliverSiemBatch,
	escapeCefValue,
	type ForwardDeps,
	formatCef,
	formatLeef,
	formatSyslogMessage,
	runSiemForwarding,
	SiemForwardError,
} from "../_shared/siem-forwarding.ts";
import { nodeSocketTransport } from "./node-socket-transport.ts";

const TENANT = "22222222-2222-4222-8222-222222222222";
const DESTINATION = "55555555-5555-4555-8555-555555555555";
const COLLECTOR = "collector.corp.example";
const DCE = "aidr-dce.westeurope-1.ingest.monitor.azure.com";
const identity = selfSignedLoopbackTls({ dnsNames: [COLLECTOR, "login.microsoftonline.com", DCE] });
const KEYS = `k1:${Buffer.alloc(32, 7).toString("base64")}`;

const servers: Array<{ close: (callback: () => void) => unknown }> = [];
afterEach(async () => {
	for (const server of servers.splice(0)) await new Promise<void>((done) => server.close(() => done()));
});

function row(overrides: Partial<ClaimedSiemDelivery> & { payload?: Record<string, unknown> } = {}): ClaimedSiemDelivery {
	return {
		deliveryId: "901",
		leaseToken: "77777777-7777-4777-8777-777777777777",
		kind: "decision",
		attempts: 1,
		maxAttempts: 12,
		createdAt: "2026-10-14T08:00:00.000Z",
		...overrides,
		payload: {
			event_row_id: "4242",
			kind: "decision",
			type: "runtime_verdict",
			occurred_at: "2026-10-14T07:59:58.000Z",
			event_id: "evt-1",
			agent_id: "6A4C0000-0000-4000-8000-000000000001",
			agent_iid: "laptop-17",
			connector: "claude-code",
			decision: "deny",
			severity: "critical",
			threat_id: "T01",
			tool_name: "Bash",
			session_id: "sess-9",
			tool_input_digest: `sha256:${"a".repeat(64)}`,
			...overrides.payload,
		},
	};
}

/** A collector name that resolves to an RFC 1918 address; the transport maps it onto the local server. */
function deps(port: number, extra: Partial<ForwardDeps> & { udp?: boolean } = {}) {
	const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port }), { udp: extra.udp });
	const resolved: string[] = [];
	const value: ForwardDeps = {
		transport,
		resolveDns: async (host) => {
			resolved.push(host);
			if (host === COLLECTOR) return ["10.20.30.40"];
			return ["20.190.160.10"];
		},
		now: () => Date.parse("2026-10-14T08:00:00.000Z"),
		allowPrivateNetworks: true,
		timeoutMs: 5_000,
		...extra,
	};
	return { deps: value, transport, resolved };
}

async function listen(server: Server | ReturnType<typeof createHttpsServer>): Promise<number> {
	servers.push(server);
	return await new Promise((resolve) =>
		server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)),
	);
}

function octetFrames(data: Buffer): string[] {
	const frames: string[] = [];
	let offset = 0;
	while (offset < data.length) {
		const space = data.indexOf(0x20, offset);
		const length = Number(data.subarray(offset, space).toString("ascii"));
		frames.push(data.subarray(space + 1, space + 1 + length).toString("utf8"));
		offset = space + 1 + length;
	}
	return frames;
}

describe("collector network policy", () => {
	it("classifies addresses and never allows loopback, link-local or metadata endpoints", () => {
		expect(classifySiemAddress("93.184.216.34")).toBe("public");
		for (const address of ["10.0.0.5", "172.16.1.1", "192.168.1.10", "100.64.0.1", "fd12::1", "::ffff:10.0.0.5"]) {
			expect(classifySiemAddress(address)).toBe("private");
		}
		for (const address of ["127.0.0.1", "169.254.169.254", "0.0.0.0", "fe80::1", "fd00:ec2::254", "::1", "::ffff:127.0.0.1", "224.0.0.1", "not-an-ip"]) {
			expect(classifySiemAddress(address)).toBe("blocked");
		}
	});

	it("requires every DNS answer to pass, and private collectors only with both opt-ins", async () => {
		const resolver = async (host: string) => (host === "mixed.example" ? ["93.184.216.34", "10.0.0.5"] : ["10.0.0.5"]);
		expect(await resolveCollector("mixed.example", resolver, false)).toEqual({ ok: false, error: "destination_policy_rejected" });
		expect(await resolveCollector("siem.corp.example", resolver, false)).toEqual({ ok: false, error: "destination_policy_rejected" });
		expect(await resolveCollector("siem.corp.example", resolver, true)).toEqual({ ok: true, addresses: ["10.0.0.5"] });
		expect(await resolveCollector("169.254.169.254", resolver, true)).toEqual({ ok: false, error: "destination_policy_rejected" });
		expect(await resolveCollector("gone.example", async () => [], true)).toEqual({ ok: false, error: "dns_unresolved" });
	});
});

describe("destination configuration", () => {
	it("validates every provider and refuses unsafe shapes", () => {
		expect(parseSiemConfig("syslog", { transport: "tls", host: "SIEM.Corp.Example.", port: 6514 })).toMatchObject({
			ok: true,
			config: { host: "siem.corp.example" },
		});
		expect(parseSiemConfig("syslog", { transport: "udp", host: "siem.corp.example", port: 514 })).toEqual({
			ok: false,
			error: "plaintext_not_confirmed",
		});
		expect(parseSiemConfig("syslog", { transport: "tcp", host: "siem.corp.example", port: 514, allow_plaintext: true, ca_pem: identity.cert }))
			.toEqual({ ok: false, error: "invalid_ca" });
		expect(parseSiemConfig("syslog", { transport: "tls", host: "bad host", port: 6514 })).toEqual({ ok: false, error: "invalid_host" });
		expect(parseSiemConfig("syslog", { transport: "tls", host: "a.example", port: 6514, extra: 1 })).toEqual({ ok: false, error: "invalid_config" });
		expect(parseSiemConfig("splunk_hec", { url: "http://splunk.example:8088", token: "t".repeat(36) })).toEqual({ ok: false, error: "url_not_https" });
		expect(parseSiemConfig("splunk_hec", { url: "https://u:p@splunk.example:8088", token: "t".repeat(36) })).toEqual({
			ok: false,
			error: "url_credentials_forbidden",
		});
		expect(parseSiemConfig("splunk_hec", { url: "https://splunk.example:8088/services?x=1", token: "t".repeat(36) }).ok).toBe(false);
		expect(parseSiemConfig("elastic", { url: "https://es.example:9200", index: "aidr", api_key: "k".repeat(20), username: "u", password: "p" }))
			.toEqual({ ok: false, error: "invalid_secret" });
		expect(parseSiemConfig("elastic", { url: "https://es.example:9200", index: "AIDR", api_key: "k".repeat(20) })).toEqual({
			ok: false,
			error: "invalid_index",
		});
		expect(parseSiemConfig("sentinel", {
			endpoint: "https://evil.example.com",
			dcr_immutable_id: `dcr-${"a".repeat(32)}`,
			stream_name: "Custom-AIDR",
			azure_tenant_id: TENANT,
			client_id: TENANT,
			client_secret: "s".repeat(20),
		})).toEqual({ ok: false, error: "invalid_sentinel" });
		expect(parseSiemConfig("webhook", { url: "https://hooks.example/aidr", secret: "short" })).toEqual({ ok: false, error: "invalid_secret" });
		expect(formatAllowed("syslog", "leef")).toBe(true);
		expect(formatAllowed("splunk_hec", "cef")).toBe(false);
	});

	it("seals configuration bound to tenant, destination and provider, and hints without secrets", async () => {
		const keyring = await parseKeyring(KEYS);
		if (!keyring) throw new Error("keyring");
		const parsed = parseSiemConfig("splunk_hec", { url: "https://splunk.corp.example:8088", token: "hec-token-secret-0123456789" });
		if (!parsed.ok) throw new Error("config");
		const binding = { tenantId: TENANT, destinationId: DESTINATION, provider: "splunk_hec" as const };
		const sealed = await encryptSiemConfig(keyring, binding, parsed.config);
		expect(sealed.ciphertext).not.toContain("hec-token");
		expect(await decryptSiemConfig(keyring, binding, sealed.ciphertext)).toEqual(parsed.config);
		expect(await decryptSiemConfig(keyring, { ...binding, destinationId: TENANT }, sealed.ciphertext)).toBeNull();
		expect(await decryptSiemConfig(keyring, { ...binding, provider: "elastic" }, sealed.ciphertext)).toBeNull();
		expect(siemTargetHint(parsed.config)).toBe("splunk.corp.example:8088");
	});
});

describe("forwarded event", () => {
	it("re-applies the allow-list and keeps a stable event id", () => {
		const event = buildForwardedEvent(TENANT, row({ payload: { prompt: "rm -rf secret", command: "curl x", threat_id: "bad id\nCEF:0|forged" } }));
		const text = JSON.stringify(event);
		expect(text).not.toContain("rm -rf");
		expect(text).not.toContain("curl x");
		expect(text).not.toContain("forged");
		expect(event).toMatchObject({
			schema_version: "aidr.siem.forwarded_event/v1",
			event_id: "aidr_evt_4242",
			kind: "decision",
			event: { decision: "deny", severity: "critical", agent_id: "6a4c0000-0000-4000-8000-000000000001", tool_name: "Bash" },
		});
		expect(buildForwardedEvent(TENANT, row({ kind: "test", payload: { event_row_id: undefined, type: "siem_test" } })).event_id)
			.toBe("aidr_test_901");
	});

	it("formats CEF and LEEF with the endpoint exporter's conventions", () => {
		const event = buildForwardedEvent(TENANT, row());
		const cef = formatCef(event);
		expect(cef).toMatch(/^CEF:0\|Singularity\|AIDR\|1\.0\|AIDR\/critical\/DECISION\/DENY\|AIDR deny decision - T01\|10\|/);
		expect(cef).toContain("externalId=aidr_evt_4242");
		expect(cef).toContain("act=deny");
		expect(cef).toContain(`rt=${Date.parse("2026-10-14T07:59:58.000Z")}`);
		expect(cef).not.toMatch(/[\r\n]/);
		const leef = formatLeef(event);
		// LEEF 1.0: exactly five pipe-delimited header fields, then tab-separated attributes.
		const [prefix, vendor, product, version, eventId, attributes] = leef.split("|");
		expect([prefix, vendor, product, version, eventId]).toEqual(["LEEF:1.0", "Singularity", "AIDR", "1.0", "AIDR-CRITICAL-DECISION-DENY"]);
		expect(attributes.split("\t")).toEqual(expect.arrayContaining(["cat=decision", "sev=10", "decision=deny", "threat_id=T01"]));

		// Same severity scale and escaping as packages/core/src/siem-export.ts.
		const incident: Incident = {
			incident_id: "inc|=\\\nx",
			opened_at_ms: 1,
			last_seen_ms: 2,
			severity: "critical",
			status: "open",
			events: [],
		};
		const coreCef = exportToCEF([incident]);
		expect(coreCef.split("|")[0]).toBe("CEF:0");
		expect(coreCef).toContain(`incident_id=${escapeCefValue(incident.incident_id)}`);
		const coreLeef = exportToLEEF([incident]);
		expect(coreLeef.split("|").slice(0, 5)).toEqual(["LEEF:1.0", "Singularity", "AIDR", coreLeef.split("|")[3], "AIDR-CRITICAL"]);
		expect(coreLeef).toContain("\tsev=10\t");
	});

	it("forwards admin audit rows as identifiers only, under their own event id", () => {
		const ACTOR = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
		const TARGET = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
		const audit = (payload: Record<string, unknown>) =>
			buildForwardedEvent(TENANT, row({
				kind: "admin_audit",
				// The defaults carry telemetry fields: none of them may survive for this kind.
				payload: { audit_row_id: "4242", type: "admin_audit", action: "tenant_member.role_changed", actor_user_id: ACTOR, target_user_id: TARGET, detail: "promoted by phone", ...payload },
			}));
		const event = audit({});
		expect(event).toEqual({
			schema_version: "aidr.siem.forwarded_event/v1",
			event_id: "aidr_audit_4242",
			observed_at: "2026-10-14T07:59:58.000Z",
			source: { vendor: "Singularity", product: "AIDR", component: "control_plane" },
			tenant_id: TENANT,
			kind: "admin_audit",
			event: {
				type: "admin_audit",
				occurred_at: "2026-10-14T07:59:58.000Z",
				event_row_id: null,
				audit_row_id: "4242",
				actor_user_id: ACTOR.toLowerCase(),
				target_user_id: TARGET,
				action: "tenant_member.role_changed",
			},
		});
		// Same numeric id as an events row, different dedupe key.
		expect(buildForwardedEvent(TENANT, row()).event_id).toBe("aidr_evt_4242");
		expect(audit({ action: "free text; CEF:0|forged", actor_user_id: "not-a-uuid" }).event).not.toHaveProperty("action");
		expect(audit({ actor_user_id: "not-a-uuid" }).event).not.toHaveProperty("actor_user_id");

		const cef = formatCef(event);
		expect(cef).toMatch(/^CEF:0\|Singularity\|AIDR\|1\.0\|AIDR\/warning\/ADMIN_AUDIT\/TENANT_MEMBER\.ROLE_CHANGED\|AIDR admin action - tenant_member\.role_changed\|5\|/);
		expect(cef).toContain("externalId=aidr_audit_4242");
		expect(cef).toContain(`suid=${ACTOR.toLowerCase()}`);
		expect(cef).toContain(`duid=${TARGET}`);
		expect(cef).toContain("audit_row_id=4242");
		expect(cef).not.toContain("act=");
		const [, , , , eventId, attributes] = formatLeef(event).split("|");
		expect(eventId).toBe("AIDR-WARNING-ADMIN_AUDIT-TENANT_MEMBER.ROLE_CHANGED");
		expect(attributes.split("\t")).toEqual(expect.arrayContaining(["cat=admin_audit", "sev=5", "action=tenant_member.role_changed"]));
		const config = { provider: "syslog", transport: "tls", host: COLLECTOR, port: 6514 } as const;
		expect(formatSyslogMessage(event, "json", config)).toMatch(
			/^<132>1 2026-10-14T07:59:58\.000Z aidr-control-plane aidr - ADMIN_AUDIT \[aidr@32473 eventId="aidr_audit_4242" kind="admin_audit" severity="warning" tenant="/,
		);
	});

	it("frames JSON as RFC 5424 and CEF/LEEF behind an RFC 3164 header", () => {
		const event = buildForwardedEvent(TENANT, row());
		const config = { provider: "syslog", transport: "tls", host: COLLECTOR, port: 6514 } as const;
		const json = formatSyslogMessage(event, "json", config);
		expect(json).toMatch(/^<130>1 2026-10-14T07:59:58\.000Z aidr-control-plane aidr - DECISION \[aidr@32473 eventId="aidr_evt_4242" kind="decision" severity="critical" decision="deny" tenant="22222222-2222-4222-8222-222222222222"\] ﻿\{/);
		expect(formatSyslogMessage(event, "leef", { ...config, facility: 13, hostname: "aidr-cp" })).toMatch(
			/^<106>Oct 14 07:59:58 aidr-cp aidr: LEEF:1\.0\|/,
		);
	});
});

describe("syslog delivery over real sockets", () => {
	it("forwards CEF over TLS to a private-CA collector, dialling the vetted address", async () => {
		const received: Buffer[] = [];
		const server = createTlsServer({ key: identity.key, cert: identity.cert }, (socket) => {
			const chunks: Buffer[] = [];
			socket.on("data", (chunk) => chunks.push(chunk));
			socket.on("end", () => {
				received.push(Buffer.concat(chunks));
				socket.end();
			});
			socket.on("error", () => undefined);
		});
		const port = await listen(server as unknown as Server);
		const { deps: forward, transport } = deps(port);
		const config: SiemDestinationConfig = {
			provider: "syslog",
			transport: "tls",
			host: COLLECTOR,
			port: 6514,
			ca_pem: identity.cert,
			allow_private_network: true,
		};
		const events = [buildForwardedEvent(TENANT, row()), buildForwardedEvent(TENANT, row({ deliveryId: "902", payload: { event_row_id: "4243" } }))];
		const outcomes = await deliverSiemBatch(config, "cef", events, forward);
		expect(outcomes.map((outcome) => outcome.outcome)).toEqual(["delivered", "delivered"]);
		expect(transport.log.dialled).toEqual([{ hostname: "10.20.30.40", port: 6514 }]);
		expect(transport.log.tls).toEqual([{ serverName: COLLECTOR, caCerts: 1 }]);
		const frames = octetFrames(received[0]);
		expect(frames).toHaveLength(2);
		expect(frames[0]).toContain("CEF:0|Singularity|AIDR|");
		expect(frames[1]).toContain("externalId=aidr_evt_4243");
	});

	it("refuses a collector certificate the configured CA did not issue (retry, nothing sent)", async () => {
		const received: Buffer[] = [];
		const server = createTlsServer({ key: identity.key, cert: identity.cert }, (socket) => {
			socket.on("data", (chunk) => received.push(chunk));
			socket.on("error", () => undefined);
		});
		const port = await listen(server as unknown as Server);
		const other = selfSignedLoopbackTls({ dnsNames: [COLLECTOR] });
		const config: SiemDestinationConfig = { provider: "syslog", transport: "tls", host: COLLECTOR, port: 6514, ca_pem: other.cert, allow_private_network: true };
		const [outcome] = await deliverSiemBatch(config, "json", [buildForwardedEvent(TENANT, row())], deps(port).deps);
		expect(outcome).toMatchObject({ outcome: "retry", error: "tls_verification_failed" });
		expect(received).toHaveLength(0);
	});

	it("never reaches a private collector unless the deployment allows it", async () => {
		const config: SiemDestinationConfig = { provider: "syslog", transport: "tls", host: COLLECTOR, port: 6514, allow_private_network: true };
		const { deps: forward, transport } = deps(1, { allowPrivateNetworks: false });
		const [outcome] = await deliverSiemBatch(config, "json", [buildForwardedEvent(TENANT, row())], forward);
		expect(outcome).toMatchObject({ outcome: "failed", error: "destination_policy_rejected" });
		expect(transport.log.dialled).toHaveLength(0);
	});

	it("sends LEEF over plaintext TCP only after the explicit opt-in", async () => {
		const received: Buffer[] = [];
		const server = createTcpServer((socket) => {
			const chunks: Buffer[] = [];
			socket.on("data", (chunk) => chunks.push(chunk));
			socket.on("end", () => {
				received.push(Buffer.concat(chunks));
				socket.end();
			});
		});
		const port = await listen(server);
		const config: SiemDestinationConfig = { provider: "syslog", transport: "tcp", host: COLLECTOR, port: 514, allow_plaintext: true, allow_private_network: true };
		const [outcome] = await deliverSiemBatch(config, "leef", [buildForwardedEvent(TENANT, row())], deps(port).deps);
		expect(outcome.outcome).toBe("delivered");
		expect(octetFrames(received[0])[0]).toContain("LEEF:1.0|Singularity|AIDR|1.0|AIDR-CRITICAL-DECISION-DENY|");
	});

	it("sends UDP datagrams when the runtime supports UDP and fails permanently when it does not", async () => {
		const datagrams: string[] = [];
		const socket = createSocket("udp4");
		socket.on("message", (message) => datagrams.push(message.toString("utf8")));
		servers.push(socket as unknown as { close: (callback: () => void) => unknown });
		const port = await new Promise<number>((resolve) => socket.bind(0, "127.0.0.1", () => resolve(socket.address().port)));
		const config: SiemDestinationConfig = { provider: "syslog", transport: "udp", host: COLLECTOR, port: 514, allow_plaintext: true, allow_private_network: true };
		const event = buildForwardedEvent(TENANT, row());
		expect((await deliverSiemBatch(config, "json", [event], deps(port, { udp: true }).deps))[0].outcome).toBe("delivered");
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(datagrams[0]).toContain('"event_id":"aidr_evt_4242"');
		expect((await deliverSiemBatch(config, "json", [event], deps(port, { udp: false }).deps))[0]).toMatchObject({
			outcome: "failed",
			error: "udp_unsupported",
		});
	});
});

interface Captured {
	method?: string;
	url?: string;
	headers: IncomingMessage["headers"];
	body: string;
}

async function httpsCollector(respond: (request: Captured, response: ServerResponse) => void): Promise<{ port: number; requests: Captured[] }> {
	const requests: Captured[] = [];
	const server = createHttpsServer({ key: identity.key, cert: identity.cert }, (request, response) => {
		const chunks: Buffer[] = [];
		request.on("data", (chunk) => chunks.push(chunk));
		request.on("end", () => {
			const captured = { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString("utf8") };
			requests.push(captured);
			respond(captured, response);
		});
	});
	return { port: await listen(server), requests };
}

describe("HTTP providers over real TLS", () => {
	it("posts Splunk HEC events with the token and the internal CA", async () => {
		const collector = await httpsCollector((_, response) => {
			response.writeHead(200, { "Content-Type": "application/json" });
			response.end('{"text":"Success","code":0}');
		});
		const config: SiemDestinationConfig = {
			provider: "splunk_hec",
			url: `https://${COLLECTOR}:8088`,
			token: "hec-token-0123456789",
			index: "aidr",
			ca_pem: identity.cert,
			allow_private_network: true,
		};
		const outcomes = await deliverSiemBatch(config, "json", [buildForwardedEvent(TENANT, row()), buildForwardedEvent(TENANT, row({ payload: { event_row_id: "4243" } }))], deps(collector.port).deps);
		expect(outcomes.map((outcome) => outcome.outcome)).toEqual(["delivered", "delivered"]);
		const [request] = collector.requests;
		expect(request.url).toBe("/services/collector/event");
		expect(request.headers.authorization).toBe("Splunk hec-token-0123456789");
		const lines = request.body.split("\n").map((line) => JSON.parse(line));
		expect(lines[0]).toMatchObject({ index: "aidr", sourcetype: "aidr:event", event: { event_id: "aidr_evt_4242" } });
	});

	it("judges every Elastic _bulk item and treats a duplicate _id as delivered", async () => {
		const collector = await httpsCollector((_, response) => {
			response.writeHead(200, { "Content-Type": "application/json", "Transfer-Encoding": "chunked" });
			response.write('{"errors":true,"items":[{"create":{"status":201}},');
			response.end('{"create":{"status":409}},{"create":{"status":400}},{"create":{"status":429}}]}');
		});
		const config: SiemDestinationConfig = { provider: "elastic", url: `https://${COLLECTOR}:9200`, index: "aidr-events", api_key: "elastic-api-key-0123", ca_pem: identity.cert, allow_private_network: true };
		const events = ["1", "2", "3", "4"].map((id) => buildForwardedEvent(TENANT, row({ payload: { event_row_id: id } })));
		const outcomes = await deliverSiemBatch(config, "json", events, deps(collector.port).deps);
		expect(outcomes.map((outcome) => `${outcome.outcome}:${outcome.statusCode}`)).toEqual(["delivered:201", "delivered:409", "failed:400", "retry:429"]);
		const [request] = collector.requests;
		expect(request.url).toBe("/_bulk");
		expect(request.headers.authorization).toBe("ApiKey elastic-api-key-0123");
		expect(JSON.parse(request.body.split("\n")[0])).toEqual({ create: { _index: "aidr-events", _id: "aidr_evt_1" } });
	});

	it("signs webhook bodies, never follows redirects and honours Retry-After", async () => {
		const secret = `whsec_${"k".repeat(40)}`;
		let mode = "ok";
		const collector = await httpsCollector((_, response) => {
			if (mode === "redirect") response.writeHead(302, { Location: "https://169.254.169.254/" });
			else if (mode === "busy") response.writeHead(503, { "Retry-After": "120" });
			else response.writeHead(204);
			response.end();
		});
		const config: SiemDestinationConfig = { provider: "webhook", url: `https://${COLLECTOR}:8443/aidr`, secret, ca_pem: identity.cert, allow_private_network: true };
		const forward = deps(collector.port).deps;
		const event = buildForwardedEvent(TENANT, row());
		expect((await deliverSiemBatch(config, "json", [event], forward))[0].outcome).toBe("delivered");
		const [request] = collector.requests;
		expect(request.headers["idempotency-key"]).toBe("aidr_evt_4242");
		expect(await verifySignature(secret, String(request.headers["x-aidr-signature"]), request.body, forward.now() / 1000)).toBe(true);
		mode = "redirect";
		expect((await deliverSiemBatch(config, "json", [event], forward))[0]).toMatchObject({ outcome: "failed", error: "redirect_refused" });
		expect(collector.requests).toHaveLength(2);
		mode = "busy";
		expect((await deliverSiemBatch(config, "json", [event], forward))[0]).toMatchObject({ outcome: "retry", retryAfterSeconds: 120 });
		mode = "ok";
		const audit = buildForwardedEvent(TENANT, row({ kind: "admin_audit", payload: { audit_row_id: "7", type: "admin_audit", action: "auth.login" } }));
		expect((await deliverSiemBatch(config, "json", [audit], forward))[0].outcome).toBe("delivered");
		const auditRequest = collector.requests.at(-1);
		expect(auditRequest?.headers["x-aidr-event"]).toBe("siem.admin_audit");
		expect(auditRequest?.headers["idempotency-key"]).toBe("aidr_audit_7");
		expect(JSON.parse(String(auditRequest?.body)).event).toMatchObject({ action: "auth.login", audit_row_id: "7" });
	});

	it("authenticates to Microsoft Sentinel with client credentials and ingests records", async () => {
		const collector = await httpsCollector((request, response) => {
			if (request.url?.includes("/oauth2/v2.0/token")) {
				response.writeHead(200, { "Content-Type": "application/json" });
				response.end('{"access_token":"azure-access-token","expires_in":3600}');
			} else {
				response.writeHead(204);
				response.end();
			}
		});
		const config = parseSiemConfig("sentinel", {
			endpoint: `https://${DCE}`,
			dcr_immutable_id: `dcr-${"b".repeat(32)}`,
			stream_name: "Custom-AIDR_CL",
			azure_tenant_id: TENANT,
			client_id: DESTINATION,
			client_secret: "client-secret-value",
		});
		if (!config.ok) throw new Error("config");
		// Sentinel and Entra are public endpoints: the system trust store applies, so the
		// test trusts its throwaway CA through Node's default CA list for this call only.
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: collector.port }));
		const forward: ForwardDeps = {
			...deps(collector.port).deps,
			transport: {
				...transport,
				startTls: (connection, options) => transport.startTls(connection, { ...options, caCerts: [identity.cert] }),
			},
		};
		const outcomes = await deliverSiemBatch(config.config, "json", [buildForwardedEvent(TENANT, row())], forward);
		expect(outcomes[0].outcome).toBe("delivered");
		const [token, ingest] = collector.requests;
		expect(token.url).toBe(`/${TENANT}/oauth2/v2.0/token`);
		expect(new URLSearchParams(token.body).get("scope")).toBe("https://monitor.azure.com//.default");
		expect(ingest.url).toBe(`/dataCollectionRules/dcr-${"b".repeat(32)}/streams/Custom-AIDR_CL?api-version=2023-01-01`);
		expect(ingest.headers.authorization).toBe("Bearer azure-access-token");
		expect(JSON.parse(ingest.body)[0]).toMatchObject({ EventId: "aidr_evt_4242", Kind: "decision", decision: "deny" });
	});
});

describe("forwarder loop", () => {
	async function fixture(options: { decryptable?: boolean; entitled?: "ok" | "denied" | "unavailable"; claimError?: boolean } = {}) {
		const keyring = await parseKeyring(KEYS);
		if (!keyring) throw new Error("keyring");
		const config: SiemDestinationConfig = { provider: "webhook", url: `https://${COLLECTOR}/aidr`, secret: "s".repeat(40), allow_private_network: true };
		const sealed = await encryptSiemConfig(keyring, { tenantId: TENANT, destinationId: DESTINATION, provider: "webhook" }, config);
		const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
		let claims = 0;
		const db = {
			rpc: async (name: string, args: Record<string, unknown>) => {
				calls.push({ name, args });
				if (name === "claim_siem_deliveries") {
					if (options.claimError) return { data: null, error: { code: "XX000" } };
					claims += 1;
					if (claims > 1) return { data: [], error: null };
					return {
						data: [{
							destination_id: DESTINATION,
							tenant_id: TENANT,
							provider: "webhook",
							format: "json",
							config_ciphertext: options.decryptable === false ? `v1.k1.${"A".repeat(60)}` : sealed.ciphertext,
							deliveries: [{
								delivery_id: "901",
								lease_token: "77777777-7777-4777-8777-777777777777",
								kind: "decision",
								payload: row().payload,
								attempts: 2,
								max_attempts: 12,
								created_at: "2026-10-14T08:00:00.000Z",
							}],
						}],
						error: null,
					};
				}
				return { data: { delivered: 1, pending: 0, dead: 0, lease_lost: 0 }, error: null };
			},
		};
		return { db, calls, keyring };
	}

	it("completes every claimed row with its outcome and backoff", async () => {
		const collector = await httpsCollector((_, response) => {
			response.writeHead(503);
			response.end();
		});
		const { db, calls, keyring } = await fixture();
		const forward = deps(collector.port).deps;
		const summary = await runSiemForwarding(db, {
			...forward,
			transport: {
				...forward.transport,
				startTls: (connection, options) => forward.transport.startTls(connection, { ...options, caCerts: [identity.cert] }),
			},
			keyring,
			random: () => 0.5,
			entitled: async () => "ok",
		});
		expect(summary.claimed).toBe(1);
		const complete = calls.find((call) => call.name === "complete_siem_deliveries");
		expect(complete?.args.p_results).toEqual([{
			delivery_id: "901",
			lease_token: "77777777-7777-4777-8777-777777777777",
			outcome: "retry",
			error: "receiver_unavailable",
			status_code: 503,
			retry_in_seconds: 60,
		}]);
	});

	it("dead-letters undecryptable configuration and plan downgrades, retries entitlement outages", async () => {
		for (const [options, expected] of [
			[{ decryptable: false }, { outcome: "failed", error: "decrypt_failed" }],
			[{ entitled: "denied" as const }, { outcome: "failed", error: "plan_feature_required" }],
			[{ entitled: "unavailable" as const }, { outcome: "retry", error: "plan_entitlement_unavailable" }],
		] as const) {
			const { db, calls, keyring } = await fixture(options);
			await runSiemForwarding(db, {
				...deps(1).deps,
				keyring,
				random: () => 0.5,
				entitled: async () => ("entitled" in options ? options.entitled : "ok"),
			});
			const results = calls.find((call) => call.name === "complete_siem_deliveries")?.args.p_results as Array<Record<string, unknown>>;
			expect(results[0]).toMatchObject(expected);
		}
	});

	it("stops the run when the claim RPC fails", async () => {
		const { db, keyring } = await fixture({ claimError: true });
		await expect(runSiemForwarding(db, { ...deps(1).deps, keyring, random: Math.random, entitled: async () => "ok" })).rejects.toBeInstanceOf(
			SiemForwardError,
		);
	});
});
