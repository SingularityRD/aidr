import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { type AddressInfo, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTlsServer } from "node:tls";

import { afterEach, describe, expect, it } from "vitest";

import type { Incident } from "../incidents/types.js";
import { DurableSiemDelivery, type SiemAdapterConfig } from "../siem-delivery.js";
import {
	exportToCEF,
	exportToLEEF,
	exportToSyslog,
	formatSyslogMessage,
	SyslogMessageTooLargeError,
} from "../siem-export.js";
import { classifySyslogAddress, type SyslogSiemConfig } from "../siem-syslog.js";

const cleanup: Array<() => Promise<void> | void> = [];
afterEach(async () => {
	for (const task of cleanup.splice(0).reverse()) await task();
});

const incident: Incident = {
	incident_id: "inc-syslog-1",
	opened_at_ms: 1_700_000_000_000,
	last_seen_ms: 1_700_000_000_500,
	severity: "critical",
	status: "open",
	agent_iid: "agent-7",
	connector: "claude",
	domain: "blocked.example",
	events: [
		{
			signal_id: "sig-1",
			timestamp_ms: 1_700_000_000_000,
			signal_type: "runtime_verdict",
			severity: "critical",
			summary: "blocked destructive command",
		},
	],
};

async function tempDir(): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), "aidr-syslog-"));
	cleanup.push(() => rm(directory, { recursive: true, force: true }));
	return directory;
}

async function delivery(
	adapter: SyslogSiemConfig,
	extra: Record<string, unknown> = {},
): Promise<DurableSiemDelivery> {
	const directory = await tempDir();
	return DurableSiemDelivery.open({
		stateFile: join(directory, "state.json"),
		adapter: adapter as SiemAdapterConfig,
		requestTimeoutMs: 2_000,
		...extra,
	});
}

/** Parse RFC 6587 octet-counted frames. */
function parseOctetFrames(data: Buffer): string[] {
	const frames: string[] = [];
	let offset = 0;
	while (offset < data.length) {
		const space = data.indexOf(0x20, offset);
		const length = Number(data.subarray(offset, space).toString("ascii"));
		expect(Number.isInteger(length)).toBe(true);
		frames.push(data.subarray(space + 1, space + 1 + length).toString("utf8"));
		offset = space + 1 + length;
	}
	expect(offset).toBe(data.length);
	return frames;
}

function listen(server: Server): Promise<number> {
	return new Promise((resolve) => {
		server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
		cleanup.push(() => new Promise<void>((done) => server.close(() => done())));
	});
}

async function tcpCollector(): Promise<{ port: number; received: Buffer[] }> {
	const received: Buffer[] = [];
	const server = createServer((socket) => {
		const chunks: Buffer[] = [];
		socket.on("data", (chunk) => chunks.push(chunk));
		socket.on("end", () => received.push(Buffer.concat(chunks)));
		socket.on("error", () => undefined);
	});
	return { port: await listen(server), received };
}

async function closedPort(): Promise<number> {
	const server = createServer();
	const port = await listen(server);
	await new Promise<void>((done) => server.close(() => done()));
	return port;
}

function untilTruthy(check: () => boolean): Promise<void> {
	return new Promise((resolve, reject) => {
		const started = Date.now();
		const timer = setInterval(() => {
			if (check()) {
				clearInterval(timer);
				resolve();
			} else if (Date.now() - started > 3_000) {
				clearInterval(timer);
				reject(new Error("condition not reached"));
			}
		}, 10);
	});
}

describe("RFC 5424 formatter", () => {
	it("emits a conformant header, structured data and BOM-prefixed JSON MSG", () => {
		const message = formatSyslogMessage(
			{
				timestampMs: 1_700_000_000_123,
				severity: "critical",
				eventId: "aidr_abc",
				incidentId: "inc-1",
				status: "open",
				payload: { hello: "world" },
			},
			{ facility: 4, hostname: "host-1", appName: "aidr" },
		);
		// PRI = 4*8 + 2 (critical) = 34
		expect(message).toBe(
			'<34>1 2023-11-14T22:13:20.123Z host-1 aidr - INCIDENT [aidr@32473 eventId="aidr_abc" incidentId="inc-1" severity="critical" status="open"] \uFEFF{"hello":"world"}',
		);
	});

	it("maps every AIDR severity to a syslog severity", () => {
		const pri = (severity: "info" | "warning" | "high" | "critical") =>
			formatSyslogMessage({
				timestampMs: 0,
				severity,
				eventId: "e",
				incidentId: "i",
				payload: {},
			}).split(">")[0];
		expect(pri("critical")).toBe("<130"); // local0 (16*8) + 2
		expect(pri("high")).toBe("<131");
		expect(pri("warning")).toBe("<132");
		expect(pri("info")).toBe("<134");
	});

	it("escapes structured-data values and strips control characters so values cannot forge records", () => {
		const message = formatSyslogMessage({
			timestampMs: 0,
			severity: "info",
			eventId: 'e"] [evil@1 x="y',
			incidentId: "line1\nline2\r\u2028",
			payload: { text: "a\nb" },
		});
		expect(message).not.toMatch(/[\r\n\u2028]/);
		expect(message).toContain('eventId="e\\"\\] [evil@1 x=\\"y"');
		expect(message).toContain('incidentId="line1 line2  "');
	});

	it("sanitises header fields to printable ASCII without spaces", () => {
		const message = formatSyslogMessage(
			{ timestampMs: 0, severity: "info", eventId: "e", incidentId: "i", payload: {} },
			{ hostname: "bad host\nname\u00e9", appName: "x".repeat(100) },
		);
		const [, , hostname, app] = message.split(" ");
		expect(hostname).toBe("bad_host_name_");
		expect(app).toHaveLength(48);
	});

	it("rejects invalid facility, structured-data ids and tiny limits", () => {
		const input = {
			timestampMs: 0,
			severity: "info" as const,
			eventId: "e",
			incidentId: "i",
			payload: {},
		};
		expect(() => formatSyslogMessage(input, { facility: 24 })).toThrow(RangeError);
		expect(() => formatSyslogMessage(input, { structuredDataId: "no-enterprise-number" })).toThrow(
			TypeError,
		);
		expect(() => formatSyslogMessage(input, { maxBytes: 100 })).toThrow(RangeError);
	});

	it("truncates events to honour maxBytes and fails closed when even that does not fit", () => {
		const events = Array.from({ length: 200 }, (_, index) => ({ n: index, text: "x".repeat(40) }));
		const message = formatSyslogMessage(
			{
				timestampMs: 0,
				severity: "info",
				eventId: "e",
				incidentId: "i",
				payload: { incident: { events } },
			},
			{ maxBytes: 2_000 },
		);
		expect(Buffer.byteLength(message)).toBeLessThanOrEqual(2_000);
		expect(message).toContain('"events_truncated":true');
		expect(() =>
			formatSyslogMessage(
				{
					timestampMs: 0,
					severity: "info",
					eventId: "e",
					incidentId: "i",
					payload: { blob: "z".repeat(5_000) },
				},
				{ maxBytes: 2_000 },
			),
		).toThrow(SyslogMessageTooLargeError);
	});

	it("exports one message per incident", () => {
		const output = exportToSyslog([
			incident,
			{ ...incident, incident_id: "inc-2", severity: "info" },
		]);
		expect(output.split("\n")).toHaveLength(2);
		expect(output.split("\n")[0]).toContain('incidentId="inc-syslog-1"');
	});
});

describe("syslog destination policy", () => {
	it.each([
		["127.0.0.1", "loopback"],
		["::1", "loopback"],
		["[::1]", "loopback"],
		["10.1.2.3", "private"],
		["172.16.0.1", "private"],
		["192.168.1.1", "private"],
		["100.64.0.1", "private"],
		["fd00::1", "private"],
		["169.254.169.254", "blocked"],
		["fe80::1", "blocked"],
		["0.0.0.0", "blocked"],
		["::", "blocked"],
		["224.0.0.1", "blocked"],
		["255.255.255.255", "blocked"],
		["ff02::1", "blocked"],
		["::ffff:169.254.169.254", "blocked"],
		["::ffff:7f00:1", "loopback"],
		["::ffff:10.0.0.1", "private"],
		["not-an-ip", "blocked"],
		["93.184.216.34", "public"],
		["2606:2800:220:1:248:1893:25c8:1946", "public"],
	])("classifies %s as %s", (address, expected) => {
		expect(classifySyslogAddress(address)).toBe(expected);
	});

	const open = (adapter: SyslogSiemConfig) => delivery(adapter);

	it("rejects metadata, link-local, loopback and private literals by default", async () => {
		for (const endpoint of [
			"tls://169.254.169.254:6514",
			"tls://127.0.0.1:6514",
			"tls://10.0.0.5:6514",
			"tls://[fe80::1]:6514",
			"tls://metadata.google.internal:6514",
			"tls://localhost:6514",
		]) {
			await expect(open({ provider: "syslog", endpoint })).rejects.toThrow(/egress policy/);
		}
	});

	it("permits private ranges only with allowPrivateNetwork and never link-local", async () => {
		await expect(
			open({ provider: "syslog", endpoint: "tls://10.0.0.5:6514", allowPrivateNetwork: true }),
		).resolves.toBeDefined();
		await expect(
			open({
				provider: "syslog",
				endpoint: "tls://169.254.169.254:6514",
				allowPrivateNetwork: true,
				allowInsecureLoopback: true,
			}),
		).rejects.toThrow(/egress policy/);
	});

	it("requires explicit opt-in for plaintext tcp/udp to non-loopback hosts", async () => {
		await expect(open({ provider: "syslog", endpoint: "tcp://34.120.10.5:514" })).rejects.toThrow(
			/unencrypted/,
		);
		await expect(open({ provider: "syslog", endpoint: "udp://93.184.216.34:514" })).rejects.toThrow(
			/unencrypted/,
		);
		await expect(
			open({
				provider: "syslog",
				endpoint: "udp://93.184.216.34:514",
				allowPlaintextTransport: true,
			}),
		).resolves.toBeDefined();
	});

	it("rejects malformed endpoints, credentials, paths and TLS settings on plaintext", async () => {
		for (const endpoint of [
			"tls://user:pw@93.184.216.34:6514",
			"tls://93.184.216.34",
			"tls://93.184.216.34:6514/path",
			"tls://93.184.216.34:6514?x=1",
			"tls://93.184.216.34:99999",
			"https://93.184.216.34:6514",
			"not a url",
		]) {
			await expect(open({ provider: "syslog", endpoint })).rejects.toThrow(TypeError);
		}
		await expect(
			open({
				provider: "syslog",
				endpoint: "udp://93.184.216.34:514",
				allowPlaintextTransport: true,
				tlsPinnedSha256: ["a".repeat(64)],
			}),
		).rejects.toThrow(/only to tls/);
	});

	it("validates TLS pins, CA material and format options eagerly", async () => {
		const base = { provider: "syslog" as const, endpoint: "tls://93.184.216.34:6514" };
		await expect(open({ ...base, tlsPinnedSha256: ["short"] })).rejects.toThrow(/SHA-256/);
		await expect(open({ ...base, tlsCaCertificatePem: "not pem" })).rejects.toThrow(/PEM/);
		await expect(open({ ...base, facility: 99 })).rejects.toThrow(RangeError);
	});

	it("dead-letters a hostname whose DNS answer includes a blocked address (rebinding / mixed answers)", async () => {
		const sender = await delivery(
			{ provider: "syslog", endpoint: "tls://collector.example:6514" },
			{ syslogLookup: async () => ["93.184.216.34", "169.254.169.254"], maxAttempts: 3 },
		);
		const { receipt } = await sender.enqueue(incident);
		const result = await sender.flush();
		expect(result).toMatchObject({ attempted: 1, deadLettered: 1, delivered: 0 });
		expect((await sender.getReceipt(receipt.receiptId))?.lastErrorCode).toBe(
			"destination_policy_rejected",
		);
	});

	it("retries a DNS outage instead of dead-lettering it", async () => {
		const sender = await delivery(
			{ provider: "syslog", endpoint: "tls://collector.example:6514" },
			{
				syslogLookup: async () => {
					throw new Error("ESERVFAIL");
				},
			},
		);
		await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ attempted: 1, retrying: 1, deadLettered: 0 });
	});
});

describe("syslog delivery over loopback", () => {
	it("delivers over TCP with RFC 6587 octet counting and records a receipt", async () => {
		const collector = await tcpCollector();
		const sender = await delivery({
			provider: "syslog",
			endpoint: `tcp://127.0.0.1:${collector.port}`,
			allowInsecureLoopback: true,
			hostname: "aidr-test",
		});
		const { receipt } = await sender.enqueue(incident);
		expect(receipt.endpointOrigin).toBe(`tcp://127.0.0.1:${collector.port}`);
		expect(await sender.flush()).toMatchObject({ attempted: 1, delivered: 1, pending: 0 });

		await untilTruthy(() => collector.received.length === 1);
		const [frame] = parseOctetFrames(collector.received[0] as Buffer);
		expect(frame).toMatch(/^<130>1 \S+ aidr-test aidr - INCIDENT \[aidr@32473 /);
		expect(frame).toContain(`incidentId="inc-syslog-1"`);
		const json = JSON.parse((frame as string).slice((frame as string).indexOf("\uFEFF") + 1));
		expect(json.incident.incident_id).toBe("inc-syslog-1");
		expect(json.event_id).toBe(receipt.eventId);

		const stored = await sender.getReceipt(receipt.receiptId);
		expect(stored).toMatchObject({
			status: "delivered",
			provider: "syslog",
			deliveryCode: "syslog_tcp_written",
		});
		expect(stored?.lastErrorCode).toBeUndefined();
	});

	it.each([
		[
			"cef",
			/^<130>\w{3} [ \d]\d \d{2}:\d{2}:\d{2} aidr-test aidr: CEF:0\|Singularity\|AIDR\|[^|]+\|AIDR\/critical\/DOMAIN\|/,
		],
		[
			"leef",
			/^<130>\w{3} [ \d]\d \d{2}:\d{2}:\d{2} aidr-test aidr: LEEF:1\.0\|Singularity\|AIDR\|[^|]+\|AIDR-CRITICAL\|cat=incident\t/,
		],
	] as const)(
		"delivers %s records from the core exporters for QRadar / ArcSight",
		async (payloadFormat, header) => {
			const collector = await tcpCollector();
			const sender = await delivery({
				provider: "syslog",
				endpoint: `tcp://127.0.0.1:${collector.port}`,
				allowInsecureLoopback: true,
				hostname: "aidr-test",
				payloadFormat,
			});
			await sender.enqueue(incident);
			expect(await sender.flush()).toMatchObject({ attempted: 1, delivered: 1 });
			await untilTruthy(() => collector.received.length === 1);
			const [frame] = parseOctetFrames(collector.received[0] as Buffer);
			expect(frame).toMatch(header);
			// The record is exactly what exportToCEF / exportToLEEF produce for the incident.
			const exported = payloadFormat === "cef" ? exportToCEF([incident]) : exportToLEEF([incident]);
			expect((frame as string).slice((frame as string).indexOf(": ") + 2)).toBe(exported);
		},
	);

	it("keeps the incident in a CEF record that must shed correlated events to fit", async () => {
		const collector = await tcpCollector();
		const busy: Incident = {
			...incident,
			events: Array.from({ length: 40 }, (_, index) => ({
				...(incident.events[0] as Incident["events"][number]),
				signal_id: `sig-${index}`,
				summary: "x".repeat(60),
			})),
		};
		const sender = await delivery({
			provider: "syslog",
			endpoint: `tcp://127.0.0.1:${collector.port}`,
			allowInsecureLoopback: true,
			payloadFormat: "cef",
			maxMessageBytes: 1024,
		});
		await sender.enqueue(busy);
		expect(await sender.flush()).toMatchObject({ delivered: 1 });
		await untilTruthy(() => collector.received.length === 1);
		const [frame] = parseOctetFrames(collector.received[0] as Buffer);
		expect(Buffer.byteLength(frame as string)).toBeLessThanOrEqual(1024);
		expect(frame).toContain("incident_id=inc-syslog-1");
	});

	it("refuses an unknown payload format at startup", async () => {
		await expect(
			delivery({
				provider: "syslog",
				endpoint: "tcp://127.0.0.1:514",
				allowInsecureLoopback: true,
				payloadFormat: "xml" as never,
			}),
		).rejects.toThrow(/payloadFormat/);
	});

	it("frames the exact UTF-8 byte length for multi-byte content", async () => {
		const collector = await tcpCollector();
		const sender = await delivery({
			provider: "syslog",
			endpoint: `tcp://127.0.0.1:${collector.port}`,
			allowInsecureLoopback: true,
		});
		await sender.enqueue({
			...incident,
			incident_id: "inc-unicode",
			events: [
				{
					...(incident.events[0] as Incident["events"][number]),
					summary: "komut engellendi \u2014 \u00fc\u011f\u015f",
				},
			],
		});
		await sender.flush();
		await untilTruthy(() => collector.received.length === 1);
		const raw = collector.received[0] as Buffer;
		const declared = Number(raw.subarray(0, raw.indexOf(0x20)).toString("ascii"));
		expect(raw.length - raw.indexOf(0x20) - 1).toBe(declared);
		expect(parseOctetFrames(raw)[0]).toContain("\u00fc\u011f\u015f");
	});

	it("delivers over UDP and marks the receipt as unacknowledged", async () => {
		const datagrams: Buffer[] = [];
		const udp: UdpSocket = createSocket("udp4");
		udp.on("message", (message) => datagrams.push(message));
		await new Promise<void>((resolve) => udp.bind(0, "127.0.0.1", resolve));
		cleanup.push(() => new Promise<void>((done) => udp.close(() => done())));
		const sender = await delivery({
			provider: "syslog",
			endpoint: `udp://127.0.0.1:${udp.address().port}`,
			allowInsecureLoopback: true,
		});
		const { receipt } = await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ delivered: 1 });
		await untilTruthy(() => datagrams.length === 1);
		expect((datagrams[0] as Buffer).toString("utf8")).toMatch(/^<130>1 /);
		expect((await sender.getReceipt(receipt.receiptId))?.deliveryCode).toBe(
			"syslog_udp_sent_unacknowledged",
		);
	});

	it("dead-letters a UDP message that exceeds the datagram ceiling instead of truncating it", async () => {
		const udp = createSocket("udp4");
		await new Promise<void>((resolve) => udp.bind(0, "127.0.0.1", resolve));
		cleanup.push(() => new Promise<void>((done) => udp.close(() => done())));
		const sender = await delivery({
			provider: "syslog",
			endpoint: `udp://127.0.0.1:${udp.address().port}`,
			allowInsecureLoopback: true,
		});
		const events = Array.from({ length: 80 }, (_, index) => ({
			signal_id: `sig-${index}`,
			timestamp_ms: 1,
			signal_type: "runtime_verdict" as const,
			severity: "info" as const,
			summary: "s".repeat(200),
		}));
		const { receipt } = await sender.enqueue({ ...incident, incident_id: "inc-big", events });
		expect(await sender.flush()).toMatchObject({ deadLettered: 1, delivered: 0 });
		expect((await sender.getReceipt(receipt.receiptId))?.lastErrorCode).toBe(
			"syslog_message_too_large_for_udp",
		);
	});

	it("resolves hostnames through the policy-checked lookup and connects to the pinned address", async () => {
		const collector = await tcpCollector();
		const sender = await delivery(
			{
				provider: "syslog",
				endpoint: `tcp://collector.test:${collector.port}`,
				allowPlaintextTransport: true,
				allowInsecureLoopback: true,
			},
			{ syslogLookup: async (host: string) => (host === "collector.test" ? ["127.0.0.1"] : []) },
		);
		await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ delivered: 1 });
	});

	it("retries with bounded exponential backoff, then dead-letters, when the collector is down", async () => {
		const port = await closedPort();
		let clock = 1_000_000;
		const sender = await delivery(
			{ provider: "syslog", endpoint: `tcp://127.0.0.1:${port}`, allowInsecureLoopback: true },
			{ now: () => clock, random: () => 1, minBackoffMs: 100, maxBackoffMs: 400, maxAttempts: 3 },
		);
		const { receipt } = await sender.enqueue(incident);

		expect(await sender.flush()).toMatchObject({ attempted: 1, retrying: 1, pending: 1 });
		let current = await sender.getReceipt(receipt.receiptId);
		expect(current).toMatchObject({
			status: "retrying",
			attemptCount: 1,
			lastErrorCode: "network_error",
		});
		expect(current?.nextAttemptAtMs).toBe(clock + 100);

		// Not due yet: nothing is attempted.
		expect(await sender.flush()).toMatchObject({ attempted: 0, pending: 1 });

		clock += 100;
		await sender.flush();
		current = await sender.getReceipt(receipt.receiptId);
		expect(current?.attemptCount).toBe(2);
		expect(current?.nextAttemptAtMs).toBe(clock + 200);

		clock += 200;
		expect(await sender.flush()).toMatchObject({ attempted: 1, deadLettered: 1, pending: 0 });
		expect(await sender.getReceipt(receipt.receiptId)).toMatchObject({
			status: "dead_letter",
			attemptCount: 3,
		});
		expect((await sender.health()).status).toBe("unhealthy");
	});

	it("binds queued events to their route so another destination cannot drain them", async () => {
		const collector = await tcpCollector();
		let clock = 5_000_000;
		const directory = await tempDir();
		const stateFile = join(directory, "state.json");
		const down = await closedPort();
		const downSender = await DurableSiemDelivery.open({
			stateFile,
			adapter: {
				provider: "syslog",
				endpoint: `tcp://127.0.0.1:${down}`,
				allowInsecureLoopback: true,
			},
			now: () => clock,
			random: () => 0,
			minBackoffMs: 10,
			requestTimeoutMs: 2_000,
		});
		await downSender.enqueue(incident);
		await downSender.flush();
		expect((await downSender.health()).queueDepth).toBe(1);
		// A different destination must not be able to drain another route's queue.
		await expect(
			DurableSiemDelivery.open({
				stateFile,
				adapter: {
					provider: "syslog",
					endpoint: `tcp://127.0.0.1:${collector.port}`,
					allowInsecureLoopback: true,
				},
			}),
		).rejects.toThrow(/different destination/);
	});
});

function findOpenssl(): string {
	const candidates = [
		"openssl",
		"C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe",
		"C:\\Program Files\\Git\\usr\\bin\\openssl.exe",
	];
	for (const candidate of candidates) {
		try {
			execFileSync(candidate, ["version"], { stdio: "ignore" });
			return candidate;
		} catch {
			// try the next location
		}
	}
	throw new Error("openssl is required to generate TLS test fixtures");
}

interface Pki {
	caPem: string;
	otherCaPem: string;
	serverKey: string;
	serverCert: string;
	otherServerKey: string;
	otherServerCert: string;
	nameServerCert: string;
	nameServerKey: string;
}

let pkiCache: Promise<Pki> | undefined;

async function pki(): Promise<Pki> {
	pkiCache ??= (async () => {
		const openssl = findOpenssl();
		const directory = await tempDir();
		const run = (...args: string[]) =>
			execFileSync(openssl, args, { cwd: directory, stdio: "ignore" });
		const issue = async (name: string, ca: string, san: string) => {
			await writeFile(join(directory, `${name}.ext`), `subjectAltName=${san}\n`);
			run(
				"req",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:prime256v1",
				"-nodes",
				"-keyout",
				`${name}.key`,
				"-out",
				`${name}.csr`,
				"-subj",
				"/CN=collector",
			);
			run(
				"x509",
				"-req",
				"-in",
				`${name}.csr`,
				"-CA",
				`${ca}.pem`,
				"-CAkey",
				`${ca}.key`,
				"-CAcreateserial",
				"-out",
				`${name}.pem`,
				"-days",
				"2",
				"-extfile",
				`${name}.ext`,
			);
		};
		for (const ca of ["ca", "otherca"]) {
			run(
				"req",
				"-x509",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:prime256v1",
				"-nodes",
				"-keyout",
				`${ca}.key`,
				"-out",
				`${ca}.pem`,
				"-subj",
				`/CN=${ca}`,
				"-days",
				"2",
				"-addext",
				"basicConstraints=critical,CA:TRUE",
			);
		}
		await issue("server", "ca", "IP:127.0.0.1,DNS:collector.test");
		await issue("other", "otherca", "IP:127.0.0.1,DNS:collector.test");
		await issue("wrongname", "ca", "DNS:someone-else.test");
		const read = (name: string) => readFile(join(directory, name), "utf8");
		return {
			caPem: await read("ca.pem"),
			otherCaPem: await read("otherca.pem"),
			serverKey: await read("server.key"),
			serverCert: await read("server.pem"),
			otherServerKey: await read("other.key"),
			otherServerCert: await read("other.pem"),
			nameServerKey: await read("wrongname.key"),
			nameServerCert: await read("wrongname.pem"),
		};
	})();
	return pkiCache;
}

async function tlsCollector(
	key: string,
	cert: string,
): Promise<{ port: number; received: Buffer[] }> {
	const received: Buffer[] = [];
	const server = createTlsServer({ key, cert }, (socket) => {
		const chunks: Buffer[] = [];
		socket.on("data", (chunk) => chunks.push(chunk));
		socket.on("end", () => received.push(Buffer.concat(chunks)));
		socket.on("error", () => undefined);
	});
	server.on("tlsClientError", () => undefined);
	return { port: await listen(server), received };
}

const spki = (pem: string): string =>
	createHash("sha256")
		.update(new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" }))
		.digest("base64");

describe("syslog delivery over TLS", () => {
	const tlsBase = (port: number): SyslogSiemConfig => ({
		provider: "syslog",
		endpoint: `tls://127.0.0.1:${port}`,
		allowInsecureLoopback: true,
	});

	it("delivers when the server certificate chains to the pinned CA bundle", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.serverKey, keys.serverCert);
		const sender = await delivery({ ...tlsBase(collector.port), tlsCaCertificatePem: keys.caPem });
		const { receipt } = await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ delivered: 1 });
		await untilTruthy(() => collector.received.length === 1);
		expect(parseOctetFrames(collector.received[0] as Buffer)[0]).toContain(
			'incidentId="inc-syslog-1"',
		);
		expect(await sender.getReceipt(receipt.receiptId)).toMatchObject({
			deliveryCode: "syslog_tls_written",
			endpointOrigin: `tls://127.0.0.1:${collector.port}`,
		});
	});

	it("verifies the certificate against the DNS name, not the connect address", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.serverKey, keys.serverCert);
		const sender = await delivery(
			{
				provider: "syslog",
				endpoint: `tls://collector.test:${collector.port}`,
				allowInsecureLoopback: true,
				tlsCaCertificatePem: keys.caPem,
			},
			{ syslogLookup: async () => ["127.0.0.1"] },
		);
		await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ delivered: 1 });
	});

	it("never accepts a certificate from an untrusted CA", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.otherServerKey, keys.otherServerCert);
		const sender = await delivery({ ...tlsBase(collector.port), tlsCaCertificatePem: keys.caPem });
		const { receipt } = await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ attempted: 1, delivered: 0, retrying: 1 });
		expect((await sender.getReceipt(receipt.receiptId))?.lastErrorCode).toBe(
			"tls_verification_failed",
		);
		expect(collector.received).toHaveLength(0);
	});

	it("rejects a certificate whose name does not match the destination host", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.nameServerKey, keys.nameServerCert);
		const sender = await delivery({ ...tlsBase(collector.port), tlsCaCertificatePem: keys.caPem });
		const { receipt } = await sender.enqueue(incident);
		await sender.flush();
		expect((await sender.getReceipt(receipt.receiptId))?.lastErrorCode).toBe(
			"tls_verification_failed",
		);
	});

	it("rejects a self-signed server when no CA is configured (system roots only)", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.serverKey, keys.serverCert);
		const sender = await delivery(tlsBase(collector.port));
		const { receipt } = await sender.enqueue(incident);
		await sender.flush();
		expect((await sender.getReceipt(receipt.receiptId))?.lastErrorCode).toBe(
			"tls_verification_failed",
		);
	});

	it("accepts a matching public-key pin (hex or base64) and rejects a mismatched pin", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.serverKey, keys.serverCert);
		const caPin = spki(keys.caPem);
		const matching = await delivery({
			...tlsBase(collector.port),
			tlsCaCertificatePem: keys.caPem,
			tlsPinnedSha256: [Buffer.from(caPin, "base64").toString("hex")],
		});
		await matching.enqueue(incident);
		expect(await matching.flush()).toMatchObject({ delivered: 1 });

		const leafPin = await delivery({
			...tlsBase(collector.port),
			tlsCaCertificatePem: keys.caPem,
			tlsPinnedSha256: [spki(keys.serverCert)],
		});
		await leafPin.enqueue({ ...incident, incident_id: "inc-leaf" });
		expect(await leafPin.flush()).toMatchObject({ delivered: 1 });

		const wrong = await delivery({
			...tlsBase(collector.port),
			tlsCaCertificatePem: keys.caPem,
			tlsPinnedSha256: [spki(keys.otherCaPem)],
		});
		const { receipt } = await wrong.enqueue({ ...incident, incident_id: "inc-wrong-pin" });
		const before = collector.received.length;
		expect(await wrong.flush()).toMatchObject({ delivered: 0, retrying: 1 });
		expect((await wrong.getReceipt(receipt.receiptId))?.lastErrorCode).toBe("tls_pin_mismatch");
		// A pin mismatch must be detected before any incident bytes are written.
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(collector.received.length).toBe(before);
	});

	it("ignores an attempt to disable certificate verification through config", async () => {
		const keys = await pki();
		const collector = await tlsCollector(keys.serverKey, keys.serverCert);
		const sender = await delivery({
			...tlsBase(collector.port),
			rejectUnauthorized: false,
		} as unknown as SyslogSiemConfig);
		await sender.enqueue(incident);
		expect(await sender.flush()).toMatchObject({ delivered: 0, retrying: 1 });
		expect(collector.received).toHaveLength(0);
	});
});
