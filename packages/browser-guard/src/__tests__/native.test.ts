import { performance as hostClock } from "node:perf_hooks";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DocumentScanner } from "../../../privacy/src/browser/documents.js";
import { PrivacyEngine } from "../../../privacy/src/engine.js";
import { deriveEdmKey } from "../../../privacy/src/native/edm.js";
import { NativeSession } from "../../../privacy/src/native/session.js";
import type { EngineOptions, NerProvider } from "../../../privacy/src/types.js";
import { VisualPrivacyEngine } from "../../../privacy/src/visual/engine.js";
import type { ImageBackend, ImageScan } from "../../../privacy/src/visual/types.js";
import {
	createNativeBridge,
	NATIVE_CONNECT_TIMEOUT_MS,
	NATIVE_HOST_NAME,
	NATIVE_MAX_FAILURES,
	NATIVE_MAX_QUEUED,
	NATIVE_RETRY_AFTER_MS,
	NATIVE_TIMEOUT_MS,
	type NativeChromeApi,
	type NativePort,
	recoverNativeFindings,
} from "../background/native.js";

type Msg = Record<string, unknown>;
const POLICY_DIGEST = "d".repeat(64);

/** Dictionary NER standing in for the host's learned model (PERSON/ADDRESS in free text). */
const NAMES: ReadonlyArray<[string, "PERSON" | "ADDRESS" | "LOCATION"]> = [
	["Ayşe Yılmaz", "PERSON"],
	["Jane Doe", "PERSON"],
	["Moda Caddesi No 12", "ADDRESS"],
	["Kadıköy", "LOCATION"],
];
function dictionaryNer(fail = false): NerProvider {
	return {
		capabilities: {
			local: true,
			offsetUnit: "utf16",
			languages: ["tr", "en"],
			entities: ["PERSON", "ADDRESS", "LOCATION"],
			revision: "test-dictionary-1",
		},
		async detect(text: string) {
			if (fail) throw new Error("model crashed");
			const entities = [];
			for (const [value, type] of NAMES) {
				for (let at = text.indexOf(value); at >= 0; at = text.indexOf(value, at + 1)) {
					entities.push({ start: at, end: at + value.length, type, score: 0.97 });
				}
			}
			return { complete: true as const, entities };
		},
	};
}

interface HostOptions {
	engine?: EngineOptions;
	nerFails?: boolean;
	scanner?: DocumentScanner;
	/** Rewrites a host response before it reaches the extension (malformed-host tests). */
	tamper?: (response: Msg, request: Msg) => Msg | null;
	/** Ops the host never answers (timeout tests). */
	hang?: readonly string[];
	/** OCR lines the host's (fake) OCR backend reads from any image; absent: host without OCR. */
	ocrLines?: readonly string[];
	/** An older host: it refuses `hello {persistent}` like host.ts (failure frame, then exit). */
	legacy?: boolean;
	/** The host's EDM secret (exact-data keys); absent: no secret configured. */
	edmSecret?: Buffer;
}

/** The host's real VisualPrivacyEngine over a fake OCR backend that reads `lines`. */
function fakeVisual(lines: readonly string[]): VisualPrivacyEngine {
	const backend: ImageBackend = {
		async inspect(data: Uint8Array): Promise<ImageScan> {
			const { createHash } = await import("node:crypto");
			const words = lines.flatMap((line, row) => {
				let x = 10;
				return line.split(" ").map((text) => {
					const word = {
						text,
						confidence: 95,
						line: row,
						x,
						y: 10 + row * 32,
						width: text.length * 7 + 7,
						height: 18,
					};
					x += word.width + 7;
					return word;
				});
			});
			return {
				protocol: 1,
				complete: true,
				inputSha256: createHash("sha256").update(data).digest("hex"),
				pixelSha256: "a".repeat(64),
				width: 640,
				height: 300,
				format: "PNG",
				languages: ["eng", "tur"],
				pages: [{ words }],
				barcodes: [],
			};
		},
		async render() {
			throw new Error("inspection never renders");
		},
	};
	return new VisualPrivacyEngine({
		backend,
		textEngine: new PrivacyEngine({ profile: "balanced", maxInputBytes: 262_144 }),
	});
}

interface FakeChrome extends NativeChromeApi {
	sent: Msg[];
	connects: number;
	disconnects: number;
	granted: boolean;
}

/**
 * A fake WebExtension runtime whose native host is the real packages/privacy
 * NativeSession (same state machine, limits and response shapes as host.ts).
 * Messages are JSON round-tripped like Chrome native messaging.
 */
function fakeChrome(options: HostOptions & { granted?: boolean; installed?: boolean } = {}) {
	const makeSession = () =>
		new NativeSession({
			text:
				options.scanner ??
				new PrivacyEngine({
					profile: "strict",
					mask: "label",
					maxInputBytes: 1_048_576,
					...(options.engine ?? {}),
					ner: dictionaryNer(options.nerFails),
				}),
			...(options.ocrLines ? { visual: fakeVisual(options.ocrLines) } : {}),
			...(options.edmSecret
				? {
						exactDataKey: (id: string) =>
							deriveEdmKey(options.edmSecret as Buffer, id).toString("base64"),
					}
				: {}),
			policyId: "aidr-default-v1",
			policyDigest: POLICY_DIGEST,
		});
	const chrome: FakeChrome = {
		sent: [],
		connects: 0,
		disconnects: 0,
		granted: options.granted ?? true,
		permissions: {
			contains: async (p) => chrome.granted && p.permissions.includes("nativeMessaging"),
		},
		runtime: {
			lastError: undefined,
			connectNative: (name): NativePort => {
				chrome.connects++;
				const onMessage: Array<(m: unknown) => void> = [];
				const onDisconnect: Array<() => void> = [];
				let alive = true;
				const session = makeSession();
				const drop = () => {
					if (!alive) return;
					alive = false;
					session.close();
					setImmediate(() => {
						for (const l of onDisconnect) l();
					});
				};
				if (name !== NATIVE_HOST_NAME || options.installed === false) drop();
				return {
					onMessage: { addListener: (l) => onMessage.push(l) },
					onDisconnect: { addListener: (l) => onDisconnect.push(l) },
					disconnect() {
						chrome.disconnects++;
						alive = false;
						session.close();
					},
					postMessage(message) {
						if (!alive) throw new Error("Attempting to use a disconnected port object");
						const request = JSON.parse(JSON.stringify(message)) as Msg;
						chrome.sent.push(request);
						if (options.hang?.includes(String(request.op))) return;
						const refused =
							options.legacy && request.op === "hello" && "persistent" in request
								? Promise.reject(new Error("NATIVE_PROTOCOL_INVALID"))
								: null;
						(refused ?? session.handle(request)).then(
							(response) => {
								const out = options.tamper ? options.tamper(response, request) : response;
								if (!alive || out === null) return;
								const frame = JSON.parse(JSON.stringify(out));
								setImmediate(() => {
									if (alive) for (const l of onMessage) l(frame);
								});
							},
							() => {
								// host.ts: failure frame without id, then exit.
								const frame = { v: 1, ok: false, code: "NATIVE_HOST_FAILURE" };
								setImmediate(() => {
									if (alive) for (const l of onMessage) l(frame);
									drop();
								});
							},
						);
					},
				};
			},
		},
	};
	return chrome;
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 5));
const slice = (text: string, f: { start: number; end: number }) => text.slice(f.start, f.end);
const nextTurn = () => new Promise((resolve) => setImmediate(resolve));

/**
 * Yields to the event loop until `done()` holds. The fake port delivers each host reply on a later
 * event-loop turn, scheduled only after the request went through async work, so a fixed sleep such
 * as `flush()` can expire first on a loaded machine.
 */
async function until(done: () => boolean): Promise<void> {
	while (!done()) await nextTurn();
}

/**
 * Runs `task` with `setTimeout` frozen and never advanced. With the host's clock already stopped
 * (see `beforeEach`), neither the bridge's deadline nor the host's NER timeout can expire however
 * slow the machine is, while the fake port's deliveries (`setImmediate`) and real async work
 * (SHA-256 digests) still run.
 */
async function withFrozenClock<T>(task: () => Promise<T>): Promise<T> {
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	let settled = false;
	const result = task().finally(() => {
		settled = true;
	});
	await until(() => settled);
	return result;
}

/**
 * The fake host is the real privacy engine, whose scan budget (`maxScanMs`, default 1 s) is read
 * from `node:perf_hooks` `performance.now()`. On a loaded machine it runs out and the host answers
 * `block` / SCAN_BUDGET, which the bridge rightly reports as `null`. That budget is host behaviour,
 * not bridge behaviour under test here, so the host's clock stands still in this file.
 * (`vi.useFakeTimers({ toFake: ["performance"] })` swaps only the global, not this import.)
 */
beforeEach(() => {
	vi.spyOn(hostClock, "now").mockReturnValue(0);
});

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});

describe("createNativeBridge: availability", () => {
	it("is disabled without touching the browser API when not enabled", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(false, { chrome });
		expect(bridge.status()).toBe("disabled");
		expect(await bridge.scanText("Ayşe Yılmaz")).toBeNull();
		expect(chrome.connects).toBe(0);
		expect(chrome.sent).toEqual([]);
	});

	it("reports unavailable and never launches the host without the nativeMessaging permission", async () => {
		const chrome = fakeChrome({ granted: false });
		const bridge = createNativeBridge(true, { chrome });
		expect(bridge.status()).toBe("unavailable");
		await flush();
		expect(bridge.status()).toBe("unavailable");
		expect(await bridge.scanText("Ayşe Yılmaz burada")).toBeNull();
		expect(chrome.connects).toBe(0);
		expect(chrome.sent).toEqual([]);
	});

	it("reports unavailable when the browser exposes no extension API", async () => {
		const bridge = createNativeBridge(true, { chrome: {} });
		bridge.status();
		await flush();
		expect(bridge.status()).toBe("unavailable");
		expect(await bridge.scanText("Ayşe Yılmaz")).toBeNull();
	});

	it("lazily starts the host with a persistent hello and reports connected", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		expect(chrome.sent).toEqual([]);
		expect(bridge.status()).toBe("unavailable");
		await until(() => bridge.status() === "connected");
		expect(chrome.sent).toHaveLength(1);
		expect(chrome.sent[0]).toMatchObject({ v: 1, op: "hello", persistent: true });
		expect(Object.keys(chrome.sent[0] ?? {}).sort()).toEqual(["id", "op", "persistent", "v"]);
		// The probe is the warm-up: it keeps the host running for the scans that follow (BG-11).
		expect(chrome.connects).toBe(1);
		expect(chrome.disconnects).toBe(0);
		expect(
			await withFrozenClock(() => bridge.scanText("Toplantıya Jane Doe katılacak.")),
		).toHaveLength(1);
		expect(chrome.connects).toBe(1);
		expect(chrome.sent.filter((m) => m.op === "hello")).toHaveLength(1);
	});

	it("reports unavailable when the browser has no connectNative", async () => {
		const chrome = fakeChrome();
		const runtime = { ...chrome.runtime, connectNative: undefined };
		const bridge = createNativeBridge(true, { chrome: { ...chrome, runtime } });
		bridge.status();
		await flush();
		expect(bridge.status()).toBe("unavailable");
		expect(await bridge.scanText("Jane Doe")).toBeNull();
	});

	it("stays unavailable when the host is not installed and retries only after the backoff", async () => {
		let clock = 1_000;
		const chrome = fakeChrome({ installed: false });
		const bridge = createNativeBridge(true, { chrome, now: () => clock });
		bridge.status();
		await flush();
		expect(bridge.status()).toBe("unavailable");
		const probesBefore = chrome.sent.length + chrome.connects;
		bridge.status();
		await flush();
		expect(chrome.sent.length + chrome.connects).toBe(probesBefore);
		expect(await bridge.scanText("Ayşe Yılmaz")).toBeNull();
		expect(chrome.connects).toBe(1);
		clock += NATIVE_RETRY_AFTER_MS;
		expect(await bridge.scanText("Ayşe Yılmaz")).toBeNull();
		expect(chrome.connects).toBe(2);
	});
});

describe("createNativeBridge: scanning over the privacy host protocol", () => {
	it("maps host redactions to native-ner findings with exact UTF-16 offsets", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		const text =
			"🚀 Merhaba, ben Ayşe Yılmaz.\nAdresim Moda Caddesi No 12\nSemt: Kadıköy\nMail: ayse@example.com";
		const findings = await withFrozenClock(() => bridge.scanText(text));
		expect(findings).not.toBeNull();
		const got = (findings ?? []).map((f) => [f.type, slice(text, f), f.source]);
		expect(got).toEqual([
			["PERSON", "Ayşe Yılmaz", "native-ner"],
			// The host merges its address-context rule span with the NER span.
			["ADDRESS", "Adresim Moda Caddesi No 12", "native-ner"],
			["LOCATION", "Kadıköy", "native-ner"],
			["EMAIL", "ayse@example.com", "native-ner"],
		]);
		for (const f of findings ?? []) expect(f.score).toBeGreaterThan(0);
		expect(bridge.status()).toBe("connected");
		// The host stays up for the next scan.
		expect(chrome.disconnects).toBe(0);
	});

	it("sends only the scanned text, following hello/begin/write/commit/read", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		const text = "Toplantıya Jane Doe katılacak.";
		await withFrozenClock(() => bridge.scanText(text));
		expect(chrome.sent.map((m) => m.op)).toEqual(["hello", "begin", "write", "commit", "read"]);
		const begin = chrome.sent[1] ?? {};
		expect(begin).toMatchObject({ v: 1, kind: "text", policyDigest: POLICY_DIGEST });
		expect(begin.size).toBe(new TextEncoder().encode(text).length);
		const uploaded = Buffer.from(String(chrome.sent[2]?.data), "base64").toString("utf8");
		expect(uploaded).toBe(text);
		// Nothing but the text itself, its size and hash crosses to the host.
		const allowed: Record<string, string[]> = {
			hello: ["persistent"],
			begin: ["kind", "policyDigest", "sha256", "size"],
			write: ["data", "offset"],
			commit: [],
			read: ["offset"],
		};
		for (const m of chrome.sent) {
			const extra = Object.keys(m).filter((k) => !["v", "id", "op"].includes(k));
			expect(extra.sort()).toEqual(allowed[String(m.op)]);
		}
		expect(new Set(chrome.sent.map((m) => m.id)).size).toBe(chrome.sent.length);
	});

	it("returns [] for clean text without reading the output back", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		expect(await withFrozenClock(() => bridge.scanText("Yarın saat üçte buluşalım."))).toEqual([]);
		expect(chrome.sent.map((m) => m.op)).toEqual(["hello", "begin", "write", "commit"]);
		expect(await withFrozenClock(() => bridge.scanText(""))).toEqual([]);
	});

	it("keeps offsets aligned when the text starts with a BOM the host strips", async () => {
		const bridge = createNativeBridge(true, { chrome: fakeChrome() });
		const text = "﻿Jane Doe aradı";
		const findings = await withFrozenClock(() => bridge.scanText(text));
		expect(findings?.map((f) => slice(text, f))).toEqual(["Jane Doe"]);
	});

	it("chunks large inputs and outputs within the host frame limits", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		const filler = "lorem ipsum dolor sit amet ".repeat(12_000);
		const text = `${filler}Ayşe Yılmaz ${filler}Jane Doe`;
		// The ~650 KB round trip is slow on a loaded machine. Timing is not under test here:
		// freeze the timers too, so the bridge's production 2 s bound cannot decide the result.
		const findings = await withFrozenClock(() => bridge.scanText(text));
		expect(findings?.map((f) => [f.type, slice(text, f)])).toEqual([
			["PERSON", "Ayşe Yılmaz"],
			["PERSON", "Jane Doe"],
		]);
		const ops = chrome.sent.map((m) => m.op);
		expect(ops.filter((o) => o === "write").length).toBeGreaterThan(1);
		expect(ops.filter((o) => o === "read").length).toBeGreaterThan(1);
		for (const m of chrome.sent) expect(JSON.stringify(m).length).toBeLessThan(524_288);
	});

	it("does not contact the host for text over the host limit or with lone surrogates", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		expect(await bridge.scanText("a".repeat(1_048_577))).toBeNull();
		expect(await bridge.scanText("ş".repeat(600_000))).toBeNull();
		expect(await bridge.scanText("Jane \ud800 Doe")).toBeNull();
		expect(chrome.connects).toBe(0);
	});

	it("treats a host policy block as healthy but unmappable (null, no backoff)", async () => {
		const chrome = fakeChrome({ engine: { actions: { PERSON: "block" } } });
		const bridge = createNativeBridge(true, { chrome });
		for (let i = 0; i < NATIVE_MAX_FAILURES + 1; i++) {
			expect(await withFrozenClock(() => bridge.scanText("Jane Doe"))).toBeNull();
		}
		// One host served every scan.
		expect(chrome.connects).toBe(1);
		expect(bridge.status()).toBe("connected");
	});

	it("with requireNer, accepts a host answer that reports NER coverage", async () => {
		const bridge = createNativeBridge(true, { chrome: fakeChrome() });
		const text = "Toplantıya Jane Doe katılacak.";
		const findings = await withFrozenClock(() => bridge.scanText(text, { requireNer: true }));
		expect(findings?.map((f) => [f.type, slice(text, f)])).toEqual([["PERSON", "Jane Doe"]]);
		expect(await withFrozenClock(() => bridge.scanText("Yarın.", { requireNer: true }))).toEqual(
			[],
		);
	});

	it("with requireNer, a rules-only host is no usable answer (null, no backoff)", async () => {
		const rulesOnly = (response: Msg, request: Msg) =>
			request.op === "commit" ? { ...response, coverage: "rules-only" } : response;
		const chrome = fakeChrome({ tamper: rulesOnly });
		const bridge = createNativeBridge(true, { chrome });
		const text = "Mail ayse@example.com";
		// Without the requirement the rules-only answer is still used.
		expect(await withFrozenClock(() => bridge.scanText(text))).toHaveLength(1);
		for (let i = 0; i < NATIVE_MAX_FAILURES + 1; i++) {
			expect(await withFrozenClock(() => bridge.scanText(text, { requireNer: true }))).toBeNull();
			expect(
				await withFrozenClock(() => bridge.scanText("Yarın.", { requireNer: true })),
			).toBeNull();
		}
		expect(bridge.status()).toBe("connected");
		const missing = fakeChrome({
			tamper: (response, request) => {
				if (request.op !== "commit") return response;
				const { coverage: _dropped, ...rest } = response;
				return rest;
			},
		});
		const silent = createNativeBridge(true, { chrome: missing });
		expect(await withFrozenClock(() => silent.scanText(text, { requireNer: true }))).toBeNull();
	});

	it("counts a host NER engine failure towards backoff", async () => {
		const chrome = fakeChrome({ nerFails: true });
		const bridge = createNativeBridge(true, { chrome });
		for (let i = 0; i < NATIVE_MAX_FAILURES; i++)
			expect(await bridge.scanText("Jane Doe")).toBeNull();
		expect(bridge.status()).toBe("unavailable");
		expect(await bridge.scanText("Jane Doe")).toBeNull();
		// An engine failure ends the connection, so each retry starts a fresh host.
		expect(chrome.connects).toBe(NATIVE_MAX_FAILURES);
	});
});

describe("createNativeBridge: one persistent host (BG-11)", () => {
	it("serves many scans from one host process and one hello", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		for (const text of ["Jane Doe aradı", "Yarın.", "Mail ayse@example.com", "Kadıköy'de"]) {
			expect(await withFrozenClock(() => bridge.scanText(text))).not.toBeNull();
		}
		expect(chrome.connects).toBe(1);
		expect(chrome.disconnects).toBe(0);
		expect(chrome.sent.filter((m) => m.op === "hello")).toHaveLength(1);
		expect(chrome.sent.filter((m) => m.op === "begin")).toHaveLength(4);
	});

	it("queues concurrent scans on the one host instead of refusing the third", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		const texts = ["Jane Doe", "Ayşe Yılmaz", "Kadıköy", "Moda Caddesi No 12", "x@example.com"];
		const results = await withFrozenClock(() => Promise.all(texts.map((t) => bridge.scanText(t))));
		for (const [i, findings] of results.entries()) expect(findings, texts[i]).toHaveLength(1);
		expect(chrome.connects).toBe(1);
	});

	it("answers null at once when the queue is full", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		const chrome = fakeChrome({ hang: ["commit"] });
		const bridge = createNativeBridge(true, { chrome });
		const pending = Array.from({ length: NATIVE_MAX_QUEUED }, () => bridge.scanText("Jane Doe"));
		expect(await bridge.scanText("Jane Doe")).toBeNull();
		await vi.advanceTimersByTimeAsync(NATIVE_TIMEOUT_MS * (NATIVE_MAX_QUEUED + 1));
		expect(await Promise.all(pending)).toEqual(Array(NATIVE_MAX_QUEUED).fill(null));
	});

	it("does not abandon a slow host start when a scan's own deadline passes", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		const chrome = fakeChrome({ hang: ["hello"] });
		const bridge = createNativeBridge(true, { chrome });
		const scan = bridge.scanText("Jane Doe");
		await until(() => chrome.sent.some((m) => m.op === "hello"));
		await vi.advanceTimersByTimeAsync(NATIVE_TIMEOUT_MS);
		expect(await scan).toBeNull();
		// The host is still starting (cold start budget), not killed by the scan's deadline.
		expect(chrome.disconnects).toBe(0);
		await vi.advanceTimersByTimeAsync(NATIVE_CONNECT_TIMEOUT_MS);
		expect(chrome.disconnects).toBe(1);
	});

	it("falls back to one host per scan for an older host that refuses persistent", async () => {
		const chrome = fakeChrome({ legacy: true, edmSecret: Buffer.alloc(32, 9) });
		const bridge = createNativeBridge(true, { chrome });
		const first = await withFrozenClock(() => bridge.scanText("Jane Doe aradı"));
		expect(first?.map((f) => f.type)).toEqual(["PERSON"]);
		const second = await withFrozenClock(() => bridge.scanText("Ayşe Yılmaz aradı"));
		expect(second?.map((f) => f.type)).toEqual(["PERSON"]);
		const hellos = chrome.sent.filter((m) => m.op === "hello");
		expect(hellos.map((m) => "persistent" in m)).toEqual([true, false, false]);
		expect(chrome.connects).toBe(3);
		// The older host cannot derive exact-data keys; it is never sent an op it does not know.
		expect(
			await withFrozenClock(() => bridge.exactDataKeys?.(["crm"]) ?? Promise.resolve(null)),
		).toBeNull();
		expect(chrome.sent.some((m) => m.op === "edm-keys")).toBe(false);
		expect(bridge.status()).toBe("connected");
	});
});

describe("createNativeBridge: exact-data keys from the host (BG-8)", () => {
	const SECRET = Buffer.from(Array.from({ length: 32 }, (_, i) => 200 - i));

	it("returns the per-dataset keys the host derives from its secret", async () => {
		const chrome = fakeChrome({ edmSecret: SECRET });
		const bridge = createNativeBridge(true, { chrome });
		const keys = await withFrozenClock(
			() => bridge.exactDataKeys?.(["crm-customers", "codes"]) ?? Promise.resolve(null),
		);
		expect(keys).toEqual({
			"crm-customers": deriveEdmKey(SECRET, "crm-customers").toString("base64"),
			codes: deriveEdmKey(SECRET, "codes").toString("base64"),
		});
		expect(chrome.sent.find((m) => m.op === "edm-keys")).toMatchObject({
			datasetIds: ["crm-customers", "codes"],
		});
		// The same host then scans.
		expect(await withFrozenClock(() => bridge.scanText("Jane Doe"))).toHaveLength(1);
		expect(chrome.connects).toBe(1);
	});

	it("gets no keys from a host without a secret, and refuses malformed key replies", async () => {
		const none = createNativeBridge(true, { chrome: fakeChrome() });
		expect(
			await withFrozenClock(() => none.exactDataKeys?.(["crm"]) ?? Promise.resolve(null)),
		).toEqual({});
		for (const keys of [{ crm: "short" }, { other: Buffer.alloc(32).toString("base64") }, ["x"]]) {
			const chrome = fakeChrome({
				edmSecret: SECRET,
				tamper: (r, q) => (q.op === "edm-keys" ? { ...r, keys } : r),
			});
			const bridge = createNativeBridge(true, { chrome });
			expect(
				await withFrozenClock(() => bridge.exactDataKeys?.(["crm"]) ?? Promise.resolve(null)),
			).toBeNull();
		}
		const bridge = createNativeBridge(true, { chrome: fakeChrome({ edmSecret: SECRET }) });
		expect(await bridge.exactDataKeys?.([])).toBeNull();
		expect(await bridge.exactDataKeys?.(["bad id"])).toBeNull();
	});
});

describe("createNativeBridge: timeout and backoff", () => {
	it("returns null after the 2 s bound and disconnects the host", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		const chrome = fakeChrome({ hang: ["commit"] });
		const bridge = createNativeBridge(true, { chrome });
		let settled: unknown = "pending";
		const pending = bridge.scanText("Jane Doe").then((r) => {
			settled = r;
		});
		// The fake host answers through real async work (the privacy engine), while
		// advancing fake timers takes no real time. Let the exchange reach the hanging
		// commit with the fake clock held at 0, so a loaded machine cannot let the 2 s
		// bound fire before the host was ever asked to commit.
		await until(() => chrome.sent.some((m) => m.op === "commit"));
		await vi.advanceTimersByTimeAsync(NATIVE_TIMEOUT_MS - 1);
		expect(settled).toBe("pending");
		expect(chrome.sent.map((m) => m.op)).toContain("commit");
		await vi.advanceTimersByTimeAsync(1);
		await pending;
		expect(settled).toBeNull();
		expect(chrome.disconnects).toBeGreaterThanOrEqual(1);
	});

	it("backs off for 60 s after repeated failures, then recovers", async () => {
		let clock = 0;
		let broken = true;
		const chrome = fakeChrome({
			tamper: (response) =>
				broken && response.protocol === 1 ? { ...response, protocol: 2 } : response,
		});
		const bridge = createNativeBridge(true, { chrome, now: () => clock });
		for (let i = 0; i < NATIVE_MAX_FAILURES - 1; i++) {
			expect(await bridge.scanText("Jane Doe")).toBeNull();
			expect(chrome.connects).toBe(i + 1);
		}
		expect(await bridge.scanText("Jane Doe")).toBeNull();
		expect(bridge.status()).toBe("unavailable");
		const connects = chrome.connects;
		clock += NATIVE_RETRY_AFTER_MS - 1;
		expect(await bridge.scanText("Jane Doe")).toBeNull();
		bridge.status();
		await flush();
		expect(chrome.connects).toBe(connects);
		expect(chrome.sent.filter((m) => m.op === "hello")).toHaveLength(connects);

		broken = false;
		clock += 1;
		const findings = await withFrozenClock(() => bridge.scanText("Jane Doe"));
		expect(findings?.map((f) => f.type)).toEqual(["PERSON"]);
		expect(bridge.status()).toBe("connected");
	});
});

describe("createNativeBridge: malformed host responses are rejected", () => {
	const text = "Merhaba Jane Doe";
	const cases: ReadonlyArray<[string, (response: Msg, request: Msg) => Msg | null]> = [
		["hello with an unknown protocol", (r, q) => (q.op === "hello" ? { ...r, protocol: 2 } : r)],
		["hello not declaring a local host", (r, q) => (q.op === "hello" ? { ...r, local: false } : r)],
		["hello with an unexpected key", (r, q) => (q.op === "hello" ? { ...r, debug: "x" } : r)],
		[
			"hello with a bad policy digest",
			(r, q) => (q.op === "hello" ? { ...r, policyDigest: "zz" } : r),
		],
		["a response for another request id", (r, q) => (q.op === "begin" ? { ...r, id: "other" } : r)],
		["a response with ok:false", (r, q) => (q.op === "write" ? { ...r, ok: false } : r)],
		["a wrong write acknowledgement", (r, q) => (q.op === "write" ? { ...r, received: 1 } : r)],
		["an unknown decision", (r, q) => (q.op === "commit" ? { ...r, decision: "maybe" } : r)],
		[
			"a commit for another policy",
			(r, q) => (q.op === "commit" ? { ...r, policyDigest: "e".repeat(64) } : r),
		],
		[
			"counts with an unknown entity",
			(r, q) => (q.op === "commit" ? { ...r, counts: { NAME: 1 } } : r),
		],
		["a negative count", (r, q) => (q.op === "commit" ? { ...r, counts: { PERSON: -1 } } : r)],
		["an oversized output", (r, q) => (q.op === "commit" ? { ...r, outputBytes: 3_000_000 } : r)],
		[
			"a block that still carries output",
			(r, q) => (q.op === "commit" ? { ...r, decision: "block" } : r),
		],
		["a read at the wrong offset", (r, q) => (q.op === "read" ? { ...r, offset: 3 } : r)],
		[
			"non-canonical base64",
			(r, q) => (q.op === "read" ? { ...r, data: `${String(r.data)}\n` } : r),
		],
		["a wrong done flag", (r, q) => (q.op === "read" ? { ...r, done: false } : r)],
		[
			"output that does not match its hash",
			(r, q) =>
				q.op === "read" ? { ...r, data: Buffer.from("Merhaba [EMAIL]").toString("base64") } : r,
		],
		[
			"a host failure frame",
			(r, q) => (q.op === "commit" ? { v: 1, ok: false, code: "NATIVE_HOST_FAILURE" } : r),
		],
		["a non-object frame", (r, q) => (q.op === "hello" ? ([r] as unknown as Msg) : r)],
	];
	for (const [name, tamper] of cases) {
		it(`rejects ${name}`, async () => {
			const chrome = fakeChrome({ tamper });
			const bridge = createNativeBridge(true, { chrome });
			await expect(bridge.scanText(text)).resolves.toBeNull();
		});
	}

	it("rejects sanitised output that contradicts the input", async () => {
		const scanner: DocumentScanner = {
			protect: async (input: string) => {
				const real = await new PrivacyEngine({ ner: dictionaryNer() }).protect(input);
				return { ...real, output: "Tamamen [PERSON] başka" };
			},
			protectJson: async () => {
				throw new Error("unused");
			},
		};
		const bridge = createNativeBridge(true, { chrome: fakeChrome({ scanner }) });
		expect(await bridge.scanText(text)).toBeNull();
	});
});

describe("createNativeBridge: image OCR (image-scan)", () => {
	const IMAGE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4, 5, 6, 7, 8]);

	it("reports sensitive text in an image as counts, without reading anything back", async () => {
		const chrome = fakeChrome({ ocrLines: ["Ad Soyad: Ayşe Yılmaz", "TCKN 10000000146"] });
		const bridge = createNativeBridge(true, { chrome });
		const inspection = await withFrozenClock(
			() => bridge.scanImage?.(IMAGE) ?? Promise.resolve(null),
		);
		expect(inspection).toEqual({
			result: "sensitive",
			counts: { PERSON: 1, TC_KIMLIK: 1 },
			reasons: ["IMAGE_SENSITIVE_TEXT"],
		});
		const ops = chrome.sent.map((m) => m.op);
		expect(ops).toEqual(["hello", "begin", "write", "commit"]);
		expect(chrome.sent.find((m) => m.op === "begin")?.kind).toBe("image-scan");
		expect(bridge.status()).toBe("connected");
	});

	it("reports a benign image as clean", async () => {
		const bridge = createNativeBridge(true, {
			chrome: fakeChrome({ ocrLines: ["Release ready"] }),
		});
		const inspection = await withFrozenClock(
			() => bridge.scanImage?.(IMAGE) ?? Promise.resolve(null),
		);
		expect(inspection).toEqual({ result: "clean", counts: {}, reasons: [] });
	});

	it("with requireNer, reports a clean verdict without NER coverage as incomplete", async () => {
		const withCoverage = (coverage: string) =>
			fakeChrome({
				ocrLines: ["Release ready"],
				tamper: (response, request) =>
					request.op === "commit" ? { ...response, coverage } : response,
			});
		const rulesOnly = createNativeBridge(true, { chrome: withCoverage("rules-only") });
		const inspection = await withFrozenClock(
			() => rulesOnly.scanImage?.(IMAGE, { requireNer: true }) ?? Promise.resolve(null),
		);
		expect(inspection).toEqual({
			result: "incomplete",
			counts: {},
			reasons: ["NATIVE_NER_UNAVAILABLE"],
		});
		const ner = createNativeBridge(true, { chrome: withCoverage("rules-and-ner") });
		expect(
			await withFrozenClock(
				() => ner.scanImage?.(IMAGE, { requireNer: true }) ?? Promise.resolve(null),
			),
		).toEqual({ result: "clean", counts: {}, reasons: [] });
	});

	it("reports an image without readable text as incomplete, never clean", async () => {
		const bridge = createNativeBridge(true, { chrome: fakeChrome({ ocrLines: [] }) });
		const inspection = await withFrozenClock(
			() => bridge.scanImage?.(IMAGE) ?? Promise.resolve(null),
		);
		expect(inspection?.result).toBe("incomplete");
		expect(inspection?.reasons).toEqual(["IMAGE_NO_TEXT"]);
	});

	it("returns null without uploading when the host has no OCR", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		expect(
			await withFrozenClock(() => bridge.scanImage?.(IMAGE) ?? Promise.resolve(null)),
		).toBeNull();
		expect(chrome.sent.map((m) => m.op)).toEqual(["hello"]);
		expect(bridge.status()).toBe("connected");
	});

	it("returns null for oversized or empty images and when disabled", async () => {
		const chrome = fakeChrome({ ocrLines: ["x"] });
		const bridge = createNativeBridge(true, { chrome });
		expect(await bridge.scanImage?.(new Uint8Array(0))).toBeNull();
		expect(await bridge.scanImage?.(new Uint8Array(8_388_609))).toBeNull();
		expect(await createNativeBridge(false, { chrome }).scanImage?.(IMAGE)).toBeNull();
		expect(chrome.sent).toEqual([]);
	});

	it.each([
		["a clean verdict with counts", (r: Msg) => ({ ...r, decision: "allow" })],
		["output bytes", (r: Msg) => ({ ...r, outputBytes: 10 })],
		["a foreign policy digest", (r: Msg) => ({ ...r, policyDigest: "e".repeat(64) })],
		["an unknown decision", (r: Msg) => ({ ...r, decision: "redact" })],
		["an unknown key", (r: Msg) => ({ ...r, text: "Ayşe Yılmaz" })],
	])("rejects a commit with %s", async (_name, change) => {
		const chrome = fakeChrome({
			ocrLines: ["TCKN 10000000146"],
			tamper: (response, request) => (request.op === "commit" ? change(response) : response),
		});
		const bridge = createNativeBridge(true, { chrome });
		expect(
			await withFrozenClock(() => bridge.scanImage?.(IMAGE) ?? Promise.resolve(null)),
		).toBeNull();
	});

	it("gives up after its own deadline", async () => {
		const chrome = fakeChrome({ ocrLines: ["x"], hang: ["commit"] });
		const bridge = createNativeBridge(true, { chrome, imageTimeoutMs: 30 });
		expect(await bridge.scanImage?.(IMAGE)).toBeNull();
	});
});

describe("recoverNativeFindings", () => {
	it("recovers exact spans for label and token markers", () => {
		const input = "Jane Doe met Ayşe Yılmaz";
		expect(recoverNativeFindings(input, "[PERSON] met [PERSON]", { PERSON: 2 })).toEqual([
			{ type: "PERSON", start: 0, end: 8, score: 0.9, source: "native-ner" },
			{ type: "PERSON", start: 13, end: 24, score: 0.9, source: "native-ner" },
		]);
		const token = `[PERSON~v1~${"A".repeat(24)}]`;
		expect(recoverNativeFindings(input, `${token} met ${token}`, { PERSON: 2 })?.length).toBe(2);
	});

	it("over-approximates ambiguous alignments instead of leaking", () => {
		// The literal " x " also occurs inside the redacted value.
		const input = "a x b x c";
		const spans = recoverNativeFindings(input, "[ADDRESS] x c", { ADDRESS: 1 });
		expect(spans?.map((f) => input.slice(f.start, f.end))).toEqual(["a x b"]);
		// Adjacent findings: the boundary is unknown, so the union is one span.
		const adjacent = recoverNativeFindings("JaneDoe!", "[PERSON][LOCATION]!", {
			PERSON: 1,
			LOCATION: 1,
		});
		expect(adjacent).toEqual([
			{ type: "PERSON", start: 0, end: 7, score: 0.9, source: "native-ner" },
		]);
	});

	it("types [REDACTED] only when a single entity type was counted", () => {
		expect(
			recoverNativeFindings("Jane Doe here", "[REDACTED] here", { PERSON: 1 })?.[0]?.type,
		).toBe("PERSON");
		expect(
			recoverNativeFindings("Jane Doe, Kadıköy", "[REDACTED], [REDACTED]", {
				PERSON: 1,
				LOCATION: 1,
			}),
		).toBeNull();
	});

	it("refuses input that already contains host markers", () => {
		expect(recoverNativeFindings("[PERSON] Jane", "[PERSON] [PERSON]", { PERSON: 1 })).toBeNull();
	});

	it("throws on output inconsistent with the input or counts", () => {
		expect(() => recoverNativeFindings("Jane Doe", "Jane [PERSON]x", { PERSON: 1 })).toThrow();
		expect(() => recoverNativeFindings("Jane Doe", "[PERSON]", {})).toThrow();
		expect(() => recoverNativeFindings("Jane Doe", "[PERSON] [PERSON]", { PERSON: 1 })).toThrow();
		expect(() => recoverNativeFindings("Jane", "Jane[PERSON]", { PERSON: 1 })).toThrow();
	});
});
