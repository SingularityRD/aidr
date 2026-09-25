import { performance as hostClock } from "node:perf_hooks";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DocumentScanner } from "../../../privacy/src/browser/documents.js";
import { PrivacyEngine } from "../../../privacy/src/engine.js";
import { NativeSession } from "../../../privacy/src/native/session.js";
import type { EngineOptions, NerProvider } from "../../../privacy/src/types.js";
import {
	createNativeBridge,
	NATIVE_HOST_NAME,
	NATIVE_MAX_FAILURES,
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
			sendNativeMessage: async (name, message) => {
				if (name !== NATIVE_HOST_NAME || options.installed === false) {
					throw new Error("Specified native messaging host not found.");
				}
				const request = JSON.parse(JSON.stringify(message)) as Msg;
				chrome.sent.push(request);
				const response = await makeSession().handle(request);
				const out = options.tamper ? options.tamper(response, request) : response;
				return JSON.parse(JSON.stringify(out));
			},
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
						session.handle(request).then(
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

	it("lazily probes with a hello handshake and reports connected", async () => {
		const chrome = fakeChrome();
		const bridge = createNativeBridge(true, { chrome });
		expect(chrome.sent).toEqual([]);
		expect(bridge.status()).toBe("unavailable");
		await flush();
		expect(bridge.status()).toBe("connected");
		expect(chrome.sent).toHaveLength(1);
		expect(Object.keys(chrome.sent[0] ?? {}).sort()).toEqual(["id", "op", "v"]);
		expect(chrome.sent[0]?.op).toBe("hello");
	});

	it("probes through connectNative when sendNativeMessage is not available", async () => {
		const chrome = fakeChrome();
		const runtime = { ...chrome.runtime, sendNativeMessage: undefined };
		const bridge = createNativeBridge(true, { chrome: { ...chrome, runtime } });
		bridge.status();
		// The probe closes its port once the hello round trip settled, successfully or not.
		await until(() => chrome.disconnects > 0);
		expect(bridge.status()).toBe("connected");
		expect(chrome.connects).toBe(1);
		expect(chrome.disconnects).toBeGreaterThanOrEqual(1);
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
		expect(chrome.connects).toBe(0);
		clock += NATIVE_RETRY_AFTER_MS;
		expect(await bridge.scanText("Ayşe Yılmaz")).toBeNull();
		expect(chrome.connects).toBe(1);
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
		expect(chrome.disconnects).toBeGreaterThanOrEqual(1);
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
			hello: [],
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
		expect(chrome.connects).toBe(NATIVE_MAX_FAILURES + 1);
		expect(bridge.status()).toBe("connected");
	});

	it("counts a host NER engine failure towards backoff", async () => {
		const chrome = fakeChrome({ nerFails: true });
		const bridge = createNativeBridge(true, { chrome });
		for (let i = 0; i < NATIVE_MAX_FAILURES; i++)
			expect(await bridge.scanText("Jane Doe")).toBeNull();
		expect(bridge.status()).toBe("unavailable");
		expect(await bridge.scanText("Jane Doe")).toBeNull();
		expect(chrome.connects).toBe(NATIVE_MAX_FAILURES);
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
