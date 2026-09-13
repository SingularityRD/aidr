import type { KeyObject } from "node:crypto";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	canonicalReputationFeedManifest,
	canonicalReputationFeedPayload,
	createFileReputationFeedSource,
	loadReputationFeed,
	type ReputationFeedBundle,
	type ReputationFeedManifest,
	type ReputationFeedPayload,
	type ReputationFeedSource,
	ReputationFeedUnavailableError,
	ReputationFeedUpdateError,
	requireAvailableReputationFeed,
	rollbackReputationFeed,
	updateReputationFeed,
} from "../reputation-feed.js";
import { makeTmpDir } from "./test-utils.js";

const NOW = new Date("2026-09-12T12:00:00.000Z");
const LATER = new Date("2026-09-19T12:00:00.000Z");

function digest(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}

describe("signed reputation feed", () => {
	let storeDir: string;
	let privateKey: KeyObject;
	let publicPem: string;

	beforeEach(async () => {
		storeDir = await makeTmpDir();
		const pair = generateKeyPairSync("ed25519");
		privateKey = pair.privateKey;
		publicPem = pair.publicKey.export({ format: "pem", type: "spki" }).toString();
	});

	afterEach(async () => {
		await rm(storeDir, { recursive: true, force: true });
	});

	function makeBundle(
		options: {
			version?: string;
			sequence?: number;
			records?: ReputationFeedPayload["records"];
			issuedAt?: string;
			expiresAt?: string;
			keyId?: string;
			publisher?: string;
			dataset?: string;
		} = {},
	): ReputationFeedBundle {
		const payload: ReputationFeedPayload = {
			schema_version: 1,
			records: options.records ?? [
				{
					id: "url-1",
					kind: "domain",
					indicator: "malicious.example",
					verdict: "deny",
					severity: "critical",
				},
			],
		};
		const payloadJson = canonicalReputationFeedPayload(payload);
		const manifest: ReputationFeedManifest = {
			schema_version: 1,
			feed_id: "enterprise-reputation",
			version: options.version ?? "1.0.0",
			sequence: options.sequence ?? 1,
			issued_at: options.issuedAt ?? NOW.toISOString(),
			expires_at: options.expiresAt ?? LATER.toISOString(),
			key_id: options.keyId ?? "publisher-key-1",
			provenance: {
				publisher: options.publisher ?? "Example Threat Lab",
				dataset: options.dataset ?? "Enterprise Indicators",
				upstream_revision: `revision-${options.sequence ?? 1}`,
			},
			payload: {
				path: "records.json",
				media_type: "application/vnd.aidr.reputation-feed+json",
				sha256: digest(payloadJson),
				record_count: payload.records.length,
			},
		};
		const manifestJson = canonicalReputationFeedManifest(manifest);
		return {
			manifest: manifestJson,
			payload: payloadJson,
			signature: sign(null, Buffer.from(manifestJson), privateKey).toString("base64"),
		};
	}

	function source(
		bundle: ReputationFeedBundle,
		overrides: Partial<ReputationFeedSource["provenance"]> = {},
	): ReputationFeedSource {
		return {
			provenance: {
				transport: "https",
				locator: "https://feeds.example.invalid/v1",
				expectedPublisher: "Example Threat Lab",
				expectedDataset: "Enterprise Indicators",
				...overrides,
			},
			async fetch() {
				return bundle;
			},
		};
	}

	it("installs a trusted feed and exposes signed and transport provenance", async () => {
		const installed = await updateReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			source: source(makeBundle()),
			now: NOW,
		});

		expect(installed.availability).toBe("available");
		expect(installed.fetchedAt).toBe(NOW.toISOString());
		expect(installed.expiresAt).toBe(LATER.toISOString());
		expect(installed.records).toHaveLength(1);
		expect(installed.provenance.signed.upstream_revision).toBe("revision-1");
		expect(installed.provenance.transport.transport).toBe("https");

		const loaded = requireAvailableReputationFeed(
			await loadReputationFeed({
				storeDir,
				feedId: "enterprise-reputation",
				trustedKeys: new Map([["publisher-key-1", publicPem]]),
				now: NOW,
			}),
		);
		expect(loaded.version).toBe("1.0.0");
		expect(loaded.provenance.transport.locator).toBe("https://feeds.example.invalid/v1");
	});

	it("returns explicit fail-closed missing and stale availability", async () => {
		const missing = await loadReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		});
		expect(missing).toMatchObject({ availability: "missing", failClosed: true });
		expect(() => requireAvailableReputationFeed(missing)).toThrow(ReputationFeedUnavailableError);

		await updateReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			source: source(makeBundle()),
			now: NOW,
		});
		const stale = await loadReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: new Date(NOW.getTime() + 25 * 60 * 60 * 1000),
		});
		expect(stale).toMatchObject({ availability: "stale", failClosed: true });

		const expired = await loadReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: LATER,
			maxAgeMs: 30 * 24 * 60 * 60 * 1000,
		});
		expect(expired).toMatchObject({ availability: "stale", failClosed: true });
	});

	it("rejects an old signed revision even if its fetch receipt would be fresh", async () => {
		const common = {
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		};
		await updateReputationFeed({ ...common, source: source(makeBundle()) });
		await expect(
			updateReputationFeed({
				...common,
				source: source(makeBundle({
					version: "2.0.0",
					sequence: 2,
					issuedAt: new Date(NOW.getTime() - 25 * 60 * 60 * 1000).toISOString(),
				})),
			}),
		).rejects.toMatchObject({ reason: "stale" });
		const active = requireAvailableReputationFeed(await loadReputationFeed(common));
		expect(active.version).toBe("1.0.0");
	});

	it("expires a signed revision independently of its fetch receipt", async () => {
		const common = {
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
		};
		await updateReputationFeed({
			...common,
			source: source(makeBundle({
				issuedAt: new Date(NOW.getTime() - 23 * 60 * 60 * 1000).toISOString(),
			})),
			now: NOW,
		});
		const result = await loadReputationFeed({
			...common,
			now: new Date(NOW.getTime() + 2 * 60 * 60 * 1000),
		});
		expect(result).toMatchObject({ availability: "stale", failClosed: true });
		expect(() => requireAvailableReputationFeed(result)).toThrow(ReputationFeedUnavailableError);
	});

	it("fails closed when the configured freshness limit is not finite", async () => {
		const common = {
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		};
		await expect(updateReputationFeed({
			...common,
			source: source(makeBundle()),
			maxAgeMs: Number.NaN,
		})).rejects.toMatchObject({ reason: "malformed" });
		await updateReputationFeed({ ...common, source: source(makeBundle()) });
		const result = await loadReputationFeed({ ...common, maxAgeMs: Number.NaN });
		expect(result).toMatchObject({ availability: "malformed", failClosed: true });
	});

	it("validates against the clock after a slow source fetch completes", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			vi.setSystemTime(NOW);
			const bundle = makeBundle();
			const delayedSource: ReputationFeedSource = {
				...source(bundle),
				async fetch() {
					vi.setSystemTime(new Date(NOW.getTime() + 25 * 60 * 60 * 1000));
					return bundle;
				},
			};
			await expect(updateReputationFeed({
				storeDir,
				feedId: "enterprise-reputation",
				trustedKeys: { "publisher-key-1": publicPem },
				source: delayedSource,
			})).rejects.toMatchObject({ reason: "stale" });
		} finally {
			vi.useRealTimers();
		}
	});

	it("rejects empty, malformed and untrusted updates without publishing state", async () => {
		const empty = makeBundle({ records: [] });
		await expect(
			updateReputationFeed({
				storeDir,
				feedId: "enterprise-reputation",
				trustedKeys: { "publisher-key-1": publicPem },
				source: source(empty),
				now: NOW,
			}),
		).rejects.toMatchObject({ reason: "empty" });

		const malformed = makeBundle();
		malformed.payload = "{not-json";
		await expect(
			updateReputationFeed({
				storeDir,
				feedId: "enterprise-reputation",
				trustedKeys: { "publisher-key-1": publicPem },
				source: source(malformed),
				now: NOW,
			}),
		).rejects.toMatchObject({ reason: "malformed" });

		const untrusted = makeBundle();
		untrusted.signature = Buffer.alloc(64, 7).toString("base64");
		await expect(
			updateReputationFeed({
				storeDir,
				feedId: "enterprise-reputation",
				trustedKeys: { "publisher-key-1": publicPem },
				source: source(untrusted),
				now: NOW,
			}),
		).rejects.toBeInstanceOf(ReputationFeedUpdateError);

		const state = await loadReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		});
		expect(state.availability).toBe("missing");
	});

	it("commits advancing versions atomically and rolls back to a verified previous version", async () => {
		const common = {
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		};
		await updateReputationFeed({ ...common, source: source(makeBundle()) });
		await updateReputationFeed({
			...common,
			expectedActiveVersion: "1.0.0",
			source: source(makeBundle({ version: "2.0.0", sequence: 2 })),
		});

		const tampered = makeBundle({ version: "3.0.0", sequence: 3 });
		tampered.payload = `${String(tampered.payload)} `;
		await expect(
			updateReputationFeed({ ...common, source: source(tampered) }),
		).rejects.toMatchObject({ reason: "malformed" });

		const beforeRollback = requireAvailableReputationFeed(
			await loadReputationFeed({ ...common, feedId: "enterprise-reputation" }),
		);
		expect(beforeRollback.version).toBe("2.0.0");

		const rolledBack = await rollbackReputationFeed({
			...common,
			feedId: "enterprise-reputation",
		});
		expect(rolledBack.version).toBe("1.0.0");
		expect(
			requireAvailableReputationFeed(
				await loadReputationFeed({ ...common, feedId: "enterprise-reputation" }),
			).version,
		).toBe("1.0.0");
		await expect(
			updateReputationFeed({
				...common,
				source: source(makeBundle({ version: "2.1.0", sequence: 2 })),
			}),
		).rejects.toMatchObject({ reason: "untrusted" });
	});

	it("reports a malformed activation pointer instead of returning a clean feed", async () => {
		await updateReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			source: source(makeBundle()),
			now: NOW,
		});
		await writeFile(join(storeDir, "enterprise-reputation", "state.json"), "{not-json", "utf8");
		const result = await loadReputationFeed({
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		});
		expect(result).toMatchObject({ availability: "malformed", failClosed: true });
	});

	it("rejects replayed sequences and mismatched signed provenance", async () => {
		const common = {
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			now: NOW,
		};
		await updateReputationFeed({ ...common, source: source(makeBundle()) });
		await expect(
			updateReputationFeed({
				...common,
				source: source(makeBundle({ version: "1.1.0", sequence: 1 })),
			}),
		).rejects.toMatchObject({ reason: "untrusted" });

		await expect(
			updateReputationFeed({
				...common,
				source: source(makeBundle({ version: "2.0.0", sequence: 2, publisher: "Other Lab" })),
			}),
		).rejects.toMatchObject({ reason: "untrusted" });
	});

	it("imports a bounded offline feed package through the file source", async () => {
		const packageDir = join(storeDir, "incoming-package");
		await mkdir(packageDir, { recursive: true });
		const bundle = makeBundle();
		await Promise.all([
			writeFile(join(packageDir, "manifest.json"), bundle.manifest),
			writeFile(join(packageDir, "manifest.sig"), bundle.signature),
			writeFile(join(packageDir, "records.json"), bundle.payload),
		]);

		const fileSource = createFileReputationFeedSource({
			directory: packageDir,
			locator: "customer-offline-package",
			expectedPublisher: "Example Threat Lab",
			expectedDataset: "Enterprise Indicators",
		});
		const installed = await updateReputationFeed({
			storeDir: join(storeDir, "installed"),
			feedId: "enterprise-reputation",
			trustedKeys: { "publisher-key-1": publicPem },
			source: fileSource,
			now: NOW,
		});
		expect(installed.provenance.transport).toMatchObject({
			transport: "file",
			locator: "customer-offline-package",
		});
		expect(await readFile(join(packageDir, "manifest.json"), "utf8")).toBe(String(bundle.manifest));
	});
});
