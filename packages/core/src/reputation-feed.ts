import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, open, readFile, rename, rm, stat, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";

import { verifyEd25519Signature } from "./intel/verify.js";

export const REPUTATION_FEED_SCHEMA_VERSION = 1 as const;
export const DEFAULT_REPUTATION_FEED_MAX_AGE_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_REPUTATION_FEED_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

const DateTimeSchema = z.string().datetime({ offset: true });
const SafeIdSchema = z.string().regex(SAFE_ID);

const ReputationIndicatorKindSchema = z.enum([
	"url",
	"domain",
	"file_sha256",
	"package_name",
	"package_sha256",
	"plugin_signature",
	"ai_fingerprint",
	"cve",
]);

export const ReputationFeedRecordSchema = z.object({
	id: SafeIdSchema,
	kind: ReputationIndicatorKindSchema,
	indicator: z.string().trim().min(1).max(4096),
	verdict: z.enum(["allow", "ask", "deny"]),
	severity: z.enum(["critical", "high", "medium", "low"]).optional(),
	confidence: z.number().min(0).max(1).optional(),
	reason: z.string().trim().min(1).max(2048).optional(),
	valid_from: DateTimeSchema.optional(),
	expires_at: DateTimeSchema.optional(),
	source_reference: z.string().trim().min(1).max(2048).optional(),
});

export const ReputationFeedPayloadSchema = z.object({
	schema_version: z.literal(REPUTATION_FEED_SCHEMA_VERSION),
	records: z.array(ReputationFeedRecordSchema),
});

export const ReputationFeedManifestSchema = z.object({
	schema_version: z.literal(REPUTATION_FEED_SCHEMA_VERSION),
	feed_id: SafeIdSchema,
	version: SafeIdSchema,
	sequence: z.number().int().nonnegative(),
	issued_at: DateTimeSchema,
	expires_at: DateTimeSchema,
	key_id: SafeIdSchema,
	provenance: z.object({
		publisher: z.string().trim().min(1).max(256),
		dataset: z.string().trim().min(1).max(256),
		upstream_revision: z.string().trim().min(1).max(512),
		license: z.string().trim().min(1).max(256).optional(),
	}),
	payload: z.object({
		path: z.literal("records.json"),
		media_type: z.literal("application/vnd.aidr.reputation-feed+json"),
		sha256: z.string().regex(SHA256),
		record_count: z.number().int().nonnegative(),
	}),
});

const StoreStateSchema = z.object({
	schema_version: z.literal(REPUTATION_FEED_SCHEMA_VERSION),
	active_version: SafeIdSchema,
	previous_version: SafeIdSchema.nullable(),
	highest_sequence: z.number().int().nonnegative(),
	generation: z.number().int().positive(),
	updated_at: DateTimeSchema,
});

const FetchReceiptSchema = z.object({
	schema_version: z.literal(REPUTATION_FEED_SCHEMA_VERSION),
	fetched_at: DateTimeSchema,
	manifest_sha256: z.string().regex(SHA256),
	source: z.object({
		transport: z.enum(["https", "file", "package", "custom"]),
		locator: z.string().trim().min(1).max(4096),
	}),
});

export type ReputationIndicatorKind = z.infer<typeof ReputationIndicatorKindSchema>;
export type ReputationFeedRecord = z.infer<typeof ReputationFeedRecordSchema>;
export type ReputationFeedPayload = z.infer<typeof ReputationFeedPayloadSchema>;
export type ReputationFeedManifest = z.infer<typeof ReputationFeedManifestSchema>;

export interface ReputationFeedTransportProvenance {
	transport: "https" | "file" | "package" | "custom";
	/** Stable, non-secret source identifier. Do not include URL credentials or tokens. */
	locator: string;
	/** Pin an expected signed publisher when a source is configured. */
	expectedPublisher?: string;
	/** Pin an expected signed dataset when a source is configured. */
	expectedDataset?: string;
}

export interface ReputationFeedBundle {
	manifest: Uint8Array | string;
	signature: string;
	payload: Uint8Array | string;
}

/**
 * Fetch transport abstraction. Implementations supply bytes only; trust comes
 * from the signed manifest, configured keyring and optional provenance pins.
 */
export interface ReputationFeedSource {
	readonly provenance: ReputationFeedTransportProvenance;
	fetch(signal?: AbortSignal): Promise<ReputationFeedBundle>;
}

export type ReputationFeedUnavailableReason =
	| "missing"
	| "empty"
	| "stale"
	| "malformed"
	| "untrusted"
	| "rollback_unavailable"
	| "update_locked"
	| "io_error";

export interface ReputationFeedSnapshot {
	availability: "available";
	failClosed: false;
	feedId: string;
	version: string;
	sequence: number;
	fetchedAt: string;
	expiresAt: string;
	manifest: ReputationFeedManifest;
	records: readonly ReputationFeedRecord[];
	provenance: {
		signed: ReputationFeedManifest["provenance"];
		transport: ReputationFeedTransportProvenance;
	};
}

export interface ReputationFeedUnavailable {
	availability: ReputationFeedUnavailableReason;
	failClosed: true;
	feedId: string;
	detail: string;
	activeVersion?: string;
}

export type ReputationFeedLoadResult = ReputationFeedSnapshot | ReputationFeedUnavailable;

export interface ReputationFeedLoadOptions {
	storeDir: string;
	feedId: string;
	trustedKeys: ReadonlyMap<string, string> | Readonly<Record<string, string>>;
	maxAgeMs?: number;
	now?: Date;
	clockSkewMs?: number;
}

export interface ReputationFeedUpdateOptions extends ReputationFeedLoadOptions {
	source: ReputationFeedSource;
	signal?: AbortSignal;
	expectedActiveVersion?: string | null;
	maxManifestBytes?: number;
	maxPayloadBytes?: number;
}

export class ReputationFeedUnavailableError extends Error {
	readonly reason: ReputationFeedUnavailableReason;

	constructor(reason: ReputationFeedUnavailableReason, message: string) {
		super(message);
		this.name = "ReputationFeedUnavailableError";
		this.reason = reason;
	}
}

export class ReputationFeedUpdateError extends Error {
	readonly reason: ReputationFeedUnavailableReason;

	constructor(reason: ReputationFeedUnavailableReason, message: string) {
		super(message);
		this.name = "ReputationFeedUpdateError";
		this.reason = reason;
	}
}

class FeedValidationError extends Error {
	constructor(
		readonly reason: ReputationFeedUnavailableReason,
		message: string,
	) {
		super(message);
	}
}

function bytes(value: Uint8Array | string): Uint8Array {
	return typeof value === "string" ? Buffer.from(value, "utf8") : value;
}

function sha256(value: Uint8Array | string): string {
	return createHash("sha256").update(bytes(value)).digest("hex");
}

function canonicalJsonValue(value: unknown): string {
	if (value === null || typeof value === "boolean" || typeof value === "string") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value))
			throw new TypeError("Canonical JSON cannot contain non-finite numbers");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJsonValue).join(",")}]`;
	if (typeof value === "object") {
		const object = value as Record<string, unknown>;
		const entries = Object.keys(object)
			.sort()
			.filter((key) => object[key] !== undefined)
			.map((key) => `${JSON.stringify(key)}:${canonicalJsonValue(object[key])}`);
		return `{${entries.join(",")}}`;
	}
	throw new TypeError("Canonical JSON supports JSON values only");
}

/** Stable bytes that publishers sign and consumers verify byte-for-byte. */
export function canonicalReputationFeedManifest(manifest: ReputationFeedManifest): string {
	return canonicalJsonValue(ReputationFeedManifestSchema.parse(manifest));
}

export function canonicalReputationFeedPayload(payload: ReputationFeedPayload): string {
	return canonicalJsonValue(ReputationFeedPayloadSchema.parse(payload));
}

function asTrustedKeyMap(
	keys: ReadonlyMap<string, string> | Readonly<Record<string, string>>,
): ReadonlyMap<string, string> {
	return keys instanceof Map ? keys : new Map(Object.entries(keys));
}

function parseJson(raw: Uint8Array, label: string): unknown {
	try {
		return JSON.parse(Buffer.from(raw).toString("utf8")) as unknown;
	} catch {
		throw new FeedValidationError("malformed", `${label} is not valid JSON`);
	}
}

function assertTimeWindow(
	manifest: ReputationFeedManifest,
	nowMs: number,
	clockSkewMs: number,
	maxAgeMs: number,
): void {
	if (
		!Number.isFinite(nowMs) ||
		!Number.isFinite(clockSkewMs) ||
		clockSkewMs < 0 ||
		!Number.isFinite(maxAgeMs) ||
		maxAgeMs < 0
	) {
		throw new FeedValidationError("malformed", "Feed freshness options are invalid");
	}
	const issuedAt = Date.parse(manifest.issued_at);
	const expiresAt = Date.parse(manifest.expires_at);
	if (expiresAt <= issuedAt) {
		throw new FeedValidationError("malformed", "Feed expires_at must be after issued_at");
	}
	if (issuedAt > nowMs + clockSkewMs) {
		throw new FeedValidationError("malformed", "Feed issued_at is in the future");
	}
	if (expiresAt <= nowMs) {
		throw new FeedValidationError("stale", "Feed manifest is expired");
	}
	if (nowMs - issuedAt > maxAgeMs) {
		throw new FeedValidationError("stale", "Feed issued_at exceeds the configured maximum age");
	}
}

function validateRecord(record: ReputationFeedRecord, ids: Set<string>): void {
	if (ids.has(record.id)) {
		throw new FeedValidationError("malformed", `Feed contains duplicate record id: ${record.id}`);
	}
	ids.add(record.id);
	const isHash = record.kind === "file_sha256" || record.kind === "package_sha256";
	if (isHash && !SHA256.test(record.indicator.toLowerCase())) {
		throw new FeedValidationError(
			"malformed",
			`Feed record ${record.id} does not contain a SHA-256 indicator`,
		);
	}
	if (
		record.valid_from &&
		record.expires_at &&
		Date.parse(record.expires_at) <= Date.parse(record.valid_from)
	) {
		throw new FeedValidationError(
			"malformed",
			`Feed record ${record.id} expires before it becomes valid`,
		);
	}
}

function isRecordActive(record: ReputationFeedRecord, nowMs: number): boolean {
	if (record.valid_from && Date.parse(record.valid_from) > nowMs) return false;
	if (record.expires_at && Date.parse(record.expires_at) <= nowMs) return false;
	return true;
}

function validateRecords(
	payload: ReputationFeedPayload,
	manifest: ReputationFeedManifest,
	nowMs: number,
): ReputationFeedRecord[] {
	if (payload.records.length !== manifest.payload.record_count) {
		throw new FeedValidationError("malformed", "Feed record_count does not match payload");
	}
	if (payload.records.length === 0) {
		throw new FeedValidationError("empty", "Feed contains no reputation records");
	}
	const ids = new Set<string>();
	for (const record of payload.records) validateRecord(record, ids);
	const active = payload.records.filter((record) => isRecordActive(record, nowMs));
	if (active.length === 0) {
		throw new FeedValidationError("empty", "Feed has no currently active reputation records");
	}
	return active;
}

interface ValidatedBundle {
	manifest: ReputationFeedManifest;
	manifestBytes: Uint8Array;
	payloadBytes: Uint8Array;
	signature: string;
	records: ReputationFeedRecord[];
}

function parseManifest(manifestBytes: Uint8Array): ReputationFeedManifest {
	const parsed = ReputationFeedManifestSchema.safeParse(parseJson(manifestBytes, "Feed manifest"));
	if (!parsed.success) {
		throw new FeedValidationError("malformed", "Feed manifest schema is invalid");
	}
	if (
		Buffer.from(manifestBytes).toString("utf8") !== canonicalReputationFeedManifest(parsed.data)
	) {
		throw new FeedValidationError("malformed", "Feed manifest is not canonical JSON");
	}
	return parsed.data;
}

function assertBundleBounds(
	manifestBytes: Uint8Array,
	payloadBytes: Uint8Array,
	signature: string,
	maximums: { manifest: number; payload: number },
): void {
	if (manifestBytes.length === 0 || manifestBytes.length > maximums.manifest) {
		throw new FeedValidationError("malformed", "Feed manifest size is invalid");
	}
	if (payloadBytes.length === 0 || payloadBytes.length > maximums.payload) {
		throw new FeedValidationError("malformed", "Feed payload size is invalid");
	}
	if (!signature || signature.length > 16_384 || !BASE64.test(signature)) {
		throw new FeedValidationError("untrusted", "Feed signature encoding is invalid");
	}
}

function assertManifestTrust(params: {
	manifest: ReputationFeedManifest;
	manifestBytes: Uint8Array;
	signature: string;
	trustedKeys: ReadonlyMap<string, string> | Readonly<Record<string, string>>;
	provenance?: ReputationFeedTransportProvenance;
}): void {
	const key = asTrustedKeyMap(params.trustedKeys).get(params.manifest.key_id);
	if (!key) throw new FeedValidationError("untrusted", "Feed signing key is not trusted");
	if (
		!verifyEd25519Signature({
			publicKeyPem: key,
			message: params.manifestBytes,
			signatureBase64: params.signature,
		})
	) {
		throw new FeedValidationError("untrusted", "Feed signature verification failed");
	}
	if (
		params.provenance?.expectedPublisher &&
		params.provenance.expectedPublisher !== params.manifest.provenance.publisher
	) {
		throw new FeedValidationError("untrusted", "Feed publisher does not match source pin");
	}
	if (
		params.provenance?.expectedDataset &&
		params.provenance.expectedDataset !== params.manifest.provenance.dataset
	) {
		throw new FeedValidationError("untrusted", "Feed dataset does not match source pin");
	}
}

function validateBundle(params: {
	bundle: ReputationFeedBundle;
	trustedKeys: ReadonlyMap<string, string> | Readonly<Record<string, string>>;
	provenance?: ReputationFeedTransportProvenance;
	now: Date;
	clockSkewMs: number;
	maxAgeMs: number;
	maxManifestBytes: number;
	maxPayloadBytes: number;
}): ValidatedBundle {
	const manifestBytes = bytes(params.bundle.manifest);
	const payloadBytes = bytes(params.bundle.payload);
	const signature = params.bundle.signature.trim();
	assertBundleBounds(manifestBytes, payloadBytes, signature, {
		manifest: params.maxManifestBytes,
		payload: params.maxPayloadBytes,
	});
	const manifest = parseManifest(manifestBytes);
	assertManifestTrust({
		manifest,
		manifestBytes,
		signature,
		trustedKeys: params.trustedKeys,
		provenance: params.provenance,
	});
	assertTimeWindow(manifest, params.now.getTime(), params.clockSkewMs, params.maxAgeMs);
	if (sha256(payloadBytes) !== manifest.payload.sha256) {
		throw new FeedValidationError("malformed", "Feed payload sha256 does not match manifest");
	}
	const payloadParsed = ReputationFeedPayloadSchema.safeParse(
		parseJson(payloadBytes, "Feed payload"),
	);
	if (!payloadParsed.success) {
		throw new FeedValidationError("malformed", "Feed payload schema is invalid");
	}
	const records = validateRecords(payloadParsed.data, manifest, params.now.getTime());
	return { manifest, manifestBytes, payloadBytes, signature, records };
}

function feedRoot(storeDir: string, feedId: string): string {
	if (!SAFE_ID.test(feedId)) throw new FeedValidationError("malformed", "Feed id is invalid");
	return join(resolve(storeDir), feedId);
}

function versionRoot(root: string, version: string): string {
	if (!SAFE_ID.test(version)) throw new FeedValidationError("malformed", "Feed version is invalid");
	return join(root, "versions", version);
}

async function durableWrite(path: string, value: Uint8Array | string): Promise<void> {
	await mkdir(dirname(path), { recursive: true });
	const handle = await open(path, "wx", 0o600);
	try {
		await handle.writeFile(value);
		await handle.sync();
	} finally {
		await handle.close();
	}
}

async function atomicJson(path: string, value: unknown): Promise<void> {
	const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
	try {
		await durableWrite(temporary, `${JSON.stringify(value)}\n`);
		await rename(temporary, path);
	} catch (error) {
		await unlink(temporary).catch(() => undefined);
		throw error;
	}
}

async function readStoreState(root: string): Promise<z.infer<typeof StoreStateSchema> | null> {
	try {
		return StoreStateSchema.parse(JSON.parse(await readFile(join(root, "state.json"), "utf8")));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw new FeedValidationError("malformed", "Feed activation state is invalid");
	}
}

async function readStoredManifest(params: {
	root: string;
	version: string;
	trustedKeys: ReputationFeedLoadOptions["trustedKeys"];
}): Promise<ReputationFeedManifest> {
	let manifestBytes: Uint8Array;
	let signature: string;
	try {
		[manifestBytes, signature] = await Promise.all([
			readFile(join(versionRoot(params.root, params.version), "manifest.json")),
			readFile(join(versionRoot(params.root, params.version), "manifest.sig"), "utf8"),
		]);
	} catch {
		throw new FeedValidationError("malformed", "Active feed manifest is incomplete");
	}
	const parsed = ReputationFeedManifestSchema.safeParse(parseJson(manifestBytes, "Feed manifest"));
	if (!parsed.success) {
		throw new FeedValidationError("malformed", "Active feed manifest schema is invalid");
	}
	if (
		Buffer.from(manifestBytes).toString("utf8") !== canonicalReputationFeedManifest(parsed.data)
	) {
		throw new FeedValidationError("malformed", "Active feed manifest is not canonical JSON");
	}
	const key = asTrustedKeyMap(params.trustedKeys).get(parsed.data.key_id);
	if (
		!key ||
		!verifyEd25519Signature({
			publicKeyPem: key,
			message: manifestBytes,
			signatureBase64: signature.trim(),
		})
	) {
		throw new FeedValidationError("untrusted", "Active feed manifest is not trusted");
	}
	if (parsed.data.version !== params.version) {
		throw new FeedValidationError("malformed", "Active feed version does not match its directory");
	}
	return parsed.data;
}

async function readVersion(params: {
	root: string;
	version: string;
	trustedKeys: ReputationFeedLoadOptions["trustedKeys"];
	now: Date;
	clockSkewMs: number;
	maxAgeMs: number;
}): Promise<ReputationFeedSnapshot> {
	const root = versionRoot(params.root, params.version);
	let manifestBytes: Uint8Array;
	let payloadBytes: Uint8Array;
	let signature: string;
	let receiptRaw: string;
	try {
		[manifestBytes, payloadBytes, signature, receiptRaw] = await Promise.all([
			readFile(join(root, "manifest.json")),
			readFile(join(root, "records.json")),
			readFile(join(root, "manifest.sig"), "utf8"),
			readFile(join(root, "receipt.json"), "utf8"),
		]);
	} catch {
		throw new FeedValidationError("malformed", "Active feed version is incomplete");
	}

	const receipt = FetchReceiptSchema.safeParse(parseJson(Buffer.from(receiptRaw), "Feed receipt"));
	if (!receipt.success)
		throw new FeedValidationError("malformed", "Feed receipt schema is invalid");
	if (receipt.data.manifest_sha256 !== sha256(manifestBytes)) {
		throw new FeedValidationError("malformed", "Feed receipt does not match manifest");
	}
	const fetchedAt = Date.parse(receipt.data.fetched_at);
	if (fetchedAt > params.now.getTime() + params.clockSkewMs) {
		throw new FeedValidationError("malformed", "Feed fetched_at is in the future");
	}
	if (params.now.getTime() - fetchedAt > params.maxAgeMs) {
		throw new FeedValidationError("stale", "Feed fetched_at exceeds the configured maximum age");
	}

	const validated = validateBundle({
		bundle: { manifest: manifestBytes, payload: payloadBytes, signature },
		trustedKeys: params.trustedKeys,
		now: params.now,
		clockSkewMs: params.clockSkewMs,
		maxAgeMs: params.maxAgeMs,
		maxManifestBytes: 256 * 1024,
		maxPayloadBytes: DEFAULT_REPUTATION_FEED_MAX_PAYLOAD_BYTES,
	});
	if (validated.manifest.version !== params.version) {
		throw new FeedValidationError("malformed", "Feed directory version does not match manifest");
	}
	return {
		availability: "available",
		failClosed: false,
		feedId: validated.manifest.feed_id,
		version: validated.manifest.version,
		sequence: validated.manifest.sequence,
		fetchedAt: receipt.data.fetched_at,
		expiresAt: validated.manifest.expires_at,
		manifest: validated.manifest,
		records: validated.records,
		provenance: {
			signed: validated.manifest.provenance,
			transport: receipt.data.source,
		},
	};
}

function unavailable(
	feedId: string,
	reason: ReputationFeedUnavailableReason,
	detail: string,
	activeVersion?: string,
): ReputationFeedUnavailable {
	return {
		availability: reason,
		failClosed: true,
		feedId,
		detail,
		...(activeVersion ? { activeVersion } : {}),
	};
}

export async function loadReputationFeed(
	options: ReputationFeedLoadOptions,
): Promise<ReputationFeedLoadResult> {
	let root: string;
	try {
		root = feedRoot(options.storeDir, options.feedId);
		const state = await readStoreState(root);
		if (!state) return unavailable(options.feedId, "missing", "Feed has no active version");
		const snapshot = await readVersion({
			root,
			version: state.active_version,
			trustedKeys: options.trustedKeys,
			now: options.now ?? new Date(),
			clockSkewMs: options.clockSkewMs ?? 5 * 60 * 1000,
			maxAgeMs: options.maxAgeMs ?? DEFAULT_REPUTATION_FEED_MAX_AGE_MS,
		});
		if (snapshot.feedId !== options.feedId) {
			return unavailable(
				options.feedId,
				"malformed",
				"Active feed id does not match requested feed",
				state.active_version,
			);
		}
		return snapshot;
	} catch (error) {
		if (error instanceof FeedValidationError) {
			return unavailable(options.feedId, error.reason, error.message);
		}
		return unavailable(options.feedId, "io_error", "Feed could not be read");
	}
}

export function requireAvailableReputationFeed(
	result: ReputationFeedLoadResult,
): ReputationFeedSnapshot {
	if (result.availability === "available") return result;
	throw new ReputationFeedUnavailableError(result.availability, result.detail);
}

async function withUpdateLock<T>(root: string, operation: () => Promise<T>): Promise<T> {
	await mkdir(root, { recursive: true });
	const lockPath = join(root, ".update.lock");
	let handle: Awaited<ReturnType<typeof open>>;
	try {
		handle = await open(lockPath, "wx", 0o600);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "EEXIST") {
			throw new FeedValidationError("update_locked", "Another feed update is in progress");
		}
		throw error;
	}
	try {
		await handle.writeFile(`${process.pid} ${new Date().toISOString()}\n`);
		await handle.sync();
		return await operation();
	} finally {
		await handle.close();
		await unlink(lockPath).catch(() => undefined);
	}
}

async function assertUpdateCanAdvance(params: {
	root: string;
	state: z.infer<typeof StoreStateSchema> | null;
	validated: ValidatedBundle;
	trustedKeys: ReputationFeedUpdateOptions["trustedKeys"];
	expectedActiveVersion?: string | null;
}): Promise<void> {
	if (
		params.expectedActiveVersion !== undefined &&
		(params.state?.active_version ?? null) !== params.expectedActiveVersion
	) {
		throw new FeedValidationError("malformed", "Active feed version changed before update");
	}
	if (!params.state) return;
	const activeManifest = await readStoredManifest({
		root: params.root,
		version: params.state.active_version,
		trustedKeys: params.trustedKeys,
	});
	if (activeManifest.sequence > params.state.highest_sequence) {
		throw new FeedValidationError(
			"malformed",
			"Feed activation state has an invalid sequence boundary",
		);
	}
	if (params.validated.manifest.sequence <= params.state.highest_sequence) {
		throw new FeedValidationError(
			"untrusted",
			"Feed update sequence must advance beyond every installed version",
		);
	}
}

async function assertVersionDoesNotExist(root: string, version: string): Promise<void> {
	try {
		await stat(versionRoot(root, version));
		throw new FeedValidationError("untrusted", "Feed version already exists in the store");
	} catch (error) {
		if (error instanceof FeedValidationError) throw error;
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}

async function stageVersion(params: {
	root: string;
	validated: ValidatedBundle;
	now: Date;
	source: ReputationFeedTransportProvenance;
}): Promise<void> {
	const finalRoot = versionRoot(params.root, params.validated.manifest.version);
	const staging = join(params.root, `.staging-${randomUUID()}`);
	try {
		await mkdir(staging, { recursive: false });
		await durableWrite(join(staging, "manifest.json"), params.validated.manifestBytes);
		await durableWrite(join(staging, "manifest.sig"), `${params.validated.signature}\n`);
		await durableWrite(join(staging, "records.json"), params.validated.payloadBytes);
		await durableWrite(
			join(staging, "receipt.json"),
			`${JSON.stringify({
				schema_version: REPUTATION_FEED_SCHEMA_VERSION,
				fetched_at: params.now.toISOString(),
				manifest_sha256: sha256(params.validated.manifestBytes),
				source: {
					transport: params.source.transport,
					locator: params.source.locator,
				},
			})}\n`,
		);
		await mkdir(dirname(finalRoot), { recursive: true });
		await rename(staging, finalRoot);
	} catch (error) {
		await rm(staging, { recursive: true, force: true }).catch(() => undefined);
		throw error;
	}
}

function snapshotFromValidated(
	validated: ValidatedBundle,
	now: Date,
	transport: ReputationFeedTransportProvenance,
): ReputationFeedSnapshot {
	return {
		availability: "available",
		failClosed: false,
		feedId: validated.manifest.feed_id,
		version: validated.manifest.version,
		sequence: validated.manifest.sequence,
		fetchedAt: now.toISOString(),
		expiresAt: validated.manifest.expires_at,
		manifest: validated.manifest,
		records: validated.records,
		provenance: { signed: validated.manifest.provenance, transport },
	};
}

async function commitValidatedUpdate(params: {
	root: string;
	validated: ValidatedBundle;
	options: ReputationFeedUpdateOptions;
	now: Date;
}): Promise<ReputationFeedSnapshot> {
	const state = await readStoreState(params.root);
	await assertUpdateCanAdvance({
		root: params.root,
		state,
		validated: params.validated,
		trustedKeys: params.options.trustedKeys,
		expectedActiveVersion: params.options.expectedActiveVersion,
	});
	await assertVersionDoesNotExist(params.root, params.validated.manifest.version);
	await stageVersion({
		root: params.root,
		validated: params.validated,
		now: params.now,
		source: params.options.source.provenance,
	});
	await atomicJson(join(params.root, "state.json"), {
		schema_version: REPUTATION_FEED_SCHEMA_VERSION,
		active_version: params.validated.manifest.version,
		previous_version: state?.active_version ?? null,
		highest_sequence: params.validated.manifest.sequence,
		generation: (state?.generation ?? 0) + 1,
		updated_at: params.now.toISOString(),
	});
	return snapshotFromValidated(params.validated, params.now, params.options.source.provenance);
}

export async function updateReputationFeed(
	options: ReputationFeedUpdateOptions,
): Promise<ReputationFeedSnapshot> {
	let validated: ValidatedBundle;
	let now: Date;
	try {
		const bundle = await options.source.fetch(options.signal);
		now = options.now ?? new Date();
		validated = validateBundle({
			bundle,
			trustedKeys: options.trustedKeys,
			provenance: options.source.provenance,
			now,
			clockSkewMs: options.clockSkewMs ?? 5 * 60 * 1000,
			maxAgeMs: options.maxAgeMs ?? DEFAULT_REPUTATION_FEED_MAX_AGE_MS,
			maxManifestBytes: options.maxManifestBytes ?? 256 * 1024,
			maxPayloadBytes: options.maxPayloadBytes ?? DEFAULT_REPUTATION_FEED_MAX_PAYLOAD_BYTES,
		});
		if (validated.manifest.feed_id !== options.feedId) {
			throw new FeedValidationError("untrusted", "Feed id does not match configured source");
		}
	} catch (error) {
		if (error instanceof FeedValidationError) {
			throw new ReputationFeedUpdateError(error.reason, error.message);
		}
		throw new ReputationFeedUpdateError("io_error", "Feed source fetch failed");
	}

	const root = feedRoot(options.storeDir, options.feedId);
	try {
		return await withUpdateLock(root, () =>
			commitValidatedUpdate({ root, validated, options, now }),
		);
	} catch (error) {
		if (error instanceof FeedValidationError) {
			throw new ReputationFeedUpdateError(error.reason, error.message);
		}
		throw new ReputationFeedUpdateError("io_error", "Feed update could not be committed");
	}
}

export async function rollbackReputationFeed(
	options: ReputationFeedLoadOptions,
): Promise<ReputationFeedSnapshot> {
	const root = feedRoot(options.storeDir, options.feedId);
	try {
		return await withUpdateLock(root, async () => {
			const state = await readStoreState(root);
			if (!state?.previous_version) {
				throw new FeedValidationError("rollback_unavailable", "Feed has no previous version");
			}
			const previous = await readVersion({
				root,
				version: state.previous_version,
				trustedKeys: options.trustedKeys,
				now: options.now ?? new Date(),
				clockSkewMs: options.clockSkewMs ?? 5 * 60 * 1000,
				maxAgeMs: options.maxAgeMs ?? DEFAULT_REPUTATION_FEED_MAX_AGE_MS,
			});
			await atomicJson(join(root, "state.json"), {
				schema_version: REPUTATION_FEED_SCHEMA_VERSION,
				active_version: state.previous_version,
				previous_version: state.active_version,
				highest_sequence: state.highest_sequence,
				generation: state.generation + 1,
				updated_at: (options.now ?? new Date()).toISOString(),
			});
			return previous;
		});
	} catch (error) {
		if (error instanceof FeedValidationError) {
			throw new ReputationFeedUpdateError(error.reason, error.message);
		}
		throw new ReputationFeedUpdateError("io_error", "Feed rollback could not be committed");
	}
}

export function createFileReputationFeedSource(options: {
	directory: string;
	locator?: string;
	expectedPublisher?: string;
	expectedDataset?: string;
	maxManifestBytes?: number;
	maxPayloadBytes?: number;
}): ReputationFeedSource {
	const directory = resolve(options.directory);
	const maxManifestBytes = options.maxManifestBytes ?? 256 * 1024;
	const maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_REPUTATION_FEED_MAX_PAYLOAD_BYTES;
	async function readBounded(path: string, maximum: number): Promise<Uint8Array> {
		const info = await lstat(path);
		if (!info.isFile() || info.size <= 0 || info.size > maximum) {
			throw new Error("Feed source file size is invalid");
		}
		return readFile(path);
	}
	return {
		provenance: {
			transport: "file",
			locator: options.locator ?? directory,
			...(options.expectedPublisher ? { expectedPublisher: options.expectedPublisher } : {}),
			...(options.expectedDataset ? { expectedDataset: options.expectedDataset } : {}),
		},
		async fetch(): Promise<ReputationFeedBundle> {
			const [manifest, signature, payload] = await Promise.all([
				readBounded(join(directory, "manifest.json"), maxManifestBytes),
				readBounded(join(directory, "manifest.sig"), 16_384),
				readBounded(join(directory, "records.json"), maxPayloadBytes),
			]);
			return { manifest, signature: Buffer.from(signature).toString("utf8"), payload };
		},
	};
}
