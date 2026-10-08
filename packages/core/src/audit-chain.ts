/**
 * Tamper-evident verdict log: SHA-256 hash chain + Ed25519 signatures for every
 * record written to `audit.jsonl`.
 *
 * ## Record format
 *
 * A chained record carries one extra top-level field:
 *
 *     "_chain": { "v": 1, "seq": 42, "prev": "<hash of 41>", "hash": "<sha256>",
 *                 "kid": "<epoch key id>", "sig": "<base64 Ed25519>" }
 *
 * `hash` covers the version, the sequence number, the previous hash and the
 * canonical JSON of the record without `_chain`, so editing, deleting, inserting
 * or reordering any record breaks either the hash, the `prev` link or the
 * sequence. `sig` is an Ed25519 signature over `hash`.
 *
 * ## Keys
 *
 * - A long-lived ROOT key. With the default `os-vault` key storage its private
 *   half lives ONLY in the OS credential vault (the store the operator approval
 *   key already uses); `file` storage is an explicit opt-in to an owner-only key
 *   file. The root key never signs records: it certifies epoch keys.
 * - Short-lived EPOCH keys (default 24 h). The private half is an owner-only file
 *   in the AIDR state directory so a hook — a new process per tool call — does
 *   not pay a vault round trip (a PowerShell/`security`/`secret-tool` spawn) per
 *   record. A stolen epoch key can only forge records inside its own window.
 * - `aidr audit rotate-key` replaces the root key; the new root is endorsed by
 *   the old one so a verifier can follow the chain of roots.
 *
 * Every public artefact (`keys.json`, `epochs.jsonl`, `anchors.jsonl`,
 * `head.json`) is signed, so the verifier needs no secret at all.
 *
 * ## What happens on failure
 *
 * The audit write itself is a detection-internal path and fails open (see
 * CLAUDE.md): a record is never dropped because signing is unavailable. It is
 * still chained, but carries `unsigned: "<reason>"` instead of `sig`, and
 * `aidr audit verify` reports it as a failure — an unsigned record is never
 * presented as verified.
 *
 * ## Rotation
 *
 * `audit.jsonl` rotates into numbered backups and the oldest is eventually
 * deleted. Before that file is deleted a signed ROTATION ANCHOR records the last
 * sequence number and hash it held, so the verifier can tell "rotated away by
 * retention" from "deleted by an attacker".
 *
 * Nothing in this module ever writes key material into the log, and string
 * values are passed through the telemetry redaction before they are hashed.
 */

import {
	createHash,
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
	type KeyObject,
	sign,
	verify,
} from "node:crypto";
import { mkdirSync } from "node:fs";
import { open, readFile, rename, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { canonicalJson } from "./canonical-json.js";
import { resolvePath } from "./config.js";
import { resolveSecretStore, type SecretStore } from "./secret-store.js";
import { redactTelemetryString } from "./telemetry-redaction.js";

const AUDIT_CHAIN_VERSION = 1;
export const AUDIT_CHAIN_GENESIS = "GENESIS";
/** Overrides `audit.key_storage`: `os-vault` or `file`. */
export const AUDIT_CHAIN_KEY_STORAGE_ENV = "AIDR_AUDIT_CHAIN_KEY_STORAGE";
/** Vault id prefix of a root key; the key id follows. */
export const AUDIT_CHAIN_ROOT_VAULT_PREFIX = "aidr-audit-chain-root-";

const CHAIN_DIR = "audit-chain";
const KEYS_FILE = "keys.json";
const EPOCHS_FILE = "epochs.jsonl";
const ANCHORS_FILE = "anchors.jsonl";
const HEAD_FILE = "head.json";
const EPOCH_KEY_FILE = "epoch-key.json";
const LOCK_FILE = "chain.lock";

const RECORD_DOMAIN = "aidr-audit-record-v1";
const EPOCH_DOMAIN = "aidr-audit-epoch-v1";
const HEAD_DOMAIN = "aidr-audit-head-v1";
const ANCHOR_DOMAIN = "aidr-audit-anchor-v1";
const ROOT_DOMAIN = "aidr-audit-root-v1";

/** How long a writer waits for the cross-process chain lock before writing unsigned. */
const LOCK_WAIT_MS = 1_500;
/** A lock older than this belongs to a crashed writer. */
const LOCK_STALE_MS = 30_000;
/** After a vault failure, do not retry the (slow) vault for this long in one process. */
const VAULT_RETRY_MS = 5 * 60_000;
/** Renew an epoch key this long before it expires so a record never straddles expiry. */
const EPOCH_RENEW_MARGIN_MS = 5 * 60_000;
/** Accepted clock skew between a record and its epoch window. */
const EPOCH_SKEW_MS = 5 * 60_000;

export type AuditChainKeyStorage = "os-vault" | "file";

export interface AuditChainSettings {
	keyStorage?: AuditChainKeyStorage;
	epochHours?: number;
}

/** The `_chain` field of a record. Exactly one of `sig` / `unsigned` is present. */
export interface AuditChainField {
	v: number;
	seq: number;
	prev: string;
	hash: string;
	kid?: string;
	sig?: string;
	/** Why the record could not be signed. The verifier reports it as a failure. */
	unsigned?: string;
}

interface RootKeyRecord {
	kid: string;
	/** base64 DER (SPKI) public key. */
	public_key: string;
	created_at: string;
	retired_at?: string;
	storage: AuditChainKeyStorage;
	/** Previous root that endorsed this one, and its signature. */
	endorsed_by?: string;
	endorsement?: string;
}

interface KeysDocument {
	version: 1;
	roots: RootKeyRecord[];
}

interface EpochCert {
	v: 1;
	kid: string;
	root_kid: string;
	public_key: string;
	not_before: string;
	not_after: string;
	sig: string;
}

interface EpochKeyFile {
	v: 1;
	kid: string;
	root_kid: string;
	private_key: string;
	not_after: string;
}

interface ChainHead {
	v: 1;
	seq: number;
	hash: string;
	at: string;
	kid?: string;
	sig?: string;
	unsigned?: string;
}

interface RotationAnchor {
	v: 1;
	type: "rotation_drop";
	at: string;
	last_seq: number;
	last_hash: string;
	kid?: string;
	sig?: string;
	unsigned?: string;
}

// ── Test seams ─────────────────────────────────────────────────────

let vaultOverride: (() => SecretStore) | null = null;
let clock: () => number = Date.now;

/**
 * Tests only: supply the vault (the suite never touches a real OS vault) and the
 * clock. Pass `null` to restore the defaults.
 */
export function setAuditChainTestHooks(
	hooks: { vault?: (() => SecretStore) | null; now?: (() => number) | null } | null,
): void {
	vaultOverride = hooks?.vault ?? null;
	clock = hooks?.now ?? Date.now;
	resetAuditChainCache();
}

// ── Small helpers ──────────────────────────────────────────────────

/** Directory holding the chain state for the log at `auditPath`. */
export function auditChainDir(auditPath: string): string {
	return join(dirname(resolvePath(auditPath)), CHAIN_DIR);
}

function sha256Hex(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

function keyIdFor(publicKeyDerB64: string): string {
	return createHash("sha256")
		.update(Buffer.from(publicKeyDerB64, "base64"))
		.digest("hex")
		.slice(0, 16);
}

/** `SHA256:<hex>` fingerprint of a root, for pinning with `--expect-root`. */
export function rootFingerprint(publicKeyDerB64: string): string {
	return `SHA256:${createHash("sha256").update(Buffer.from(publicKeyDerB64, "base64")).digest("hex")}`;
}

function publicKeyB64(key: KeyObject): string {
	return key.export({ type: "spki", format: "der" }).toString("base64");
}

function publicKeyFromB64(value: string): KeyObject {
	return createPublicKey({ key: Buffer.from(value, "base64"), format: "der", type: "spki" });
}

function signText(domain: string, text: string, key: KeyObject): string {
	return sign(null, Buffer.from(`${domain}\n${text}`, "utf8"), key).toString("base64");
}

function verifyText(domain: string, text: string, key: KeyObject, signature: string): boolean {
	try {
		return verify(
			null,
			Buffer.from(`${domain}\n${text}`, "utf8"),
			key,
			Buffer.from(signature, "base64"),
		);
	} catch {
		return false;
	}
}

function errorCode(error: unknown): string | undefined {
	return (error as NodeJS.ErrnoException | undefined)?.code;
}

async function readTextIfPresent(path: string): Promise<string | null> {
	try {
		return await readFile(path, "utf8");
	} catch (error) {
		if (errorCode(error) === "ENOENT") return null;
		throw error;
	}
}

async function readJsonIfPresent<T>(path: string): Promise<T | null> {
	const text = await readTextIfPresent(path);
	if (text === null) return null;
	try {
		return JSON.parse(text) as T;
	} catch {
		return null;
	}
}

function parseJsonLines<T>(text: string | null): T[] {
	if (!text) return [];
	const out: T[] = [];
	for (const line of text.split("\n")) {
		if (!line.trim()) continue;
		try {
			out.push(JSON.parse(line) as T);
		} catch {
			// Reported by the verifier through the signature checks of what remains.
		}
	}
	return out;
}

/** Owner-only atomic replace. The directory inherits the audit directory's private ACL. */
async function writePrivateAtomic(path: string, content: string): Promise<void> {
	const tmp = `${path}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`;
	const handle = await open(tmp, "wx", 0o600);
	try {
		await handle.writeFile(content, "utf8");
	} finally {
		await handle.close();
	}
	for (let attempt = 0; ; attempt++) {
		try {
			await rename(tmp, path);
			return;
		} catch (error) {
			// Windows refuses to replace a file another process has open for a moment
			// (a verifier reading the head); retry briefly before giving up.
			const code = errorCode(error);
			if ((code === "EPERM" || code === "EBUSY" || code === "EACCES") && attempt < 5) {
				await delay(5 * (attempt + 1));
				continue;
			}
			await unlink(tmp).catch(() => undefined);
			throw error;
		}
	}
}

async function appendPrivate(path: string, line: string): Promise<void> {
	const handle = await open(path, "a", 0o600);
	try {
		await handle.writeFile(line, "utf8");
	} finally {
		await handle.close();
	}
}

function ensureChainDir(dir: string): void {
	mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/**
 * Credential-shaped string values are redacted (the shared telemetry redaction)
 * before a record is hashed; keys and non-string values are untouched, so the
 * record's structure is exactly what an unchained log would hold.
 */
function redactAuditRecordStrings(value: unknown, depth = 0): unknown {
	if (typeof value === "string") return redactTelemetryString(value, Number.MAX_SAFE_INTEGER);
	if (value === null || typeof value !== "object" || depth > 16) return value;
	if (Array.isArray(value)) return value.map((item) => redactAuditRecordStrings(item, depth + 1));
	const out: Record<string, unknown> = {};
	for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
		out[key] = redactAuditRecordStrings(item, depth + 1);
	}
	return out;
}

/** The hash a record must carry: version, position, link and canonical body. */
function auditRecordHash(seq: number, prev: string, body: Record<string, unknown>): string {
	return sha256Hex(
		`${RECORD_DOMAIN}\n${AUDIT_CHAIN_VERSION}\n${seq}\n${prev}\n${canonicalJson(body)}`,
	);
}

// ── Key storage ────────────────────────────────────────────────────

export function resolveAuditChainKeyStorage(
	configured: AuditChainKeyStorage | undefined,
	env: NodeJS.ProcessEnv = process.env,
): AuditChainKeyStorage {
	const fromEnv = env[AUDIT_CHAIN_KEY_STORAGE_ENV]?.trim().toLowerCase();
	if (fromEnv === "file") return "file";
	if (fromEnv === "os-vault") return "os-vault";
	// Anything but an explicit `file` is the vault: the weaker storage is never a default.
	return configured === "file" ? "file" : "os-vault";
}

function vault(): SecretStore {
	const store = vaultOverride ? vaultOverride() : resolveSecretStore();
	if (!store.osProtected) {
		throw new Error(`the selected secret store (${store.kind}) is not an OS credential vault`);
	}
	return store;
}

function rootFilePath(dir: string, kid: string): string {
	return join(dir, `root-${kid}.key`);
}

async function storeRootPrivate(
	dir: string,
	storage: AuditChainKeyStorage,
	kid: string,
	pem: string,
): Promise<void> {
	if (storage === "file") {
		await writePrivateAtomic(rootFilePath(dir, kid), pem);
		return;
	}
	vault().put(`${AUDIT_CHAIN_ROOT_VAULT_PREFIX}${kid}`, pem);
}

async function loadRootPrivate(
	dir: string,
	storage: AuditChainKeyStorage,
	kid: string,
): Promise<KeyObject | null> {
	const pem =
		storage === "file"
			? await readTextIfPresent(rootFilePath(dir, kid))
			: vault().get(`${AUDIT_CHAIN_ROOT_VAULT_PREFIX}${kid}`);
	if (!pem) return null;
	return createPrivateKey(pem);
}

async function revokeRootPrivate(
	dir: string,
	storage: AuditChainKeyStorage,
	kid: string,
): Promise<void> {
	if (storage === "file") {
		await unlink(rootFilePath(dir, kid)).catch(() => undefined);
		return;
	}
	vault().revoke(`${AUDIT_CHAIN_ROOT_VAULT_PREFIX}${kid}`);
}

async function readKeys(dir: string): Promise<KeysDocument> {
	const doc = await readJsonIfPresent<KeysDocument>(join(dir, KEYS_FILE));
	if (!doc || doc.version !== 1 || !Array.isArray(doc.roots)) return { version: 1, roots: [] };
	return doc;
}

function activeRoot(doc: KeysDocument): RootKeyRecord | undefined {
	return [...doc.roots].reverse().find((root) => !root.retired_at);
}

function rootEndorsementText(
	root: Pick<RootKeyRecord, "kid" | "public_key" | "created_at">,
): string {
	return canonicalJson({ kid: root.kid, public_key: root.public_key, created_at: root.created_at });
}

function epochCertText(cert: Omit<EpochCert, "sig">): string {
	return canonicalJson(cert);
}

/** Create the first root key. Caller holds the provisioning section. */
async function createRoot(
	dir: string,
	storage: AuditChainKeyStorage,
	previous?: { record: RootKeyRecord; key: KeyObject | null },
): Promise<{ record: RootKeyRecord; key: KeyObject }> {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const pub = publicKeyB64(publicKey);
	const kid = keyIdFor(pub);
	const record: RootKeyRecord = {
		kid,
		public_key: pub,
		created_at: new Date(clock()).toISOString(),
		storage,
	};
	if (previous?.key) {
		record.endorsed_by = previous.record.kid;
		record.endorsement = signText(ROOT_DOMAIN, rootEndorsementText(record), previous.key);
	}
	await storeRootPrivate(
		dir,
		storage,
		kid,
		privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
	);
	return { record, key: privateKey };
}

// ── Epoch signer (per process cache) ───────────────────────────────

interface EpochSigner {
	kid: string;
	rootKid: string;
	key: KeyObject;
	notAfter: number;
}

const signerCache = new Map<string, EpochSigner>();
const vaultFailures = new Map<string, { at: number; reason: string }>();

/** Drop the per-process key cache (after a rotation, and in tests). */
export function resetAuditChainCache(): void {
	signerCache.clear();
	vaultFailures.clear();
}

async function readEpochKeyFile(dir: string): Promise<EpochSigner | null> {
	const file = await readJsonIfPresent<EpochKeyFile>(join(dir, EPOCH_KEY_FILE));
	if (!file || file.v !== 1 || typeof file.private_key !== "string") return null;
	try {
		return {
			kid: file.kid,
			rootKid: file.root_kid,
			key: createPrivateKey(file.private_key),
			notAfter: Date.parse(file.not_after),
		};
	} catch {
		return null;
	}
}

function usable(signer: EpochSigner | null | undefined, rootKid: string | undefined): boolean {
	return (
		!!signer &&
		Number.isFinite(signer.notAfter) &&
		signer.notAfter - EPOCH_RENEW_MARGIN_MS > clock() &&
		(rootKid === undefined || signer.rootKid === rootKid)
	);
}

/**
 * Issue a new epoch key certified by the active root (creating the root on first
 * use). This is the only path that touches the vault, once per epoch.
 */
async function issueEpoch(
	dir: string,
	settings: Required<AuditChainSettings>,
): Promise<EpochSigner> {
	const keys = await readKeys(dir);
	let root = activeRoot(keys);
	let rootKey: KeyObject | null = null;
	if (root) {
		rootKey = await loadRootPrivate(dir, root.storage, root.kid);
		if (!rootKey) throw new Error("the audit chain root key is missing from its key storage");
	} else {
		const created = await createRoot(dir, settings.keyStorage);
		root = created.record;
		rootKey = created.key;
		keys.roots.push(root);
		await writePrivateAtomic(join(dir, KEYS_FILE), `${JSON.stringify(keys, null, 2)}\n`);
	}

	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const pub = publicKeyB64(publicKey);
	const now = clock();
	const unsignedCert: Omit<EpochCert, "sig"> = {
		v: 1,
		kid: keyIdFor(pub),
		root_kid: root.kid,
		public_key: pub,
		not_before: new Date(now).toISOString(),
		not_after: new Date(now + settings.epochHours * 3_600_000).toISOString(),
	};
	const cert: EpochCert = {
		...unsignedCert,
		sig: signText(EPOCH_DOMAIN, epochCertText(unsignedCert), rootKey),
	};
	// Certificate first: a key whose certificate is missing would sign records the
	// verifier rejects.
	await appendPrivate(join(dir, EPOCHS_FILE), `${JSON.stringify(cert)}\n`);
	const keyFile: EpochKeyFile = {
		v: 1,
		kid: cert.kid,
		root_kid: root.kid,
		private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		not_after: cert.not_after,
	};
	await writePrivateAtomic(join(dir, EPOCH_KEY_FILE), `${JSON.stringify(keyFile)}\n`);
	return {
		kid: cert.kid,
		rootKid: root.kid,
		key: privateKey,
		notAfter: Date.parse(cert.not_after),
	};
}

/** The signer for this process, or a reason why there is none. Never throws. */
async function epochSigner(
	dir: string,
	settings: Required<AuditChainSettings>,
): Promise<EpochSigner | { unavailable: string }> {
	const cached = signerCache.get(dir);
	if (usable(cached, undefined)) return cached as EpochSigner;
	try {
		ensureChainDir(dir);
		const onDisk = await readEpochKeyFile(dir);
		const keys = await readKeys(dir);
		const root = activeRoot(keys);
		if (root && usable(onDisk, root.kid)) {
			signerCache.set(dir, onDisk as EpochSigner);
			return onDisk as EpochSigner;
		}
		const failure = vaultFailures.get(dir);
		if (failure && clock() - failure.at < VAULT_RETRY_MS) return { unavailable: failure.reason };
		const issued = await issueEpoch(dir, settings);
		signerCache.set(dir, issued);
		return issued;
	} catch (error) {
		const reason = `signing_key_unavailable: ${error instanceof Error ? error.message : String(error)}`;
		vaultFailures.set(dir, { at: clock(), reason });
		return { unavailable: reason };
	}
}

// ── Cross-process lock ─────────────────────────────────────────────

async function acquireLock(dir: string): Promise<(() => Promise<void>) | null> {
	const path = join(dir, LOCK_FILE);
	const deadline = clock() + LOCK_WAIT_MS;
	for (;;) {
		try {
			const handle = await open(path, "wx", 0o600);
			try {
				await handle.writeFile(`${process.pid} ${Date.now()}\n`, "utf8");
			} finally {
				await handle.close();
			}
			return async () => {
				await unlink(path).catch(() => undefined);
			};
		} catch (error) {
			if (errorCode(error) !== "EEXIST") throw error;
			const info = await stat(path).catch(() => null);
			if (info && Date.now() - info.mtimeMs > LOCK_STALE_MS) {
				// A crashed writer's lock. Removing it can race another remover, which
				// at worst costs one extra wait; it never lets two writers hold it
				// because `wx` stays the only way in.
				await unlink(path).catch(() => undefined);
				continue;
			}
			if (clock() > deadline) return null;
			await delay(3 + Math.floor(Math.random() * 7));
		}
	}
}

// ── Writing ────────────────────────────────────────────────────────

async function readHead(dir: string): Promise<ChainHead | null> {
	const head = await readJsonIfPresent<ChainHead>(join(dir, HEAD_FILE));
	if (!head || head.v !== 1 || !Number.isSafeInteger(head.seq) || typeof head.hash !== "string") {
		return null;
	}
	return head;
}

function headText(head: Pick<ChainHead, "v" | "seq" | "hash" | "at" | "kid">): string {
	return canonicalJson({
		v: head.v,
		seq: head.seq,
		hash: head.hash,
		at: head.at,
		kid: head.kid ?? null,
	});
}

function anchorText(anchor: Omit<RotationAnchor, "sig" | "unsigned">): string {
	return canonicalJson({ ...anchor, kid: anchor.kid ?? null });
}

/** Last `_chain` of a log file (the file about to be deleted by rotation). */
async function lastChainOf(path: string): Promise<AuditChainField | null> {
	const text = await readTextIfPresent(path);
	if (!text) return null;
	const lines = text.split("\n");
	for (let i = lines.length - 1; i >= 0; i--) {
		const line = lines[i]?.trim();
		if (!line) continue;
		try {
			const parsed = JSON.parse(line) as { _chain?: AuditChainField };
			if (parsed._chain && Number.isSafeInteger(parsed._chain.seq)) return parsed._chain;
		} catch {
			// keep looking backwards
		}
	}
	return null;
}

export interface ChainedAppendIo {
	/** Rotate the active log; call `beforeDrop(path)` before deleting the oldest backup. */
	rotate(beforeDrop: (path: string) => Promise<void>): Promise<void>;
	/** Append one complete line (with trailing newline) durably. */
	write(line: string): Promise<void>;
}

/**
 * Seal `entry` into the chain and append it, under the cross-process chain lock.
 *
 * Never throws for a signing problem: the record is written chained-but-unsigned
 * with the reason. It throws only when the underlying write fails, exactly like
 * an unchained append.
 */
export async function appendChainedAuditRecord(
	auditPath: string,
	entry: Record<string, unknown>,
	settings: AuditChainSettings,
	io: ChainedAppendIo,
): Promise<AuditChainField> {
	const dir = auditChainDir(auditPath);
	ensureChainDir(dir);
	const effective: Required<AuditChainSettings> = {
		keyStorage: resolveAuditChainKeyStorage(settings.keyStorage),
		epochHours: settings.epochHours ?? 24,
	};
	// Provision outside the lock: the first record of an epoch may need the vault,
	// and other writers must not wait on it.
	const signer = await epochSigner(dir, effective);

	const release = await acquireLock(dir);
	try {
		const head = await readHead(dir);
		const signerKid = "unavailable" in signer ? undefined : signer.kid;

		// Without the lock another writer may be mid-rotation; rotating again would
		// shift its files under it, so the log is allowed to grow one record instead.
		if (release)
			await io.rotate(async (droppedPath) => {
				const last = await lastChainOf(droppedPath);
				if (!last) return;
				const base: Omit<RotationAnchor, "sig" | "unsigned"> = {
					v: 1,
					type: "rotation_drop",
					at: new Date(clock()).toISOString(),
					last_seq: last.seq,
					last_hash: last.hash,
					kid: signerKid,
				};
				const anchor: RotationAnchor =
					"unavailable" in signer
						? { ...base, unsigned: signer.unavailable }
						: { ...base, sig: signText(ANCHOR_DOMAIN, anchorText(base), signer.key) };
				await appendPrivate(join(dir, ANCHORS_FILE), `${JSON.stringify(anchor)}\n`);
			});

		const body = redactAuditRecordStrings(
			JSON.parse(JSON.stringify(entry, (key, value) => (key === "_chain" ? undefined : value))),
		) as Record<string, unknown>;
		const seq = (head?.seq ?? 0) + 1;
		const prev = head?.hash ?? AUDIT_CHAIN_GENESIS;
		const hash = auditRecordHash(seq, prev, body);
		let chain: AuditChainField;
		if (!release) {
			// Another writer held the lock too long. Write the record anyway (fail-open
			// audit), flagged so the verifier reports the gap instead of trusting it.
			chain = { v: AUDIT_CHAIN_VERSION, seq, prev, hash, unsigned: "chain_lock_timeout" };
		} else if ("unavailable" in signer) {
			chain = { v: AUDIT_CHAIN_VERSION, seq, prev, hash, unsigned: signer.unavailable };
		} else {
			chain = {
				v: AUDIT_CHAIN_VERSION,
				seq,
				prev,
				hash,
				kid: signer.kid,
				sig: signText(RECORD_DOMAIN, hash, signer.key),
			};
		}
		await io.write(`${JSON.stringify({ ...body, _chain: chain })}\n`);

		if (release) {
			const at = new Date(clock()).toISOString();
			const newHead: ChainHead = { v: 1, seq, hash, at, kid: chain.kid };
			if (chain.sig && !("unavailable" in signer)) {
				newHead.sig = signText(HEAD_DOMAIN, headText(newHead), signer.key);
			} else {
				newHead.unsigned = chain.unsigned ?? "unsigned";
			}
			await writePrivateAtomic(join(dir, HEAD_FILE), `${JSON.stringify(newHead)}\n`);
		}
		return chain;
	} finally {
		await release?.();
	}
}

// ── Rotation of the root key ───────────────────────────────────────

export interface AuditKeyRotationResult {
	previousRootKid: string | null;
	rootKid: string;
	fingerprint: string;
	storage: AuditChainKeyStorage;
	/** False when the previous root could not be read, so the new root is unendorsed. */
	endorsed: boolean;
}

/**
 * Replace the root key (operator action, `aidr audit rotate-key`). The new root is
 * endorsed by the old one when it can be read, the old private key is revoked
 * from its storage, and the next record starts a fresh epoch under the new root.
 */
export async function rotateAuditChainRootKey(
	auditPath: string,
	settings: AuditChainSettings = {},
): Promise<AuditKeyRotationResult> {
	const dir = auditChainDir(auditPath);
	ensureChainDir(dir);
	const storage = resolveAuditChainKeyStorage(settings.keyStorage);
	const release = await acquireLock(dir);
	if (!release) throw new Error("the audit chain is busy; try again");
	try {
		const keys = await readKeys(dir);
		const previous = activeRoot(keys);
		let previousKey: KeyObject | null = null;
		if (previous) {
			previousKey = await loadRootPrivate(dir, previous.storage, previous.kid).catch(() => null);
		}
		const created = await createRoot(
			dir,
			storage,
			previous ? { record: previous, key: previousKey } : undefined,
		);
		const retiredAt = new Date(clock()).toISOString();
		const roots = keys.roots.map((root) =>
			root.kid === previous?.kid ? { ...root, retired_at: retiredAt } : root,
		);
		roots.push(created.record);
		await writePrivateAtomic(
			join(dir, KEYS_FILE),
			`${JSON.stringify({ version: 1, roots }, null, 2)}\n`,
		);
		// The current epoch key was certified by the old root: retire it now.
		await unlink(join(dir, EPOCH_KEY_FILE)).catch(() => undefined);
		if (previous)
			await revokeRootPrivate(dir, previous.storage, previous.kid).catch(() => undefined);
		resetAuditChainCache();
		return {
			previousRootKid: previous?.kid ?? null,
			rootKid: created.record.kid,
			fingerprint: rootFingerprint(created.record.public_key),
			storage,
			endorsed: !previous || !!created.record.endorsement,
		};
	} finally {
		await release();
	}
}

// ── Verification ───────────────────────────────────────────────────

export type AuditChainProblemKind =
	| "malformed_record"
	| "unchained_record"
	| "unsigned_record"
	| "hash_mismatch"
	| "bad_signature"
	| "unknown_key"
	| "outside_epoch"
	| "broken_link"
	| "missing_records"
	| "reordered_record"
	| "missing_head_records"
	| "tail_truncated"
	| "head_mismatch"
	| "head_missing"
	| "bad_head_signature"
	| "bad_anchor"
	| "bad_epoch_certificate"
	| "bad_root_endorsement"
	| "untrusted_root";

export interface AuditChainProblem {
	kind: AuditChainProblemKind;
	/** Log file and 1-based line, when the problem is a record. */
	file?: string;
	line?: number;
	seq?: number;
	detail: string;
}

export interface AuditChainVerification {
	ok: boolean;
	/** Chained records whose hash, link and signature all verified. */
	verified: number;
	/** Records written before the chain was enabled (no `_chain` before the first chained one). */
	legacyUnchained: number;
	firstSeq: number | null;
	lastSeq: number | null;
	roots: Array<{ kid: string; fingerprint: string; retired: boolean }>;
	problems: AuditChainProblem[];
	/** True when there is no chain state at all (signing was never enabled). */
	noChain: boolean;
}

const MAX_PROBLEMS = 100;

interface EpochInfo {
	key: KeyObject;
	notBefore: number;
	notAfter: number;
}

/**
 * Verify the chain across the active log and its rotated backups (oldest first).
 * Needs no secret. `expectRoot` pins the first root's fingerprint.
 */
export async function verifyAuditChain(
	auditPath: string,
	files: string[],
	options: { expectRoot?: string } = {},
): Promise<AuditChainVerification> {
	const dir = auditChainDir(auditPath);
	const problems: AuditChainProblem[] = [];
	const report = (problem: AuditChainProblem) => {
		if (problems.length < MAX_PROBLEMS) problems.push(problem);
	};

	// Roots: each later root must be endorsed by the root before it.
	const keys = await readKeys(dir);
	const roots = new Map<string, KeyObject>();
	for (const [index, root] of keys.roots.entries()) {
		let key: KeyObject;
		try {
			key = publicKeyFromB64(root.public_key);
			if (keyIdFor(root.public_key) !== root.kid) throw new Error("kid mismatch");
		} catch {
			report({
				kind: "bad_root_endorsement",
				detail: `root ${root.kid} has an invalid public key`,
			});
			continue;
		}
		if (index > 0) {
			const endorser = root.endorsed_by ? roots.get(root.endorsed_by) : undefined;
			if (
				!endorser ||
				!root.endorsement ||
				!verifyText(ROOT_DOMAIN, rootEndorsementText(root), endorser, root.endorsement)
			) {
				report({
					kind: "bad_root_endorsement",
					detail: `root ${root.kid} is not endorsed by the root before it`,
				});
				continue;
			}
		}
		roots.set(root.kid, key);
	}
	const firstRoot = keys.roots[0];
	if (
		options.expectRoot &&
		(!firstRoot || rootFingerprint(firstRoot.public_key) !== options.expectRoot)
	) {
		report({
			kind: "untrusted_root",
			detail: `the first root key does not match the expected fingerprint ${options.expectRoot}`,
		});
	}

	// Epoch certificates.
	const epochs = new Map<string, EpochInfo>();
	for (const cert of parseJsonLines<EpochCert>(await readTextIfPresent(join(dir, EPOCHS_FILE)))) {
		const rootKey = roots.get(cert.root_kid);
		const { sig, ...unsignedCert } = cert;
		if (
			!rootKey ||
			typeof sig !== "string" ||
			!verifyText(EPOCH_DOMAIN, epochCertText(unsignedCert), rootKey, sig)
		) {
			report({
				kind: "bad_epoch_certificate",
				detail: `epoch key ${cert.kid} is not certified by a known root`,
			});
			continue;
		}
		try {
			epochs.set(cert.kid, {
				key: publicKeyFromB64(cert.public_key),
				notBefore: Date.parse(cert.not_before),
				notAfter: Date.parse(cert.not_after),
			});
		} catch {
			report({ kind: "bad_epoch_certificate", detail: `epoch key ${cert.kid} is malformed` });
		}
	}

	const checkSignature = (
		domain: string,
		text: string,
		kid: string | undefined,
		sig: string | undefined,
		at: number,
	): AuditChainProblemKind | null => {
		const epoch = kid ? epochs.get(kid) : undefined;
		if (!epoch) return "unknown_key";
		if (!sig || !verifyText(domain, text, epoch.key, sig)) return "bad_signature";
		if (
			Number.isFinite(at) &&
			(at < epoch.notBefore - EPOCH_SKEW_MS || at > epoch.notAfter + EPOCH_SKEW_MS)
		) {
			return "outside_epoch";
		}
		return null;
	};

	// Rotation anchors: the newest one says where the oldest surviving record starts.
	let anchor: RotationAnchor | null = null;
	for (const candidate of parseJsonLines<RotationAnchor>(
		await readTextIfPresent(join(dir, ANCHORS_FILE)),
	)) {
		const { sig, unsigned, ...base } = candidate;
		const problem = unsigned
			? "unsigned_record"
			: checkSignature(
					ANCHOR_DOMAIN,
					anchorText(base),
					candidate.kid,
					sig,
					Date.parse(candidate.at),
				);
		if (problem) {
			report({
				kind: "bad_anchor",
				detail: `rotation anchor for seq ${candidate.last_seq} does not verify (${unsigned ?? problem})`,
			});
			continue;
		}
		if (!anchor || candidate.last_seq > anchor.last_seq) anchor = candidate;
	}

	let verified = 0;
	let legacyUnchained = 0;
	let firstSeq: number | null = null;
	let lastSeq: number | null = null;
	let lastHash: string | null = null;
	let seenChain = false;

	for (const file of files) {
		const text = await readTextIfPresent(file);
		if (text === null) continue;
		const lines = text.split("\n");
		for (const [index, raw] of lines.entries()) {
			if (!raw.trim()) continue;
			const at = { file, line: index + 1 };
			let parsed: Record<string, unknown>;
			try {
				const value: unknown = JSON.parse(raw);
				if (!value || typeof value !== "object" || Array.isArray(value))
					throw new Error("not an object");
				parsed = value as Record<string, unknown>;
			} catch {
				report({ ...at, kind: "malformed_record", detail: "the line is not a JSON record" });
				continue;
			}
			const chain = parsed._chain as AuditChainField | undefined;
			if (!chain || typeof chain !== "object" || !Number.isSafeInteger(chain.seq)) {
				if (seenChain) {
					report({
						...at,
						kind: "unchained_record",
						detail: "a record after the chain started has no _chain field",
					});
				} else {
					legacyUnchained++;
				}
				continue;
			}
			const { _chain: _omit, ...body } = parsed;

			if (!seenChain) {
				seenChain = true;
				const expectedSeq = anchor ? anchor.last_seq + 1 : 1;
				const expectedPrev = anchor ? anchor.last_hash : AUDIT_CHAIN_GENESIS;
				if (chain.seq !== expectedSeq || chain.prev !== expectedPrev) {
					report({
						...at,
						seq: chain.seq,
						kind: "missing_head_records",
						detail: anchor
							? `the oldest surviving record should be seq ${expectedSeq} (after the rotation anchor), found seq ${chain.seq}`
							: `the chain should start at seq 1 from GENESIS, found seq ${chain.seq}; earlier records are missing`,
					});
				}
				firstSeq = chain.seq;
			} else if (lastSeq !== null) {
				if (chain.seq <= lastSeq) {
					report({
						...at,
						seq: chain.seq,
						kind: "reordered_record",
						detail: `seq ${chain.seq} follows seq ${lastSeq}: the record is duplicated or out of order`,
					});
				} else if (chain.seq > lastSeq + 1) {
					report({
						...at,
						seq: chain.seq,
						kind: "missing_records",
						detail: `seq ${lastSeq + 1}..${chain.seq - 1} are missing before this record`,
					});
				} else if (chain.prev !== lastHash) {
					report({
						...at,
						seq: chain.seq,
						kind: "broken_link",
						detail: `the record does not link to the hash of seq ${lastSeq}`,
					});
				}
			}

			let hash: string;
			try {
				hash = auditRecordHash(chain.seq, String(chain.prev), body);
			} catch {
				hash = "";
			}
			let recordOk = true;
			if (hash !== chain.hash) {
				report({
					...at,
					seq: chain.seq,
					kind: "hash_mismatch",
					detail: "the record was modified after it was written",
				});
				recordOk = false;
			} else if (chain.unsigned) {
				report({
					...at,
					seq: chain.seq,
					kind: "unsigned_record",
					detail: `the record was written without a signature (${chain.unsigned})`,
				});
				recordOk = false;
			} else {
				const timestamp =
					typeof body.timestamp === "string" ? Date.parse(body.timestamp) : Number.NaN;
				const problem = checkSignature(RECORD_DOMAIN, chain.hash, chain.kid, chain.sig, timestamp);
				if (problem) {
					report({
						...at,
						seq: chain.seq,
						kind: problem,
						detail:
							problem === "unknown_key"
								? `signed by key ${chain.kid ?? "(none)"}, which no root certifies`
								: problem === "outside_epoch"
									? "the record's timestamp is outside its signing key's window"
									: "the signature does not verify",
					});
					recordOk = false;
				}
			}
			if (recordOk) verified++;
			// Advance on the record's own claims so one bad record yields one problem,
			// not a cascade over every later record.
			if (lastSeq === null || chain.seq > lastSeq) {
				lastSeq = chain.seq;
				lastHash = chain.hash;
			}
		}
	}

	// Tail: the signed head says what the newest record must be.
	const head = await readHead(dir);
	const hasChainState = keys.roots.length > 0 || epochs.size > 0;
	if (!head) {
		if (seenChain || hasChainState) {
			report({
				kind: "head_missing",
				detail: "the signed chain head is missing; the tail of the log cannot be checked",
			});
		}
	} else {
		const problem = head.unsigned
			? null
			: checkSignature(HEAD_DOMAIN, headText(head), head.kid, head.sig, Date.parse(head.at));
		if (problem) {
			report({ kind: "bad_head_signature", detail: `the chain head does not verify (${problem})` });
		} else if (head.unsigned) {
			report({
				kind: "unsigned_record",
				seq: head.seq,
				detail: `the chain head was written without a signature (${head.unsigned})`,
			});
		}
		if (lastSeq === null || head.seq > lastSeq) {
			report({
				kind: "tail_truncated",
				seq: lastSeq === null ? undefined : lastSeq + 1,
				detail: `the head records seq ${head.seq} but the newest record in the log is ${lastSeq ?? "absent"}: records were removed from the end`,
			});
		} else if (head.seq < lastSeq) {
			report({
				kind: "head_mismatch",
				seq: head.seq,
				detail: `records after the signed head (seq ${head.seq}) were appended without updating it`,
			});
		} else if (head.hash !== lastHash) {
			report({
				kind: "head_mismatch",
				seq: head.seq,
				detail: "the newest record does not match the signed head",
			});
		}
	}

	return {
		ok: problems.length === 0,
		verified,
		legacyUnchained,
		firstSeq,
		lastSeq,
		roots: keys.roots.map((root) => ({
			kid: root.kid,
			fingerprint: rootFingerprint(root.public_key),
			retired: !!root.retired_at,
		})),
		problems,
		noChain: !seenChain && !hasChainState && !head,
	};
}
