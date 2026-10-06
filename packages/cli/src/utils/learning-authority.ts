import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { link, lstat, open, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import {
	createSecretReferenceId,
	type PlatformSecretStoreKind,
	preparePrivateLocalDirectory,
	preparePrivateLocalFile,
	resolvePath,
	resolveSecretStore,
	type SecretStore,
	windowsTargetsAreAlreadyPrivate,
} from "@singularityrd/aidr-core";

export type LearningAuthorityRole = "execution" | "approval";
export interface LearningAuthorityReference {
	schema_version: 1;
	role: LearningAuthorityRole;
	key_id: string;
	public_key_pem: string;
	created_at: string;
	private: { store: PlatformSecretStoreKind; id: string } | { store: "file-acl"; path: string };
}

const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const VAULTS: readonly string[] = ["windows-dpapi", "macos-keychain", "linux-secret-service"];

function sameFile(a: Stats, b: Stats): boolean {
	return a.dev === b.dev && a.ino === b.ino;
}

function assertRegularFile(info: Stats, privateFile = false): void {
	if (
		!info.isFile() ||
		info.isSymbolicLink() ||
		info.nlink !== 1 ||
		(typeof process.getuid === "function" && info.uid !== process.getuid()) ||
		(privateFile && process.platform !== "win32" && (info.mode & 0o077) !== 0)
	) {
		throw new Error("Unsafe authority file.");
	}
}

async function readBoundedFile(path: string, max: number, privateFile = false): Promise<string> {
	if (!Number.isSafeInteger(max) || max < 1) throw new Error("Invalid file limit.");
	const checkPrivateAcl = (): void => {
		if (
			privateFile &&
			process.platform === "win32" &&
			!windowsTargetsAreAlreadyPrivate([
				{ path: dirname(path), directory: true },
				{ path, directory: false },
			])
		)
			throw new Error("Private file ACL could not be verified.");
	};
	checkPrivateAcl();
	const before = await lstat(path);
	assertRegularFile(before, privateFile);
	const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | NO_FOLLOW);
	try {
		const opened = await handle.stat();
		assertRegularFile(opened, privateFile);
		if (!sameFile(before, opened) || opened.size > max) throw new Error("Unsafe authority file.");
		const bytes = Buffer.alloc(max + 1);
		let size = 0;
		while (size < bytes.length) {
			const chunk = await handle.read(bytes, size, bytes.length - size, null);
			if (!chunk.bytesRead) break;
			size += chunk.bytesRead;
		}
		const after = await lstat(path);
		assertRegularFile(after, privateFile);
		if (size > max || !sameFile(opened, after)) throw new Error("Unsafe authority file.");
		checkPrivateAcl();
		return bytes.subarray(0, size).toString("utf8");
	} finally {
		await handle.close();
	}
}

export async function readJsonFile(
	path: string,
	max = 2 * 1024 * 1024,
	privateFile = false,
): Promise<unknown> {
	try {
		return JSON.parse(await readBoundedFile(resolve(resolvePath(path)), max, privateFile));
	} catch {
		throw new Error("Could not read a bounded regular JSON file.");
	}
}

async function removeOwnedFile(path: string, expected: Stats): Promise<void> {
	try {
		const current = await lstat(path);
		if (current.isFile() && !current.isSymbolicLink() && sameFile(current, expected))
			await unlink(path);
	} catch {
		// Never remove a replacement owned by another operation.
	}
}

export async function prepareLearningOutput(path: string): Promise<void> {
	try {
		const destination = resolve(resolvePath(path));
		const directory = dirname(destination);
		preparePrivateLocalDirectory(directory);
		try {
			await lstat(destination);
			throw new Error("Destination exists.");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		const probe = `${destination}.${randomUUID()}.tmp`;
		const handle = await open(
			probe,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
			0o600,
		);
		let created: Stats | undefined;
		try {
			created = await handle.stat();
			assertRegularFile(created, true);
		} finally {
			await handle.close().catch(() => {});
			if (created) await removeOwnedFile(probe, created);
		}
	} catch {
		throw new Error("Learning output requires a new destination in a writable owned directory.");
	}
}

async function writePrivateNewText(path: string, value: string): Promise<Stats> {
	const directory = dirname(path);
	await prepareLearningOutput(path);
	const before = await lstat(directory);
	const temporary = `${path}.${randomUUID()}.tmp`;
	const handle = await open(
		temporary,
		constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
		0o600,
	);
	let created: Stats | undefined;
	let published = false;
	try {
		created = await handle.stat();
		assertRegularFile(created, true);
		if (process.platform === "win32") preparePrivateLocalFile(temporary);
		await handle.writeFile(value, "utf8");
		await handle.sync();
		await handle.close();
		const current = await lstat(directory);
		if (current.isSymbolicLink() || !current.isDirectory() || !sameFile(before, current)) {
			throw new Error("Authority directory changed.");
		}
		const staged = await lstat(temporary);
		assertRegularFile(staged, true);
		if (!sameFile(created, staged)) throw new Error("Authority temporary file changed.");
		// A hard link publishes the complete file atomically and refuses every existing destination.
		await link(temporary, path);
		published = true;
		await unlink(temporary);
		const result = await lstat(path);
		assertRegularFile(result, true);
		if (!sameFile(created, result)) throw new Error("Authority output changed.");
		if (process.platform !== "win32") {
			const dir = await open(
				directory,
				constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | NO_FOLLOW,
			);
			try {
				await dir.sync();
			} finally {
				await dir.close();
			}
		}
		return created;
	} catch (error) {
		if (published && created) await removeOwnedFile(path, created);
		throw error;
	} finally {
		await handle.close().catch(() => {});
		if (created) await removeOwnedFile(temporary, created);
	}
}

export async function writePrivateNewJson(path: string, value: unknown): Promise<void> {
	try {
		await writePrivateNewText(resolve(resolvePath(path)), `${JSON.stringify(value, null, 2)}\n`);
	} catch {
		throw new Error("Could not write private JSON; use a new destination in an owned directory.");
	}
}

export async function generateLearningAuthority(options: {
	role: LearningAuthorityRole;
	out: string;
	secretStore?: string;
}): Promise<LearningAuthorityReference> {
	let store: SecretStore | undefined;
	let vaultId: string | undefined;
	let privateFile: { path: string; stats: Stats } | undefined;
	try {
		if (options.role !== "execution" && options.role !== "approval")
			throw new Error("Invalid role.");
		const out = resolve(resolvePath(options.out));
		await prepareLearningOutput(out);
		store = resolveSecretStore({ selection: options.secretStore });
		const fileFallback = options.secretStore?.trim().toLowerCase() === "file-acl";
		if (
			(store.location !== "os-vault" || !store.osProtected || !VAULTS.includes(store.kind)) &&
			!(fileFallback && store.kind === "file-acl")
		) {
			throw new Error("Explicit file fallback required.");
		}
		if (store.kind === "windows-dpapi")
			preparePrivateLocalDirectory(resolvePath("~/.singularity-aidr/secrets"));
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const secret = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
		let privateReference: LearningAuthorityReference["private"];
		if (fileFallback && store.kind === "file-acl") {
			const path = `${out}.pkcs8`;
			privateFile = { path, stats: await writePrivateNewText(path, `${secret}\n`) };
			privateReference = { store: "file-acl", path };
		} else {
			vaultId = createSecretReferenceId();
			store.put(vaultId, secret);
			if (store.get(vaultId) !== secret) throw new Error("Vault readback failed.");
			privateReference = { store: store.kind as PlatformSecretStoreKind, id: vaultId };
		}
		const reference: LearningAuthorityReference = {
			schema_version: 1,
			role: options.role,
			key_id: `aidr-authority-${randomUUID()}`,
			public_key_pem: publicKey.export({ format: "pem", type: "spki" }).toString(),
			created_at: new Date().toISOString(),
			private: privateReference,
		};
		await writePrivateNewJson(out, reference);
		return reference;
	} catch {
		if (privateFile) await removeOwnedFile(privateFile.path, privateFile.stats);
		if (store && vaultId) {
			try {
				store.revoke(vaultId);
			} catch {
				/* Own unreferenced entry only. */
			}
		}
		throw new Error(
			"Could not create learning authority; check the role, new destination and credential store.",
		);
	}
}

export async function loadLearningAuthority(
	path: string,
	expectedRole: LearningAuthorityRole,
): Promise<{
	keyId: string;
	privateKeyPem: string;
	publicKeyPem: string;
}> {
	try {
		const value = (await readJsonFile(path, 16 * 1024)) as LearningAuthorityReference;
		if (
			!value ||
			typeof value !== "object" ||
			Array.isArray(value) ||
			Object.keys(value).length !== 6 ||
			value.schema_version !== 1 ||
			value.role !== expectedRole ||
			(expectedRole !== "execution" && expectedRole !== "approval") ||
			typeof value.key_id !== "string" ||
			!SAFE_ID.test(value.key_id) ||
			value.key_id.includes("..") ||
			typeof value.public_key_pem !== "string" ||
			typeof value.created_at !== "string" ||
			!Number.isFinite(Date.parse(value.created_at)) ||
			!value.private ||
			typeof value.private !== "object" ||
			Array.isArray(value.private) ||
			Object.keys(value.private).length !== 2
		)
			throw new Error("Invalid authority reference.");
		let secret: string | null;
		if (value.private.store === "file-acl") {
			if (typeof value.private.path !== "string" || !isAbsolute(value.private.path))
				throw new Error("Invalid private path.");
			secret = (await readBoundedFile(value.private.path, 4 * 1024, true)).trim();
		} else {
			if (
				!VAULTS.includes(value.private.store) ||
				typeof value.private.id !== "string" ||
				!SAFE_ID.test(value.private.id) ||
				value.private.id.includes("..")
			)
				throw new Error("Invalid vault reference.");
			const store = resolveSecretStore({ selection: value.private.store });
			if (store.location !== "os-vault" || store.kind !== value.private.store)
				throw new Error("Vault mismatch.");
			secret = store.get(value.private.id);
		}
		if (!secret || secret.length > 4 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(secret))
			throw new Error("Missing private key.");
		const privateKey = createPrivateKey({
			key: Buffer.from(secret, "base64"),
			format: "der",
			type: "pkcs8",
		});
		const publicKey = createPublicKey(value.public_key_pem);
		if (
			privateKey.asymmetricKeyType !== "ed25519" ||
			publicKey.asymmetricKeyType !== "ed25519" ||
			publicKey.export({ format: "pem", type: "spki" }).toString() !== value.public_key_pem ||
			privateKey.export({ format: "der", type: "pkcs8" }).toString("base64") !== secret ||
			!createPublicKey(privateKey)
				.export({ format: "der", type: "spki" })
				.equals(publicKey.export({ format: "der", type: "spki" }))
		)
			throw new Error("Authority key mismatch.");
		return {
			keyId: value.key_id,
			privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
		};
	} catch {
		throw new Error("Could not load the requested learning authority.");
	}
}
