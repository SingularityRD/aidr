import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
	type CommandRequest,
	type CommandResult,
	type CommandRunner,
	createMacosKeychainStore,
	SecretStoreError,
} from "../secret-store.js";

const service = "singularity-aidr-cli";
const marker = "aidr-utf8-base64-v1";
const labelPrefix = "aidr-secret-v1-";
const absent = { status: 44, stderr: "The specified item could not be found." };
interface Item {
	account: string;
	service: string;
	label: string;
	marker: string;
	password: string;
}

/** Apple's primary-key lookup intentionally ignores all other filters. */
function nativeFixture(seed: Item[] = []) {
	const items = new Map(seed.map((item) => [`${item.service}:${item.account}`, item]));
	const calls: { command: string; args: string[]; request: CommandRequest }[] = [];
	const runner: CommandRunner = (command, args, request) => {
		calls.push({ command, args, request });
		expect(command).toBe("/usr/bin/security");
		if (args[0] === "list-keychains") return { status: 0 };
		let argv = args;
		if (args[0] === "-q") {
			expect(args).toEqual(["-q", "-i"]);
			const input = request.input ?? "";
			expect(Buffer.byteLength(input)).toBeLessThanOrEqual(4095);
			expect(input).toMatch(/^[A-Za-z0-9+/=._ -]+\n$/);
			expect(input.split("\n")).toHaveLength(2);
			argv = input.slice(0, -1).split(" ");
		}
		const option = (name: string) =>
			argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined;
		const account = option("-a");
		const itemService = option("-s");
		const key = `${itemService}:${account}`;
		if (argv[0] === "add-generic-password") {
			expect(argv).toContain("-U");
			items.set(key, {
				account: account ?? "",
				service: itemService ?? "",
				label: option("-l") ?? "",
				marker: option("-G") ?? "",
				password: option("-w") ?? "",
			});
			return { status: 0 };
		}
		if (argv[0] === "delete-generic-password") {
			return items.delete(key) ? { status: 0 } : absent;
		}
		if (argv[0] === "find-generic-password") {
			const item =
				account && itemService
					? items.get(key)
					: [...items.values()].find(
							(value) =>
								(!account || value.account === account) &&
								(!itemService || value.service === itemService) &&
								(!option("-l") || value.label === option("-l")) &&
								(!option("-G") || value.marker === option("-G")),
						);
			return item ? { status: 0, stdout: `${item.password}\n` } : absent;
		}
		throw new Error("unexpected native fixture command");
	};
	return { runner, items, calls };
}

function legacy(account: string, password: string): Item {
	return { account, service, password, label: service, marker: "" };
}

function caught(action: () => unknown): SecretStoreError {
	try {
		action();
	} catch (error) {
		expect(error).toBeInstanceOf(SecretStoreError);
		return error as SecretStoreError;
	}
	throw new Error("expected a secret-store error");
}

describe("macOS Keychain source protocol (injected runner; no native vault acceptance)", () => {
	it.each([
		"plain-key",
		" spaces 'quotes' \"double\" \\backslash $(whoami); -leading",
		"first\nsecond\r\nthird\tend\n",
		"Türkçe İstanbul 🚀 漢字",
		"before\0after",
	])("round trips UTF-8 through a single bounded ASCII stdin command: %j", (secret) => {
		const { runner, calls, items } = nativeFixture();
		const store = createMacosKeychainStore({ runner });
		store.put("aidr-test", secret);
		expect(store.get("aidr-test")).toBe(secret);
		expect(items.get(`${service}:aidr-test`)).toMatchObject({
			marker,
			label: `${labelPrefix}aidr-test`,
		});
		expect(calls[0]?.args).toEqual(["-q", "-i"]);
		expect(calls[0]?.request.input).toContain(`-w ${Buffer.from(secret).toString("base64")} -U\n`);
		for (const call of calls) {
			expect(call.args.join(" ")).not.toContain(secret);
			expect(call.args).not.toContain("-v");
		}
	});

	it("supports an actual RSA-2048 PKCS8 PEM within the native input ceiling", () => {
		const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
		const { runner } = nativeFixture();
		const store = createMacosKeychainStore({ runner });
		store.put("discovery-gcp-private-key", pem);
		expect(store.get("discovery-gcp-private-key")).toBe(pem);
	});

	it.each(["YWJj", "616263", "aidr-utf8-base64-v1", "legacy key with spaces"])(
		"keeps unmarked legacy ASCII literal even when it resembles encoding: %s",
		(password) => {
			const { runner, calls } = nativeFixture([legacy("old-key", password)]);
			expect(createMacosKeychainStore({ runner }).get("old-key")).toBe(password);
			expect(calls[0]?.args).not.toContain("-a");
			expect(calls[0]?.args).toContain("-G");
			expect(calls[1]?.args).toEqual([
				"find-generic-password",
				"-a",
				"old-key",
				"-s",
				service,
				"-w",
			]);
		},
	);

	it("atomically replaces a legacy service/account item and keeps delete identity", () => {
		const { runner, items } = nativeFixture([legacy("old-key", "old-value")]);
		const store = createMacosKeychainStore({ runner });
		store.put("old-key", "new\nvalue");
		expect(items.size).toBe(1);
		expect(store.get("old-key")).toBe("new\nvalue");
		store.revoke("old-key");
		expect(items.size).toBe(0);
		expect(store.get("old-key")).toBeNull();
		expect(() => store.revoke("old-key")).not.toThrow();
	});

	it("does not return the encoded value when migration occurs during a legacy fallback", () => {
		const fixture = nativeFixture([legacy("old-key", "old-value")]);
		let migrated = false;
		const runner: CommandRunner = (command, args, request) => {
			if (args[0] === "find-generic-password" && args.includes("-a") && !migrated) {
				migrated = true;
				fixture.items.set(`${service}:old-key`, {
					...legacy("old-key", Buffer.from("migrated-value").toString("base64")),
					label: `${labelPrefix}old-key`,
					marker,
				});
			}
			return fixture.runner(command, args, request);
		};
		expect(createMacosKeychainStore({ runner }).get("old-key")).toBe("migrated-value");
	});

	it.each(["", "abc", "Zg=", "Zh==", "Zm9=", "YWJj\n", "/w==", "77+9/w==", "A".repeat(4096)])(
		"rejects malformed marked base64, UTF-8 or size with no legacy fallback",
		(payload) => {
			const runner = vi.fn<CommandRunner>(() => ({ status: 0, stdout: `${payload}\n` }));
			expect(() => createMacosKeychainStore({ runner }).get("test")).toThrow(
				/invalid storage format/,
			);
			expect(runner).toHaveBeenCalledTimes(1);
		},
	);

	it.each(["", "\ud800", "\udc00", "a".repeat(4096)])(
		"rejects invalid input before native execution",
		(secret) => {
			const runner = vi.fn<CommandRunner>(() => ({ status: 0 }));
			expect(() => createMacosKeychainStore({ runner }).put("test", secret)).toThrow(
				SecretStoreError,
			);
			expect(runner).not.toHaveBeenCalled();
		},
	);

	it.each(["x", "x".repeat(128)])(
		"accepts the maximum complete line and rejects the next encoded block",
		(id) => {
			const fixture = nativeFixture();
			const store = createMacosKeychainStore({ runner: fixture.runner });
			store.put(id, "a");
			const fixedBytes = (fixture.calls[0]?.request.input?.length ?? 0) - 1 - 4;
			const maxBytes = Math.floor((4094 - fixedBytes) / 4) * 3;
			store.put(id, "a".repeat(maxBytes));
			expect(store.get(id)).toBe("a".repeat(maxBytes));
			const count = fixture.calls.length;
			expect(() => store.put(id, "a".repeat(maxBytes + 1))).toThrow(/input limit/);
			expect(fixture.calls).toHaveLength(count);
		},
	);

	it("enforces the input ceiling in UTF-8 bytes rather than character count", () => {
		const id = "x".repeat(128);
		const fixture = nativeFixture();
		const store = createMacosKeychainStore({ runner: fixture.runner });
		store.put(id, "€".repeat(935)); // 2805 UTF-8 bytes, maximum for a 128-byte ID.
		expect(store.get(id)).toBe("€".repeat(935));
		const count = fixture.calls.length;
		expect(() => store.put(id, "€".repeat(936))).toThrow(/input limit/);
		expect(fixture.calls).toHaveLength(count);
	});

	it.each(["-id", "id\nhelp", "id;help", "id..next", "x".repeat(129)])(
		"rejects invalid references before native execution",
		(id) => {
			const runner = vi.fn<CommandRunner>(() => ({ status: 0 }));
			const store = createMacosKeychainStore({ runner });
			for (const operation of [
				() => store.put(id, "secret"),
				() => store.get(id),
				() => store.revoke(id),
			]) {
				expect(operation).toThrow(SecretStoreError);
			}
			expect(runner).not.toHaveBeenCalled();
		},
	);

	it.each<CommandResult>([
		{ status: 1, stderr: "The specified item could not be found." },
		{ status: 44, stderr: "permission denied" },
		{ status: null },
		{ status: 44, stderr: "The specified item could not be found.", error: new Error("timeout") },
	])("only permits the native item-not-found result to start a legacy lookup", (result) => {
		const runner = vi.fn<CommandRunner>(() => result);
		expect(() => createMacosKeychainStore({ runner }).get("test")).toThrow(/could not be queried/);
		expect(runner).toHaveBeenCalledTimes(1);
	});

	it.each(["put", "get", "revoke"] as const)(
		"sanitizes %s native failures and thrown exceptions",
		(operation) => {
			const secret = "private-material-do-not-expose";
			for (const throws of [false, true]) {
				const runner: CommandRunner = () => {
					if (throws) throw new Error(secret);
					return { status: null, stdout: secret, stderr: secret, error: new Error(secret) };
				};
				const store = createMacosKeychainStore({ runner });
				const error = caught(() =>
					operation === "put" ? store.put("test", secret) : store[operation]("test"),
				);
				expect(`${error.stack}\n${JSON.stringify(error)}`).not.toContain(secret);
				expect(error.cause).toBeUndefined();
			}
		},
	);

	it("probes the fixed native executable and handles native exceptions as unavailable", () => {
		const fixture = nativeFixture();
		expect(createMacosKeychainStore({ runner: fixture.runner }).isAvailable()).toBe(true);
		expect(fixture.calls[0]?.args).toEqual(["list-keychains"]);
		expect(
			createMacosKeychainStore({
				runner: () => {
					throw new Error("native exception");
				},
			}).isAvailable(),
		).toBe(false);
	});
});
