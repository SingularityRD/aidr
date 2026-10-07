import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({
	initialize: vi.fn(),
	open: vi.fn(),
	scan: vi.fn(),
	close: vi.fn(),
	uninitialize: vi.fn(),
	spawn: vi.fn(),
}));

// Like real koffi, named types live in a process-wide registry and may only be
// defined once.
const registeredTypes = new Set<string>();
vi.mock("koffi", () => ({
	default: {
		opaque: () => ({}),
		pointer: (name: string) => {
			if (registeredTypes.has(name)) throw new Error(`Duplicate type name '${name}'`);
			registeredTypes.add(name);
			return {};
		},
		load: () => ({
			func: (signature: string) => {
				if (signature.includes("AmsiInitialize")) return native.initialize;
				if (signature.includes("AmsiOpenSession")) return native.open;
				if (signature.includes("AmsiScanBuffer")) return native.scan;
				if (signature.includes("AmsiCloseSession")) return native.close;
				if (signature.includes("AmsiUninitialize")) return native.uninitialize;
				throw new Error("Unexpected native function");
			},
		}),
	},
}));
vi.mock("../clients/amsi-spawn.js", () => ({ spawn: native.spawn }));

import { AmsiClient } from "../clients/amsi.js";
import { nullLogger } from "../types.js";

describe("native Windows AMSI backend", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		native.initialize.mockImplementation((_name: string, context: unknown[]) => {
			context[0] = { context: true };
			return 0;
		});
		native.open.mockImplementation((_context: unknown, session: unknown[]) => {
			session[0] = { session: true };
			return 0;
		});
		native.scan.mockImplementation((
			_context: unknown,
			_content: Buffer,
			_length: number,
			_name: string,
			_session: unknown,
			result: number[],
		) => {
			result[0] = 0;
			return 0;
		});
	});
	afterEach(() => vi.restoreAllMocks());

	it("uses Koffi without spawning PowerShell and reports its backend", async () => {
		const client = new AmsiClient(nullLogger);
		await client.init();
		expect(client.isAvailable).toBe(true);
		expect(client.backendKind).toBe("native-koffi");
		const result = await client.scanString("benign local call", "Bash:command");
		expect(result?.amsiResult).toBe(0);
		expect(result?.isDetected).toBe(false);
		expect(native.scan).toHaveBeenCalledOnce();
		expect(native.spawn).not.toHaveBeenCalled();
		client.close();
		expect(client.backendKind).toBe("unavailable");
		expect(native.close).toHaveBeenCalledOnce();
		expect(native.uninitialize).toHaveBeenCalledOnce();
	});

	it("keeps the native backend for every client in a long-lived process", async () => {
		// In-process connectors (OpenClaw, OpenCode) create one client per tool
		// call; redefining koffi's named handle types used to throw and push every
		// call after the first onto the PowerShell fallback.
		for (let call = 0; call < 3; call++) {
			const client = new AmsiClient(nullLogger);
			await client.init();
			expect(client.backendKind).toBe("native-koffi");
			expect((await client.scanString(`call ${call}`, "Bash:command"))?.amsiResult).toBe(0);
			client.close();
		}
		expect(native.spawn).not.toHaveBeenCalled();
	});

	it("preserves the native AMSI detection result", async () => {
		native.scan.mockImplementation((
			_context: unknown,
			_content: Buffer,
			_length: number,
			_name: string,
			_session: unknown,
			result: number[],
		) => {
			result[0] = 32768;
			return 0;
		});
		const client = new AmsiClient(nullLogger);
		await client.init();
		const result = await client.scanString("test detection marker", "Bash:command");
		expect(result?.isDetected).toBe(true);
		expect(native.spawn).not.toHaveBeenCalled();
		client.close();
	});
});
