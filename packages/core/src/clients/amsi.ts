/**
 * AMSI (Antimalware Scan Interface) client.
 * Tries koffi FFI first, then PowerShell P/Invoke as fallback.
 *
 * Degradation policy. A host that does not support AMSI at all (not native
 * Windows, not WSL) is a silent no-op: the leg does not exist there and an
 * answer of `null` means "nothing to run". Everything else that stops a scan
 * from running on a host that DOES support AMSI raises
 * `DetectionLegUnavailableError` instead of answering `null`, because a null
 * answer used to be indistinguishable from "scanned and found nothing".
 */

import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DetectionLegUnavailableError } from "../detection-leg.js";
import type { AmsiCheckResult, Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { spawn } from "./amsi-spawn.js";

/** AMSI_RESULT thresholds */
const AMSI_RESULT_DETECTED = 32768; // 0x8000
const AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384; // 0x4000

/** Max content length to scan (AMSI has practical limits). */
const MAX_SCAN_LENGTH = 1_048_576; // 1 MB

/** Timeout for PowerShell operations (ms). */
const PS_TIMEOUT = 15_000;

/** Written to stderr by the PowerShell backend when the language mode forbids Add-Type. */
const LANGUAGE_MODE_MARKER = "AIDR_LANGUAGE_MODE=";

/**
 * Why a host that supports AMSI has no usable backend.
 *
 * - `constrained_language`: PowerShell runs in ConstrainedLanguage (AppLocker /
 *   WDAC), so the P/Invoke fallback cannot compile, and the native backend is
 *   not available either. This does not change from one call to the next.
 * - `no_backend`: neither backend initialised for another reason (koffi
 *   missing or blocked, PowerShell missing, slow or failing).
 */
export type AmsiUnavailableKind = "constrained_language" | "no_backend";

/**
 * Bundled Claude hooks load the manifest-covered native addon from dist/vendor.
 * The unbundled core library keeps its normal optional dependency resolution.
 * A present but broken bundled addon must not silently select a different copy
 * from the host's node_modules; the caller will use the PowerShell fallback.
 */
type KoffiModule = typeof import("koffi") & { default?: typeof import("koffi") };

async function loadKoffi(): Promise<KoffiModule> {
	const bundledPath =
		typeof __dirname === "string" ? join(__dirname, "vendor", "koffi", "index.js") : null;
	if (bundledPath && existsSync(bundledPath)) {
		return (await import(pathToFileURL(bundledPath).href)) as KoffiModule;
	}
	return (await import("koffi")) as KoffiModule;
}

/** Detect whether we're running inside WSL (Windows Subsystem for Linux). */
function isWSL(): boolean {
	if (process.platform !== "linux") return false;
	return !!process["env"]["WSL_DISTRO_NAME"];
}

/** Check whether the current platform supports AMSI scanning (native Windows or WSL). */
export function isAmsiSupported(): boolean {
	return process.platform === "win32" || isWSL();
}

/** Interpret a numeric AMSI result into the standard result fields. */
function interpretAmsiResult(
	amsiResult: number,
	content: string,
	contentName: string,
): AmsiCheckResult {
	return {
		content: content.length > 200 ? `${content.slice(0, 200)}...` : content,
		contentName,
		amsiResult,
		isDetected: amsiResult >= AMSI_RESULT_DETECTED,
		isBlockedByAdmin:
			amsiResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && amsiResult < AMSI_RESULT_DETECTED,
	};
}

/** Backend interface for AMSI implementations. */
interface AmsiBackend {
	readonly isAvailable: boolean;
	init(): Promise<void>;
	scanString(content: string, contentName: string): Promise<AmsiCheckResult | null>;
	close(): void;
}

// ---------------------------------------------------------------------------
// Koffi FFI backend (native, fast — requires koffi)
// ---------------------------------------------------------------------------

/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
type KoffiFn = (...args: any[]) => any;

interface KoffiAmsiBindings {
	AmsiInitialize: KoffiFn;
	AmsiOpenSession: KoffiFn;
	AmsiScanBuffer: KoffiFn;
	AmsiCloseSession: KoffiFn;
	AmsiUninitialize: KoffiFn;
}

/**
 * The amsi.dll bindings, created once per process. koffi registers named types
 * (`HAMSICONTEXT`, `HAMSISESSION`) in a process-wide registry, so defining them
 * again for a second client throws "Duplicate type name". Without this cache
 * every evaluation after the first in a long-lived process (OpenClaw, OpenCode)
 * fell back to spawning PowerShell (~300-500 ms per call).
 */
let koffiAmsiBindings: Promise<KoffiAmsiBindings> | null = null;

function loadKoffiAmsiBindings(): Promise<KoffiAmsiBindings> {
	koffiAmsiBindings ??= (async () => {
		const koffiModule = await loadKoffi();
		// unwrap CJS module if needed
		const koffi = koffiModule.default ?? koffiModule;
		const lib = koffi.load("amsi.dll");
		// define opaque handle types matching the Win32 AMSI API
		koffi.pointer("HAMSICONTEXT", koffi.opaque());
		koffi.pointer("HAMSISESSION", koffi.opaque());
		return {
			AmsiInitialize: lib.func(
				"int32 __stdcall AmsiInitialize(str16 appName, _Out_ HAMSICONTEXT *ctx)",
			),
			AmsiOpenSession: lib.func(
				"int32 __stdcall AmsiOpenSession(HAMSICONTEXT ctx, _Out_ HAMSISESSION *session)",
			),
			AmsiScanBuffer: lib.func(
				"int32 __stdcall AmsiScanBuffer(HAMSICONTEXT ctx, void *buf, uint32 len, str16 contentName, HAMSISESSION session, _Out_ int32 *result)",
			),
			AmsiCloseSession: lib.func(
				"void __stdcall AmsiCloseSession(HAMSICONTEXT ctx, HAMSISESSION session)",
			),
			AmsiUninitialize: lib.func("void __stdcall AmsiUninitialize(HAMSICONTEXT ctx)"),
		};
	})();
	// A transient load failure must not disable the native backend for the life of
	// a long-running process: forget the rejected attempt so the next client retries.
	koffiAmsiBindings.catch(() => {
		koffiAmsiBindings = null;
	});
	return koffiAmsiBindings;
}

class KoffiAmsiBackend implements AmsiBackend {
	private readonly logger: Logger;
	private context: unknown = null;
	private session: unknown = null;
	private available = false;

	/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
	private fnScanBuffer: ((...args: any[]) => number) | null = null;
	/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
	private fnCloseSession: ((...args: any[]) => void) | null = null;
	/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
	private fnUninitialize: ((...args: any[]) => void) | null = null;

	constructor(logger: Logger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	async init(): Promise<void> {
		try {
			const bindings = await loadKoffiAmsiBindings();
			const { AmsiInitialize, AmsiOpenSession } = bindings;
			this.fnScanBuffer = bindings.AmsiScanBuffer;
			this.fnCloseSession = bindings.AmsiCloseSession;
			this.fnUninitialize = bindings.AmsiUninitialize;

			const ctxOut: unknown[] = [null];
			const hr = AmsiInitialize("Singularity AIDR", ctxOut);
			if (hr !== 0) {
				this.logger.warn("AMSI: koffi AmsiInitialize failed", { hr });
				return;
			}
			this.context = ctxOut[0];

			const sessOut: unknown[] = [null];
			const hr2 = AmsiOpenSession(this.context, sessOut);
			if (hr2 !== 0) {
				this.logger.warn("AMSI: koffi AmsiOpenSession failed", { hr: hr2 });
				try {
					if (this.fnUninitialize) {
						this.fnUninitialize(this.context);
					}
				} catch {
					/* best effort */
				}
				this.context = null;
				return;
			}
			this.session = sessOut[0];

			this.available = true;
			this.logger.debug("AMSI: koffi backend initialized");
		} catch (e) {
			this.logger.debug("AMSI: koffi backend init failed", { error: String(e) });
			this.available = false;
		}
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		if (!this.available || !this.fnScanBuffer || !this.context || !this.session) {
			return null;
		}

		try {
			const truncated =
				content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;
			const buf = Buffer.from(truncated, "utf-8");
			const resultOut = [0];

			const hr = this.fnScanBuffer(
				this.context,
				buf,
				buf.length,
				contentName,
				this.session,
				resultOut,
			);
			if (hr !== 0) {
				this.logger.warn("AMSI: koffi AmsiScanBuffer failed", { hr, contentName });
				return null;
			}

			const amsiResult = resultOut[0] ?? 0;
			this.logger.debug("AMSI: koffi scan result", { contentName, amsiResult });
			return interpretAmsiResult(amsiResult, content, contentName);
		} catch (e) {
			this.logger.warn("AMSI: koffi scanBuffer failed", { error: String(e), contentName });
			return null;
		}
	}

	close(): void {
		try {
			if (this.session && this.context && this.fnCloseSession) {
				this.fnCloseSession(this.context, this.session);
			}
		} catch {
			/* best effort */
		}

		try {
			if (this.context && this.fnUninitialize) {
				this.fnUninitialize(this.context);
			}
		} catch {
			/* best effort */
		}

		this.session = null;
		this.context = null;
		this.available = false;
	}
}

// ---------------------------------------------------------------------------
// PowerShell P/Invoke backend
// ---------------------------------------------------------------------------

/** Shared C# AMSI interop type compiled once by Add-Type in each script. */
const AMSI_CSHARP_TYPE = `
using System;
using System.Runtime.InteropServices;
using System.Text;

public class SageAmsi {
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    static extern int AmsiInitialize(string appName, out IntPtr ctx);

    [DllImport("amsi.dll")]
    static extern int AmsiOpenSession(IntPtr ctx, out IntPtr session);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    static extern int AmsiScanBuffer(
        IntPtr ctx, byte[] buf, uint len,
        string contentName, IntPtr session, out int result);

    [DllImport("amsi.dll")]
    static extern void AmsiCloseSession(IntPtr ctx, IntPtr session);

    [DllImport("amsi.dll")]
    static extern void AmsiUninitialize(IntPtr ctx);

    private static IntPtr _ctx;
    private static IntPtr _session;
    private static bool _initialized;

    public static bool Init() {
        int hr = AmsiInitialize("Singularity AIDR", out _ctx);
        if (hr != 0) return false;
        hr = AmsiOpenSession(_ctx, out _session);
        if (hr != 0) {
            AmsiUninitialize(_ctx);
            return false;
        }
        _initialized = true;
        return true;
    }

    public static int Scan(string content, string contentName) {
        if (!_initialized) return -1;
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        int result;
        int hr = AmsiScanBuffer(_ctx, bytes, (uint)bytes.Length,
                                contentName, _session, out result);
        if (hr != 0) return -1;
        return result;
    }

    public static void Shutdown() {
        if (!_initialized) return;
        AmsiCloseSession(_ctx, _session);
        AmsiUninitialize(_ctx);
        _initialized = false;
    }
}
`;

/**
 * Persistent PowerShell script: compiles the interop type once, initializes
 * AMSI once, then enters a read loop. Used on native Windows where stdin
 * piping is reliable.
 */
const PS_PERSISTENT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    # Add-Type is refused outside FullLanguage (AppLocker / WDAC put PowerShell
    # in ConstrainedLanguage). Say so explicitly instead of failing on Add-Type.
    $mode = [string]$ExecutionContext.SessionState.LanguageMode
    if ($mode -ne 'FullLanguage') {
        [Console]::Error.Write("${LANGUAGE_MODE_MARKER}" + $mode)
        exit 3
    }
    Add-Type -TypeDefinition @'
${AMSI_CSHARP_TYPE}
'@

    if (-not [SageAmsi]::Init()) {
        [Console]::Error.Write("AMSI initialization failed")
        exit 1
    }

    [Console]::Out.WriteLine("READY")
    [Console]::Out.Flush()

    while ($null -ne ($line = [Console]::In.ReadLine())) {
        try {
            $req = $line | ConvertFrom-Json
            $content = $req.content
            $cname = $req.contentName
            if (-not $cname) { $cname = 'aidr:test' }
            $result = [SageAmsi]::Scan($content, $cname)
            [Console]::Out.WriteLine($result)
            [Console]::Out.Flush()
        } catch {
            [Console]::Out.WriteLine("-1")
            [Console]::Out.Flush()
        }
    }

    [SageAmsi]::Shutdown()
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 1
}
`;

/**
 * One-shot PowerShell script: reads a single JSON line from stdin, scans,
 * outputs result, and exits. Used under WSL where stdin pipes to Windows
 * executables are unreliable for persistent processes (data written after
 * the first read may never be delivered).
 */
const PS_ONESHOT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -TypeDefinition @'
${AMSI_CSHARP_TYPE}
'@

    if (-not [SageAmsi]::Init()) {
        [Console]::Out.WriteLine("-1")
        exit
    }

    $line = [Console]::In.ReadLine()
    $req = $line | ConvertFrom-Json
    $content = $req.content
    $cname = $req.contentName
    if (-not $cname) { $cname = 'aidr:scan' }
    $result = [SageAmsi]::Scan($content, $cname)
    [SageAmsi]::Shutdown()
    [Console]::Out.WriteLine($result)
    [Console]::Out.Flush()
} catch {
    [Console]::Out.WriteLine("-1")
}
`;

/**
 * Persistent PowerShell AMSI backend for native Windows.
 * Spawns a single long-lived PowerShell process with a stdin/stdout loop.
 */
class PersistentPowershellAmsiBackend implements AmsiBackend {
	private readonly logger: Logger;
	private process: ChildProcess | null = null;
	private available = false;
	private stdoutBuffer = "";
	/** First stderr bytes of the process, kept to explain a failed start. */
	private stderrText = "";
	private scanQueue: Promise<void> = Promise.resolve();
	private pendingResponse: {
		resolve: (line: string) => void;
		reject: (err: Error) => void;
		timer: ReturnType<typeof setTimeout>;
	} | null = null;

	constructor(logger: Logger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	private waitForLine(timeout: number): Promise<string> {
		return new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => {
				if (this.pendingResponse?.timer !== timer) return;
				this.pendingResponse = null;
				this.terminateProcess();
				reject(new Error("timeout"));
			}, timeout);

			this.pendingResponse = { resolve, reject, timer };
		});
	}

	private rejectPending(error: Error): void {
		if (!this.pendingResponse) return;
		const { reject, timer } = this.pendingResponse;
		this.pendingResponse = null;
		clearTimeout(timer);
		reject(error);
	}

	private terminateProcess(): void {
		if (this.process) {
			try {
				this.process.stdin?.end();
			} catch {
				/* best effort */
			}
			try {
				this.process.kill();
			} catch {
				/* best effort */
			}
			this.process = null;
		}
		this.stdoutBuffer = "";
		this.available = false;
	}

	async init(): Promise<void> {
		try {
			this.process = spawn(
				"powershell.exe",
				["-NoProfile", "-NonInteractive", "-Command", PS_PERSISTENT_SCRIPT],
				{
					stdio: ["pipe", "pipe", "pipe"],
					windowsHide: true,
				},
			);

			this.process.on("error", (err) => {
				this.logger.debug("AMSI: PowerShell process error", { error: String(err) });
				this.available = false;
				if (this.pendingResponse) {
					const { reject, timer } = this.pendingResponse;
					this.pendingResponse = null;
					clearTimeout(timer);
					reject(err);
				}
			});

			this.process.on("exit", () => {
				this.available = false;
				if (this.pendingResponse) {
					const { reject, timer } = this.pendingResponse;
					this.pendingResponse = null;
					clearTimeout(timer);
					reject(new Error("process exited"));
				}
			});

			this.process.stdout?.on("data", (chunk: Buffer) => {
				this.stdoutBuffer += chunk.toString();
				let idx = this.stdoutBuffer.indexOf("\n");
				while (idx !== -1) {
					const line = this.stdoutBuffer.slice(0, idx).trim();
					this.stdoutBuffer = this.stdoutBuffer.slice(idx + 1);
					if (this.pendingResponse) {
						const { resolve, timer } = this.pendingResponse;
						this.pendingResponse = null;
						clearTimeout(timer);
						resolve(line);
					}
					idx = this.stdoutBuffer.indexOf("\n");
				}
			});

			this.process.stdin?.on("error", () => {
				/* ignore write errors on closed pipe */
			});

			this.process.stderr?.on("data", (chunk: Buffer) => {
				if (this.stderrText.length < 2048) this.stderrText += chunk.toString();
				this.logger.debug("AMSI: PowerShell stderr", {
					data: chunk.toString().slice(0, 200),
				});
			});

			const readyLine = await this.waitForLine(PS_TIMEOUT);
			if (readyLine === "READY") {
				this.available = true;
				this.logger.debug("AMSI: PowerShell persistent backend initialized");
			} else {
				this.logger.debug("AMSI: PowerShell unexpected ready signal", { readyLine });
				this.close();
			}
		} catch (e) {
			this.logger.debug("AMSI: PowerShell persistent backend init failed", {
				error: String(e),
			});
			await this.drainStderr();
			this.close();
		}
	}

	/**
	 * `exit` can fire before the last stderr chunk is read. Give a process that
	 * failed to start a moment to deliver it, so a language-mode refusal is
	 * reported as such rather than as a generic failure.
	 */
	private async drainStderr(): Promise<void> {
		const stderr = this.process?.stderr;
		if (!stderr || this.stderrText.includes(LANGUAGE_MODE_MARKER)) return;
		await new Promise<void>((resolve) => {
			const timer = setTimeout(resolve, 250);
			stderr.once("end", () => {
				clearTimeout(timer);
				resolve();
			});
		});
	}

	/** The PowerShell language mode reported by a failed start, or null. */
	get refusedLanguageMode(): string | null {
		const index = this.stderrText.indexOf(LANGUAGE_MODE_MARKER);
		if (index === -1) return null;
		const mode = /^[A-Za-z]{1,40}/.exec(this.stderrText.slice(index + LANGUAGE_MODE_MARKER.length));
		return mode?.[0] ?? "unknown";
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		const operation = this.scanQueue.then(() => this.scanStringSerialized(content, contentName));
		this.scanQueue = operation.then(
			() => undefined,
			() => undefined,
		);
		return operation;
	}

	private async scanStringSerialized(
		content: string,
		contentName: string,
	): Promise<AmsiCheckResult | null> {
		if (!this.available || !this.process) return null;

		const truncated =
			content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;

		try {
			const req = JSON.stringify({ content: truncated, contentName });
			// Install the response waiter before writing. PowerShell can answer in the
			// same turn, and registering afterwards can lose that response.
			const response = this.waitForLine(PS_TIMEOUT);
			try {
				this.process.stdin?.write(`${req}\n`);
			} catch (error) {
				this.rejectPending(error instanceof Error ? error : new Error(String(error)));
				this.terminateProcess();
			}

			const line = await response;
			const amsiResult = parseInt(line, 10);

			if (Number.isNaN(amsiResult) || amsiResult < 0) {
				this.logger.warn("AMSI: PowerShell scan returned invalid result", {
					stdout: line.slice(0, 100),
					contentName,
				});
				// A malformed or late line makes the stream framing untrustworthy. Reset
				// the backend rather than assigning a future line to the wrong scan.
				this.terminateProcess();
				return null;
			}

			this.logger.debug("AMSI: PowerShell scan result", { contentName, amsiResult });
			return interpretAmsiResult(amsiResult, content, contentName);
		} catch (e) {
			this.logger.warn("AMSI: PowerShell scan failed", { error: String(e), contentName });
			return null;
		}
	}

	close(): void {
		if (this.pendingResponse) {
			const { reject, timer } = this.pendingResponse;
			this.pendingResponse = null;
			clearTimeout(timer);
			reject(new Error("closed"));
		}
		this.terminateProcess();
	}
}

/**
 * One-shot PowerShell AMSI backend for WSL.
 * Spawns a fresh powershell.exe per scan and closes stdin after writing to
 * flush the WSL interop pipe. Stateless — no persistent process.
 */
class WslPowershellAmsiBackend implements AmsiBackend {
	private readonly logger: Logger;
	private available = false;

	constructor(logger: Logger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	async init(): Promise<void> {
		this.available = true;
		this.logger.debug("AMSI: PowerShell one-shot backend ready (WSL)");
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		if (!this.available) return null;

		const truncated =
			content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;

		return new Promise((resolve) => {
			try {
				const ps = spawn(
					"powershell.exe",
					["-NoProfile", "-NonInteractive", "-Command", PS_ONESHOT_SCRIPT],
					{ stdio: ["pipe", "pipe", "pipe"] },
				);

				let stdout = "";
				const timer = setTimeout(() => {
					this.logger.warn("AMSI: PowerShell one-shot timeout", { contentName });
					try {
						ps.kill();
					} catch {
						/* best effort */
					}
					resolve(null);
				}, PS_TIMEOUT);

				ps.stdout?.on("data", (chunk: Buffer) => {
					stdout += chunk.toString();
				});
				ps.stderr?.on("data", (chunk: Buffer) => {
					this.logger.debug("AMSI: PowerShell one-shot stderr", {
						data: chunk.toString().slice(0, 200),
					});
				});
				ps.on("error", (err) => {
					clearTimeout(timer);
					this.logger.debug("AMSI: PowerShell one-shot error", { error: String(err) });
					resolve(null);
				});
				ps.on("exit", () => {
					clearTimeout(timer);
					const amsiResult = parseInt(stdout.trim(), 10);
					if (Number.isNaN(amsiResult) || amsiResult < 0) {
						this.logger.warn("AMSI: PowerShell one-shot invalid result", {
							stdout: stdout.slice(0, 100),
							contentName,
						});
						resolve(null);
						return;
					}
					this.logger.debug("AMSI: PowerShell one-shot result", { contentName, amsiResult });
					resolve(interpretAmsiResult(amsiResult, content, contentName));
				});

				const req = JSON.stringify({ content: truncated, contentName });
				ps.stdin?.write(`${req}\n`);
				ps.stdin?.end();
			} catch (e) {
				this.logger.warn("AMSI: PowerShell one-shot failed", { error: String(e), contentName });
				resolve(null);
			}
		});
	}

	close(): void {
		this.available = false;
	}
}

// ---------------------------------------------------------------------------
// Exported facade — tries koffi, then PowerShell, then gives up
// ---------------------------------------------------------------------------

export class AmsiClient {
	private readonly logger: Logger;
	private backend: AmsiBackend | null = null;
	private selectedBackend:
		| "native-koffi"
		| "powershell-persistent"
		| "powershell-oneshot"
		| "unavailable" = "unavailable";
	/**
	 * Operator-readable reason why this host, which supports AMSI, has no usable
	 * backend. Set only by `init()` after both backends failed; a client that was
	 * never initialised, was closed, or runs on an unsupported host leaves it
	 * null, and those cases stay silent no-ops.
	 */
	private unavailableReason: string | null = null;
	private unavailableKindValue: AmsiUnavailableKind | null = null;

	constructor(logger: Logger = nullLogger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.backend?.isAvailable ?? false;
	}

	/**
	 * Why `init()` found no backend on a host that supports AMSI, or null (a
	 * backend is available, the host does not support AMSI, or `init()` has not
	 * run). Lets the caller tell a host where AMSI cannot run at all from a scan
	 * that failed on a working backend.
	 */
	get unavailableKind(): AmsiUnavailableKind | null {
		return this.unavailableKindValue;
	}

	/** Operator-readable reason paired with {@link unavailableKind}. */
	get unavailableDetail(): string | null {
		return this.unavailableReason;
	}

	/** Makes native availability and fallback visible to installers and diagnostics. */
	get backendKind():
		| "native-koffi"
		| "powershell-persistent"
		| "powershell-oneshot"
		| "unavailable" {
		return this.selectedBackend;
	}

	async init(): Promise<void> {
		const wsl = isWSL();

		if (process.platform !== "win32" && !wsl) {
			this.logger.debug("AMSI: skipping, not Windows");
			return;
		}

		// Koffi (native FFI) — only viable on native Windows (can't load
		// Windows DLLs from Linux userspace, even under WSL).
		if (!wsl) {
			const koffi = new KoffiAmsiBackend(this.logger);
			await koffi.init();
			if (koffi.isAvailable) {
				this.backend = koffi;
				this.selectedBackend = "native-koffi";
				return;
			}
			this.logger.warn("AMSI native backend unavailable; trying PowerShell fallback");
		}

		// PowerShell P/Invoke — works on native Windows and WSL (WSL interop
		// routes powershell.exe to the Windows-side binary).
		const ps = wsl
			? new WslPowershellAmsiBackend(this.logger)
			: new PersistentPowershellAmsiBackend(this.logger);
		await ps.init();
		if (ps.isAvailable) {
			this.backend = ps;
			this.selectedBackend = wsl ? "powershell-oneshot" : "powershell-persistent";
			if (!wsl) this.logger.warn("AMSI PowerShell fallback active");
			return;
		}

		this.selectedBackend = "unavailable";
		// The host supports AMSI (see isAmsiSupported), so reaching this point is an
		// outage of the leg itself, not "there was nothing to scan".
		const languageMode =
			ps instanceof PersistentPowershellAmsiBackend ? ps.refusedLanguageMode : null;
		this.unavailableKindValue = languageMode ? "constrained_language" : "no_backend";
		this.unavailableReason = languageMode
			? `no AMSI backend could be established on this host: the native koffi backend is unavailable and PowerShell runs in ${languageMode} mode (AppLocker/WDAC), which blocks the PowerShell fallback`
			: "no AMSI backend could be established on this host: the native koffi backend and the PowerShell fallback both failed to initialize";
		this.logger.warn("AMSI unavailable: native and PowerShell backends failed", {
			kind: this.unavailableKindValue,
		});
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		if (!this.backend?.isAvailable) {
			// An unsupported host, a never-initialised client and a closed client are
			// all "this leg does not apply here" and stay a silent no-op. A supported
			// host whose backends failed is a different thing entirely, and answering
			// `null` there would read as "scanned, nothing found".
			if (this.unavailableReason !== null) {
				throw new DetectionLegUnavailableError("amsi", this.unavailableReason);
			}
			return null;
		}

		return (await this.backend.scanString(content, contentName)) ?? null;
	}

	close(): void {
		this.backend?.close();
		this.backend = null;
		this.selectedBackend = "unavailable";
		this.unavailableReason = null;
		this.unavailableKindValue = null;
	}
}
