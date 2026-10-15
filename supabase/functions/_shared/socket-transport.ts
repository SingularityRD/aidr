// Raw TCP, TLS and UDP for Edge Functions that speak a non-HTTP protocol
// (SMTP mail, syslog SIEM forwarding) or must pin an internal CA for HTTPS.
//
// The transport is injectable. Production uses Deno's socket API:
//
//   * `connect` opens a plain TCP connection to an address the caller has
//     already vetted (the SIEM forwarder dials the exact IP it checked, so a
//     DNS answer cannot change between the policy check and the connection).
//   * `startTls` upgrades that connection (STARTTLS, or implicit TLS right
//     after connect). The certificate is verified against `serverName`, with
//     the system roots or, when given, ONLY the supplied PEM CA certificates
//     (an internal/private CA). Verification is never disabled.
//   * `sendDatagram` sends one UDP datagram when the runtime offers UDP. Some
//     Edge runtimes do not; the call then fails with `udp_unsupported`, which
//     callers record as a permanent delivery failure rather than a success.
//
// Tests substitute a Node implementation (node:net / node:tls) so the same
// protocol code runs end to end against local servers with a private CA.

export interface StreamConnection {
	write(data: Uint8Array): Promise<void>;
	/** The next chunk, or null once the peer closed the stream. */
	read(): Promise<Uint8Array | null>;
	/** Half-close: no more writes; the peer still answers (and closes). */
	closeWrite(): Promise<void>;
	close(): void;
}

interface TlsOptions {
	/** Host name (or IP literal) the certificate must be valid for; also the SNI name. */
	serverName: string;
	/** PEM certificates that replace the system trust store (internal CA). */
	caCerts?: string[];
}

export interface SocketTransport {
	connect(options: { hostname: string; port: number }): Promise<StreamConnection>;
	startTls(connection: StreamConnection, options: TlsOptions): Promise<StreamConnection>;
	sendDatagram(options: { hostname: string; port: number; data: Uint8Array }): Promise<void>;
}

export class TransportError extends Error {
	constructor(readonly code: "timeout" | "udp_unsupported" | "socket_unsupported" | "connection_closed") {
		super(code);
		this.name = "TransportError";
	}
}

/** Reject with `TransportError("timeout")` (and run `onTimeout`) when `promise` takes longer than `ms`. */
export function withTimeout<T>(promise: Promise<T>, ms: number, onTimeout?: () => void): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			try {
				onTimeout?.();
			} finally {
				reject(new TransportError("timeout"));
			}
		}, ms);
	});
	return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

/** Split PEM text into its certificate blocks; empty when there are none. */
export function pemCertificates(pem: string): string[] {
	return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
}

// ── Buffered reading ──────────────────────────────────────────────────────

/** Line and length oriented reads over a StreamConnection, with hard bounds. */
export class StreamReader {
	private buffer = new Uint8Array(0);
	private ended = false;

	constructor(private readonly connection: StreamConnection) {}

	private async fill(): Promise<boolean> {
		if (this.ended) return false;
		const chunk = await this.connection.read();
		if (chunk === null) {
			this.ended = true;
			return false;
		}
		const next = new Uint8Array(this.buffer.length + chunk.length);
		next.set(this.buffer);
		next.set(chunk, this.buffer.length);
		this.buffer = next;
		return true;
	}

	/** One CRLF- (or LF-) terminated line without the terminator; null at end of stream. */
	async readLine(maxBytes: number): Promise<string | null> {
		for (;;) {
			const index = this.buffer.indexOf(0x0a);
			if (index >= 0) {
				const end = index > 0 && this.buffer[index - 1] === 0x0d ? index - 1 : index;
				const line = new TextDecoder().decode(this.buffer.subarray(0, end));
				this.buffer = this.buffer.slice(index + 1);
				return line;
			}
			if (this.buffer.length > maxBytes) throw new RangeError("line_too_long");
			if (!(await this.fill())) {
				if (this.buffer.length === 0) return null;
				throw new TransportError("connection_closed");
			}
		}
	}

	async readExact(length: number): Promise<Uint8Array> {
		while (this.buffer.length < length) {
			if (!(await this.fill())) throw new TransportError("connection_closed");
		}
		const out = this.buffer.slice(0, length);
		this.buffer = this.buffer.slice(length);
		return out;
	}

	/** Everything until the peer closes, refusing more than `maxBytes`. */
	async readToEnd(maxBytes: number): Promise<Uint8Array> {
		while (await this.fill()) {
			if (this.buffer.length > maxBytes) throw new RangeError("body_too_large");
		}
		const out = this.buffer;
		this.buffer = new Uint8Array(0);
		return out;
	}
}

// ── Deno implementation ───────────────────────────────────────────────────

interface DenoConn {
	read(buffer: Uint8Array): Promise<number | null>;
	write(data: Uint8Array): Promise<number>;
	close(): void;
	closeWrite?: () => Promise<void>;
	handshake?: () => Promise<unknown>;
}

interface DenoSocketApi {
	connect?: (options: { hostname: string; port: number; transport: "tcp" }) => Promise<DenoConn>;
	startTls?: (conn: DenoConn, options: { hostname: string; caCerts?: string[] }) => Promise<DenoConn>;
	listenDatagram?: (options: { transport: "udp"; hostname: string; port: number }) => {
		send(data: Uint8Array, address: { transport: "udp"; hostname: string; port: number }): Promise<number>;
		close(): void;
	};
}

const RAW = Symbol("aidr.rawConnection");

function wrapDenoConn(conn: DenoConn): StreamConnection & { [RAW]: DenoConn } {
	return {
		[RAW]: conn,
		async write(data) {
			let offset = 0;
			while (offset < data.length) offset += await conn.write(data.subarray(offset));
		},
		async read() {
			const buffer = new Uint8Array(16 * 1024);
			const count = await conn.read(buffer);
			return count === null ? null : buffer.subarray(0, count);
		},
		async closeWrite() {
			if (typeof conn.closeWrite !== "function") throw new TransportError("socket_unsupported");
			await conn.closeWrite();
		},
		close() {
			try {
				conn.close();
			} catch {
				// Already closed.
			}
		},
	};
}

function denoApi(): DenoSocketApi {
	return ((globalThis as unknown as { Deno?: DenoSocketApi }).Deno ?? {}) as DenoSocketApi;
}

export const denoSocketTransport: SocketTransport = {
	async connect({ hostname, port }) {
		const api = denoApi();
		if (typeof api.connect !== "function") throw new TransportError("socket_unsupported");
		return wrapDenoConn(await api.connect({ hostname, port, transport: "tcp" }));
	},
	async startTls(connection, { serverName, caCerts }) {
		const api = denoApi();
		const raw = (connection as { [RAW]?: DenoConn })[RAW];
		if (typeof api.startTls !== "function" || !raw) throw new TransportError("socket_unsupported");
		const tls = await api.startTls(raw, { hostname: serverName, ...(caCerts?.length ? { caCerts } : {}) });
		// Complete (and verify) the handshake before any application byte is sent.
		if (typeof tls.handshake === "function") await tls.handshake();
		return wrapDenoConn(tls);
	},
	async sendDatagram({ hostname, port, data }) {
		const api = denoApi();
		if (typeof api.listenDatagram !== "function") throw new TransportError("udp_unsupported");
		let socket: ReturnType<NonNullable<DenoSocketApi["listenDatagram"]>>;
		try {
			socket = api.listenDatagram({ transport: "udp", hostname: hostname.includes(":") ? "::" : "0.0.0.0", port: 0 });
		} catch {
			throw new TransportError("udp_unsupported");
		}
		try {
			await socket.send(data, { transport: "udp", hostname, port });
		} finally {
			socket.close();
		}
	},
};
