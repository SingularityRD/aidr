// A node:net / node:tls implementation of the Edge Functions SocketTransport,
// so the SMTP and syslog protocol code runs end to end against local servers
// (with a throwaway private CA) under vitest. `redirect` lets a test map the
// vetted address the code dials onto the local server while still asserting
// which address it chose.
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createSocket } from "node:dgram";
import { type SocketTransport, type StreamConnection, TransportError } from "../_shared/socket-transport.ts";

function wrap(socket: Socket): StreamConnection & { socket: Socket } {
	const queue: Array<Uint8Array | null> = [];
	const waiters: Array<(chunk: Uint8Array | null) => void> = [];
	let failure: Error | null = null;
	const push = (chunk: Uint8Array | null) => {
		const waiter = waiters.shift();
		if (waiter) waiter(chunk);
		else queue.push(chunk);
	};
	socket.on("data", (chunk: Buffer) => push(new Uint8Array(chunk)));
	socket.on("end", () => push(null));
	socket.on("close", () => push(null));
	socket.on("error", (error) => {
		failure = error;
		push(null);
	});
	return {
		socket,
		write: (data) =>
			new Promise((resolve, reject) => socket.write(data, (error) => (error ? reject(error) : resolve()))),
		read: () => {
			if (failure) return Promise.reject(failure);
			if (queue.length > 0) return Promise.resolve(queue.shift() as Uint8Array | null);
			return new Promise((resolve, reject) =>
				waiters.push((chunk) => (failure ? reject(failure) : resolve(chunk))),
			);
		},
		closeWrite: () => new Promise<void>((resolve) => socket.end(() => resolve())),
		close: () => socket.destroy(),
	};
}

export interface NodeTransportLog {
	dialled: Array<{ hostname: string; port: number }>;
	tls: Array<{ serverName: string; caCerts: number }>;
	datagrams: Array<{ hostname: string; port: number; data: string }>;
}

export function nodeSocketTransport(
	redirect: (target: { hostname: string; port: number }) => { host: string; port: number } = (target) => ({
		host: target.hostname,
		port: target.port,
	}),
	options: { udp?: boolean } = {},
): SocketTransport & { log: NodeTransportLog } {
	const log: NodeTransportLog = { dialled: [], tls: [], datagrams: [] };
	return {
		log,
		connect(target) {
			log.dialled.push(target);
			const { host, port } = redirect(target);
			return new Promise((resolve, reject) => {
				const socket = netConnect({ host, port });
				socket.once("connect", () => resolve(wrap(socket)));
				socket.once("error", reject);
			});
		},
		startTls(connection, { serverName, caCerts }) {
			log.tls.push({ serverName, caCerts: caCerts?.length ?? 0 });
			const plain = (connection as unknown as { socket: Socket }).socket;
			plain.removeAllListeners("data");
			plain.removeAllListeners("end");
			plain.removeAllListeners("close");
			plain.removeAllListeners("error");
			return new Promise((resolve, reject) => {
				const isIp = /^[0-9.]+$/.test(serverName) || serverName.includes(":");
				const secure = tlsConnect({
					socket: plain,
					host: serverName,
					...(isIp ? {} : { servername: serverName }),
					...(caCerts?.length ? { ca: caCerts } : {}),
					rejectUnauthorized: true,
					minVersion: "TLSv1.2",
				});
				secure.once("secureConnect", () => resolve(wrap(secure)));
				secure.once("error", reject);
			});
		},
		async sendDatagram({ hostname, port, data }) {
			if (!options.udp) throw new TransportError("udp_unsupported");
			log.datagrams.push({ hostname, port, data: Buffer.from(data).toString("utf8") });
			const target = redirect({ hostname, port });
			await new Promise<void>((resolve, reject) => {
				const socket = createSocket("udp4");
				socket.send(data, target.port, target.host, (error) => {
					socket.close();
					if (error) reject(error);
					else resolve();
				});
			});
		},
	};
}
