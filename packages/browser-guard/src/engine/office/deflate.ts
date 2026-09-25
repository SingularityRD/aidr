/**
 * Bounded (de)compression on the platform's Compression Streams API.
 *
 * Browser-safe: `DecompressionStream` / `CompressionStream` exist in Chrome 80+ (deflate-raw
 * from 103), Firefox 113+ and Node 18+. No wasm, no remote code, no `node:` imports.
 *
 * `inflateBounded` never materialises more than `maxOutput` bytes: the input is fed in small
 * slices and the output is read as it is produced, so a decompression bomb is cancelled as
 * soon as it crosses the limit instead of after it has filled memory.
 */

export type InflateFormat = "deflate-raw" | "deflate";

/** Thrown when inflated output would exceed the caller's byte budget. */
export class InflateLimitError extends Error {
	constructor() {
		super("INFLATE_LIMIT");
		this.name = "InflateLimitError";
	}
}

export interface InflateResult {
	readonly bytes: Uint8Array;
	/** False when the stream was corrupt or truncated; `bytes` then holds what was decoded. */
	readonly complete: boolean;
}

const INPUT_SLICE = 64 * 1024;

/** The next input slice (a view, typed for the Streams API; our buffers are never shared). */
function slice(data: Uint8Array, offset: number): BufferSource {
	return data.subarray(offset, Math.min(data.length, offset + INPUT_SLICE)) as BufferSource;
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
	const out = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.length;
	}
	return out;
}

/**
 * Inflates `data`. Throws {@link InflateLimitError} as soon as the output would exceed
 * `maxOutput` bytes; a corrupt stream resolves with `complete: false` and the partial output.
 */
export async function inflateBounded(
	data: Uint8Array,
	format: InflateFormat,
	maxOutput: number,
): Promise<InflateResult> {
	const stream = new DecompressionStream(format);
	const writer = stream.writable.getWriter();
	const reader = stream.readable.getReader();
	const feeding = (async () => {
		for (let offset = 0; offset < data.length; offset += INPUT_SLICE) {
			await writer.write(slice(data, offset));
		}
		await writer.close();
	})().catch(() => undefined);
	const chunks: Uint8Array[] = [];
	let total = 0;
	let complete = true;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.length;
			if (total > maxOutput) {
				await reader.cancel().catch(() => undefined);
				await writer.abort().catch(() => undefined);
				throw new InflateLimitError();
			}
			chunks.push(value);
		}
	} catch (error) {
		if (error instanceof InflateLimitError) throw error;
		complete = false;
		await writer.abort().catch(() => undefined);
	}
	await feeding;
	return { bytes: concat(chunks, total), complete };
}

/** Raw DEFLATE (RFC 1951) compression, as stored in ZIP entries with method 8. */
export async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
	const stream = new CompressionStream("deflate-raw");
	const writer = stream.writable.getWriter();
	const reader = stream.readable.getReader();
	const feeding = (async () => {
		for (let offset = 0; offset < data.length; offset += INPUT_SLICE) {
			await writer.write(slice(data, offset));
		}
		await writer.close();
	})();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		chunks.push(value);
		total += value.length;
	}
	await feeding;
	return concat(chunks, total);
}
