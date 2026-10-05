// Egress address policy for server-side fetches of operator-supplied URLs.
//
// This is a dependency-free port of `isPrivateIpAddress` from
// packages/core/src/mcp-transport.ts (the repository's MCP SSRF guard). Edge
// Functions are deployed independently of the workspace packages and cannot
// import them, so the logic is copied; supabase/functions/__tests__/
// egress-guard.test.ts compares this copy with the core function over a corpus
// so the two cannot drift silently.

function normalizeIpv4(value: string): number[] | null {
	const parts = value.split(".");
	if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
	const numbers = parts.map(Number);
	return numbers.every((part) => part >= 0 && part <= 255) ? numbers : null;
}

function isPrivateIpv4(value: string): boolean {
	const parts = normalizeIpv4(value);
	if (!parts) return false;
	const [first, second] = parts;
	return (
		first === 0 ||
		first === 10 ||
		first === 127 ||
		(first === 100 && second !== undefined && second >= 64 && second <= 127) ||
		(first === 169 && second === 254) ||
		(first === 172 && second !== undefined && second >= 16 && second <= 31) ||
		(first === 192 && second === 0) ||
		(first === 192 && second === 168) ||
		(first === 192 && second === 88) ||
		(first === 198 && second !== undefined && (second === 18 || second === 19)) ||
		(first === 198 && second === 51) ||
		(first === 203 && second === 0) ||
		(first !== undefined && first >= 224)
	);
}

function replaceEmbeddedIpv4(value: string): string | null {
	if (!value.includes(".")) return value;
	const separator = value.lastIndexOf(":");
	const ipv4 = separator === -1 ? null : normalizeIpv4(value.slice(separator + 1));
	if (!ipv4) return null;
	const high = ((ipv4[0] ?? 0) << 8) | (ipv4[1] ?? 0);
	const low = ((ipv4[2] ?? 0) << 8) | (ipv4[3] ?? 0);
	return `${value.slice(0, separator)}:${high.toString(16)}:${low.toString(16)}`;
}

function parseIpv6Half(half: string): number[] | null {
	if (half === "") return [];
	const parts = half.split(":");
	if (parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
	return parts.map((part) => Number.parseInt(part, 16));
}

function normalizeIpv6(value: string): number[] | null {
	if (value.includes("%")) return null;
	const candidate = replaceEmbeddedIpv4(value.toLowerCase());
	if (!candidate) return null;
	const halves = candidate.split("::");
	if (halves.length > 2) return null;
	const left = parseIpv6Half(halves[0] ?? "");
	const right = parseIpv6Half(halves[1] ?? "");
	if (!left || !right) return null;
	if (halves.length === 1) return left.length === 8 ? left : null;
	const omitted = 8 - left.length - right.length;
	return omitted >= 1 ? [...left, ...Array<number>(omitted).fill(0), ...right] : null;
}

function embeddedIpv4(words: readonly number[], offset: number): string {
	const high = words[offset] ?? 0;
	const low = words[offset + 1] ?? 0;
	return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
}

function hasIpv6Prefix(words: readonly number[], prefix: readonly number[], bits: number): boolean {
	const wholeWords = Math.floor(bits / 16);
	for (let index = 0; index < wholeWords; index += 1) {
		if (words[index] !== prefix[index]) return false;
	}
	const remaining = bits % 16;
	if (remaining === 0) return true;
	const mask = (0xffff << (16 - remaining)) & 0xffff;
	return ((words[wholeWords] ?? 0) & mask) === ((prefix[wholeWords] ?? 0) & mask);
}

/** 4 for a dotted-quad IPv4 literal, 6 for an IPv6 literal, 0 otherwise. */
export function ipVersion(value: string): 0 | 4 | 6 {
	const text = value.trim().replace(/^\[|\]$/g, "").split("%", 1)[0] ?? "";
	if (normalizeIpv4(text)) return 4;
	return text.includes(":") && normalizeIpv6(text.toLowerCase()) ? 6 : 0;
}

/** Port of the core guard: true for loopback, private, link-local, reserved and mapped-private addresses. */
export function isPrivateIpAddress(value: string): boolean {
	const normalized =
		value
			.trim()
			.replace(/^\[|\]$/g, "")
			.split("%", 1)[0]
			?.toLowerCase() ?? "";
	const version = ipVersion(normalized);
	if (version === 4) return isPrivateIpv4(normalized);
	if (version !== 6) return false;
	const words = normalizeIpv6(normalized);
	if (!words) return true;
	if (words.slice(0, 6).every((word) => word === 0)) return isPrivateIpv4(embeddedIpv4(words, 6));
	if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff)
		return isPrivateIpv4(embeddedIpv4(words, 6));
	if (hasIpv6Prefix(words, [0x0064, 0xff9b, 0, 0, 0, 0], 96))
		return isPrivateIpv4(embeddedIpv4(words, 6));
	if (words[0] === 0x2002) return isPrivateIpv4(embeddedIpv4(words, 1));
	return (
		hasIpv6Prefix(words, [0xfc00], 7) ||
		hasIpv6Prefix(words, [0xfe80], 10) ||
		hasIpv6Prefix(words, [0xfec0], 10) ||
		hasIpv6Prefix(words, [0xff00], 8) ||
		hasIpv6Prefix(words, [0x0100, 0, 0, 0], 64) ||
		hasIpv6Prefix(words, [0x0100, 0, 0, 1], 64) ||
		hasIpv6Prefix(words, [0x0064, 0xff9b, 0x0001], 48) ||
		hasIpv6Prefix(words, [0x2001, 0x0000], 32) ||
		hasIpv6Prefix(words, [0x2001, 0x0002, 0], 48) ||
		hasIpv6Prefix(words, [0x2001, 0x0010], 28) ||
		hasIpv6Prefix(words, [0x2001, 0x0020], 28) ||
		hasIpv6Prefix(words, [0x2001, 0x0db8], 32) ||
		hasIpv6Prefix(words, [0x3fff, 0], 20) ||
		hasIpv6Prefix(words, [0x5f00], 16)
	);
}

/** Fail-closed variant: anything that is not a clearly public IP literal is refused. */
export function isPublicIpAddress(value: string): boolean {
	return ipVersion(value) !== 0 && !isPrivateIpAddress(value);
}

const BLOCKED_HOSTNAMES = new Set([
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data.ec2.internal",
]);

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".lan", ".corp"];

/** Hostnames that must never be fetched regardless of what they resolve to. */
export function isBlockedHostname(hostname: string): boolean {
	const host = hostname.toLowerCase().replace(/\.+$/, "");
	return (
		BLOCKED_HOSTNAMES.has(host) ||
		!host.includes(".") ||
		BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))
	);
}
