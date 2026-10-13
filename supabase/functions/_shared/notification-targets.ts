// Notification channel destinations: validation, SSRF defence and encryption.
//
// A destination is a credential. A Slack or Teams webhook URL, or a generic
// webhook's HMAC secret, lets its holder post into the customer's channel, so:
//
//   * It is validated here before it is stored, and again before every send.
//   * It is stored only as AES-256-GCM ciphertext (`v1.<key id>.<base64url>`)
//     whose associated data binds the tenant, channel id and channel type, so a
//     ciphertext copied to another row or tenant does not decrypt.
//   * No API ever returns it; the console shows `targetHint` (host plus a
//     digest prefix, or masked recipients).
//
// Outbound requests are refused unless the URL is https on port 443 (8443 for a
// generic webhook), carries no credentials, names a DNS host (no IP literal,
// no single-label, `.local`, `.internal` or `localhost` name), and — for Slack
// and Teams — is on the provider's webhook host allow-list. Before each send
// the host is resolved and EVERY address must be public unicast: loopback,
// RFC 1918, CGNAT, link-local (including the 169.254.169.254 metadata
// service), unique-local, multicast, documentation, benchmarking and
// IPv4-mapped/NAT64/6to4 forms of those are refused. Redirects are never
// followed (see notification-delivery.ts).

export const CHANNEL_TYPES = ["slack", "teams", "webhook", "email"] as const;
export type ChannelType = (typeof CHANNEL_TYPES)[number];

export type ChannelTarget =
	| { type: "slack"; url: string }
	| { type: "teams"; url: string }
	| { type: "webhook"; url: string; secret: string }
	| { type: "email"; recipients: string[] };

const MAX_EMAIL_RECIPIENTS = 10;
const MIN_WEBHOOK_SECRET_LENGTH = 32;
const MAX_WEBHOOK_SECRET_LENGTH = 256;
const MAX_URL_LENGTH = 2048;
const ADDRESS = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;

/** Slack incoming-webhook hosts (commercial and GovSlack). */
const SLACK_WEBHOOK_HOSTS = Object.freeze(["hooks.slack.com", "hooks.slack-gov.com"]);
/**
 * Microsoft Teams incoming-webhook hosts: Power Automate / Workflows triggers
 * (`*.logic.azure.com`, `*.api.powerplatform.com`) and legacy Office 365
 * connectors (`*.webhook.office.com`).
 */
const TEAMS_WEBHOOK_HOST_SUFFIXES = Object.freeze([
	".logic.azure.com",
	".api.powerplatform.com",
	".webhook.office.com",
]);

export type TargetError =
	| "invalid_target"
	| "invalid_url"
	| "url_not_https"
	| "url_credentials_forbidden"
	| "url_port_forbidden"
	| "url_host_forbidden"
	| "url_host_not_allowed"
	| "invalid_webhook_secret"
	| "invalid_recipients";

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	const actual = Object.keys(value);
	return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

/** True when the string is an IPv4 or IPv6 literal (with or without brackets). */
function isIpLiteral(host: string): boolean {
	const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
	return parseIpv4(bare) !== null || parseIpv6(bare) !== null;
}

/**
 * Static URL checks for a channel type. Returns the parsed URL on success.
 * DNS is checked separately, immediately before each send.
 */
export function checkTargetUrl(type: ChannelType, value: unknown):
	| { ok: true; url: URL }
	| { ok: false; error: TargetError } {
	if (typeof value !== "string" || value.length === 0 || value.length > MAX_URL_LENGTH || /\s/.test(value)) {
		return { ok: false, error: "invalid_url" };
	}
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return { ok: false, error: "invalid_url" };
	}
	if (url.protocol !== "https:") return { ok: false, error: "url_not_https" };
	if (url.username !== "" || url.password !== "") return { ok: false, error: "url_credentials_forbidden" };
	const allowedPorts = type === "webhook" ? ["", "443", "8443"] : ["", "443"];
	if (!allowedPorts.includes(url.port)) return { ok: false, error: "url_port_forbidden" };
	const host = url.hostname.toLowerCase().replace(/\.$/, "");
	if (
		host === "" ||
		isIpLiteral(host) ||
		!host.includes(".") ||
		host === "localhost" ||
		/\.(localhost|local|internal|intranet|lan|home|corp|arpa)$/.test(host) ||
		!/^[a-z0-9.-]+$/.test(host)
	) {
		return { ok: false, error: "url_host_forbidden" };
	}
	if (type === "slack") {
		if (!SLACK_WEBHOOK_HOSTS.includes(host) || !url.pathname.startsWith("/services/")) {
			return { ok: false, error: "url_host_not_allowed" };
		}
	} else if (type === "teams") {
		if (!TEAMS_WEBHOOK_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix) && host.length > suffix.length)) {
			return { ok: false, error: "url_host_not_allowed" };
		}
	}
	return { ok: true, url };
}

function isEmailAddress(value: unknown): value is string {
	return typeof value === "string" && value.length <= 254 && ADDRESS.test(value);
}

/** Parse the write-only destination a client submitted for a channel type. */
export function parseTarget(type: ChannelType, value: unknown):
	| { ok: true; target: ChannelTarget }
	| { ok: false; error: TargetError } {
	if (!isRecord(value)) return { ok: false, error: "invalid_target" };
	if (type === "slack" || type === "teams") {
		if (!exactKeys(value, ["url"])) return { ok: false, error: "invalid_target" };
		const checked = checkTargetUrl(type, value.url);
		if (!checked.ok) return checked;
		return { ok: true, target: { type, url: checked.url.href } };
	}
	if (type === "webhook") {
		if (!exactKeys(value, ["url", "secret"])) return { ok: false, error: "invalid_target" };
		const checked = checkTargetUrl(type, value.url);
		if (!checked.ok) return checked;
		const secret = value.secret;
		if (
			typeof secret !== "string" ||
			secret.length < MIN_WEBHOOK_SECRET_LENGTH ||
			secret.length > MAX_WEBHOOK_SECRET_LENGTH ||
			!/^[\x21-\x7e]+$/.test(secret)
		) {
			return { ok: false, error: "invalid_webhook_secret" };
		}
		return { ok: true, target: { type, url: checked.url.href, secret } };
	}
	if (!exactKeys(value, ["recipients"]) || !Array.isArray(value.recipients)) {
		return { ok: false, error: "invalid_target" };
	}
	const recipients = [...new Set(value.recipients.map((item) => (typeof item === "string" ? item.trim().toLowerCase() : item)))];
	if (
		recipients.length < 1 ||
		recipients.length > MAX_EMAIL_RECIPIENTS ||
		!recipients.every(isEmailAddress)
	) {
		return { ok: false, error: "invalid_recipients" };
	}
	return { ok: true, target: { type: "email", recipients: recipients as string[] } };
}

async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Non-secret console label. Webhook paths and query strings routinely embed the
 * credential, so only the host and a 6-hex digest prefix of the whole URL are
 * shown; e-mail shows the first recipient masked plus a count.
 */
export async function targetHint(target: ChannelTarget): Promise<string> {
	if (target.type === "email") {
		const [first] = target.recipients;
		const [local, domain] = first.split("@");
		const masked = `${local.slice(0, 1)}***@${domain}`;
		const more = target.recipients.length - 1;
		return (more > 0 ? `${masked} +${more} more` : masked).slice(0, 160);
	}
	const host = new URL(target.url).hostname;
	return `${host} · #${(await sha256Hex(target.url)).slice(0, 6)}`.slice(0, 160);
}

// ── Address classification ─────────────────────────────────────────────────

function parseIpv4(value: string): number[] | null {
	const parts = value.split(".");
	if (parts.length !== 4) return null;
	const octets: number[] = [];
	for (const part of parts) {
		if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
		const octet = Number(part);
		if (octet > 255) return null;
		octets.push(octet);
	}
	return octets;
}

/** Parse an IPv6 literal (optionally with an embedded IPv4 tail) into 16 bytes. */
function parseIpv6(value: string): number[] | null {
	let text = value.toLowerCase();
	const zone = text.indexOf("%");
	if (zone >= 0) text = text.slice(0, zone);
	if (!/^[0-9a-f:.]+$/.test(text) || !text.includes(":")) return null;
	let tail: number[] = [];
	const lastColon = text.lastIndexOf(":");
	if (text.slice(lastColon + 1).includes(".")) {
		const v4 = parseIpv4(text.slice(lastColon + 1));
		if (!v4) return null;
		tail = v4;
		text = `${text.slice(0, lastColon + 1)}0:0`;
	}
	const halves = text.split("::");
	if (halves.length > 2) return null;
	const parseGroups = (part: string) => (part === "" ? [] : part.split(":"));
	const head = parseGroups(halves[0]);
	const rest = halves.length === 2 ? parseGroups(halves[1]) : [];
	if ([...head, ...rest].some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
	const missing = 8 - head.length - rest.length;
	if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
	const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...rest].map((group) =>
		Number.parseInt(group, 16),
	);
	const bytes = groups.flatMap((group) => [group >> 8, group & 0xff]);
	if (tail.length === 4) bytes.splice(12, 4, ...tail);
	return bytes;
}

function inV4(octets: number[], base: [number, number, number, number], bits: number): boolean {
	const value = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
	const net = ((base[0] << 24) | (base[1] << 16) | (base[2] << 8) | base[3]) >>> 0;
	const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
	return (value & mask) === (net & mask);
}

const BLOCKED_V4: ReadonlyArray<[[number, number, number, number], number]> = [
	[[0, 0, 0, 0], 8], // "this" network
	[[10, 0, 0, 0], 8], // RFC 1918
	[[100, 64, 0, 0], 10], // CGNAT
	[[127, 0, 0, 0], 8], // loopback
	[[169, 254, 0, 0], 16], // link-local, cloud metadata (169.254.169.254)
	[[172, 16, 0, 0], 12], // RFC 1918
	[[192, 0, 0, 0], 24], // IETF protocol assignments
	[[192, 0, 2, 0], 24], // TEST-NET-1
	[[192, 88, 99, 0], 24], // 6to4 relay anycast
	[[192, 168, 0, 0], 16], // RFC 1918
	[[198, 18, 0, 0], 15], // benchmarking
	[[198, 51, 100, 0], 24], // TEST-NET-2
	[[203, 0, 113, 0], 24], // TEST-NET-3
	[[224, 0, 0, 0], 4], // multicast
	[[240, 0, 0, 0], 4], // reserved, broadcast
];

function blockedV4(octets: number[]): boolean {
	return BLOCKED_V4.some(([base, bits]) => inV4(octets, base, bits));
}

function prefixMatches(bytes: number[], prefix: number[], bits: number): boolean {
	for (let bit = 0; bit < bits; bit += 1) {
		const byte = bit >> 3;
		const mask = 0x80 >> (bit & 7);
		if ((bytes[byte] & mask) !== ((prefix[byte] ?? 0) & mask)) return false;
	}
	return true;
}

function blockedV6(bytes: number[]): boolean {
	const zeroPrefix = (count: number) => bytes.slice(0, count).every((byte) => byte === 0);
	if (zeroPrefix(16)) return true; // ::
	if (zeroPrefix(15) && bytes[15] === 1) return true; // ::1
	// IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
	if (zeroPrefix(10) && bytes[10] === 0xff && bytes[11] === 0xff) return blockedV4(bytes.slice(12));
	if (zeroPrefix(12)) return true;
	// NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
	if (prefixMatches(bytes, [0x00, 0x64, 0xff, 0x9b], 32)) return true;
	// 6to4 2002::/16 embeds an IPv4 address
	if (bytes[0] === 0x20 && bytes[1] === 0x02) return blockedV4(bytes.slice(2, 6));
	const ranges: Array<[number[], number]> = [
		[[0x01, 0x00], 64], // discard-only 100::/64
		[[0x20, 0x01, 0x00, 0x00], 32], // Teredo 2001::/32
		[[0x20, 0x01, 0x00, 0x02], 48], // benchmarking 2001:2::/48
		[[0x20, 0x01, 0x0d, 0xb8], 32], // documentation 2001:db8::/32
		[[0x20, 0x01, 0x00, 0x10], 28], // ORCHID 2001:10::/28
		[[0xfc], 7], // unique local fc00::/7 (includes fd00:ec2::254)
		[[0xfe, 0x80], 10], // link-local fe80::/10
		[[0xfe, 0xc0], 10], // site-local fec0::/10
		[[0xff], 8], // multicast
	];
	return ranges.some(([prefix, bits]) => prefixMatches(bytes, prefix, bits));
}

/**
 * True when an address must never be contacted: anything that is not public
 * unicast, and anything unparseable (fail closed).
 */
export function isBlockedAddress(address: string): boolean {
	const bare = address.startsWith("[") && address.endsWith("]") ? address.slice(1, -1) : address;
	const v4 = parseIpv4(bare);
	if (v4) return blockedV4(v4);
	const v6 = parseIpv6(bare);
	if (v6) return blockedV6(v6);
	return true;
}

/** Resolves a host name to its A and AAAA addresses. */
export type DnsResolver = (host: string) => Promise<string[]>;

/** Deno's resolver; unavailable runtimes fail closed. */
export const denoDnsResolver: DnsResolver = async (host) => {
	const deno = (globalThis as { Deno?: { resolveDns?: (name: string, type: "A" | "AAAA") => Promise<string[]> } }).Deno;
	if (typeof deno?.resolveDns !== "function") throw new Error("dns_unavailable");
	const resolveDns = deno.resolveDns;
	// A missing record for one family is normal. When both families come back
	// empty the caller reports the host as unresolved and the delivery retries.
	const settle = (type: "A" | "AAAA") => resolveDns(host, type).catch(() => [] as string[]);
	const [a, aaaa] = await Promise.all([settle("A"), settle("AAAA")]);
	return [...a, ...aaaa];
};

export type AddressCheck =
	| { ok: true; addresses: string[] }
	| { ok: false; error: "dns_unavailable" | "dns_unresolved" | "ssrf_blocked" };

/** Resolve `host` and require every returned address to be public unicast. */
export async function resolvePublicAddresses(host: string, resolve: DnsResolver): Promise<AddressCheck> {
	let addresses: string[];
	try {
		addresses = await resolve(host);
	} catch (error) {
		return {
			ok: false,
			error: error instanceof Error && error.message === "dns_unavailable" ? "dns_unavailable" : "dns_unresolved",
		};
	}
	if (!Array.isArray(addresses) || addresses.length === 0) return { ok: false, error: "dns_unresolved" };
	// One private answer taints the name: the client may pick any of them.
	if (addresses.some((address) => typeof address !== "string" || isBlockedAddress(address))) {
		return { ok: false, error: "ssrf_blocked" };
	}
	return { ok: true, addresses };
}

// ── Encryption at rest ────────────────────────────────────────────────────

export interface NotificationKeyring {
	/** Key id used for new ciphertext (the first configured key). */
	readonly activeKeyId: string;
	readonly keys: ReadonlyMap<string, CryptoKey>;
}

const KEY_ID = /^[a-z0-9][a-z0-9_-]{0,31}$/;

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> | null {
	try {
		const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
		const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
		return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
	} catch {
		return null;
	}
}

function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Parse `AIDR_NOTIFICATION_ENCRYPTION_KEYS`: comma-separated `<key id>:<base64
 * 32-byte key>` entries. The first entry encrypts; every entry decrypts, so a
 * rotated-out key stays listed until every channel has been re-saved. Returns
 * null for anything malformed (the caller treats that as not configured).
 */
export async function parseKeyring(value: string | null | undefined): Promise<NotificationKeyring | null> {
	if (typeof value !== "string" || value.trim() === "") return null;
	const keys = new Map<string, CryptoKey>();
	let activeKeyId: string | null = null;
	for (const entry of value.split(",")) {
		const separator = entry.indexOf(":");
		if (separator < 1) return null;
		const id = entry.slice(0, separator).trim();
		const raw = base64ToBytes(entry.slice(separator + 1).trim());
		if (!KEY_ID.test(id) || keys.has(id) || !raw || raw.length !== 32) return null;
		try {
			keys.set(id, await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]));
		} catch {
			return null;
		}
		activeKeyId ??= id;
	}
	return activeKeyId ? { activeKeyId, keys } : null;
}

export interface TargetBinding {
	tenantId: string;
	channelId: string;
	type: ChannelType;
}

function associatedData(binding: TargetBinding): Uint8Array<ArrayBuffer> {
	return new TextEncoder().encode(
		`aidr-notification-target:v1:${binding.tenantId.toLowerCase()}:${binding.channelId.toLowerCase()}:${binding.type}`,
	);
}

export async function encryptTarget(
	keyring: NotificationKeyring,
	binding: TargetBinding,
	target: ChannelTarget,
): Promise<{ ciphertext: string; keyId: string }> {
	if (target.type !== binding.type) throw new TypeError("target type does not match its binding");
	const key = keyring.keys.get(keyring.activeKeyId);
	if (!key) throw new TypeError("active notification key missing");
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const sealed = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv, additionalData: associatedData(binding), tagLength: 128 },
			key,
			new TextEncoder().encode(JSON.stringify(target)),
		),
	);
	const payload = new Uint8Array(iv.length + sealed.length);
	payload.set(iv);
	payload.set(sealed, iv.length);
	return { ciphertext: `v1.${keyring.activeKeyId}.${bytesToBase64Url(payload)}`, keyId: keyring.activeKeyId };
}

/** Decrypt and re-validate a stored destination; null on any failure. */
export async function decryptTarget(
	keyring: NotificationKeyring,
	binding: TargetBinding,
	ciphertext: string,
): Promise<ChannelTarget | null> {
	const match = /^v1\.([a-z0-9][a-z0-9_-]{0,31})\.([A-Za-z0-9_-]+)$/.exec(ciphertext);
	if (!match) return null;
	const key = keyring.keys.get(match[1]);
	const payload = base64ToBytes(match[2]);
	if (!key || !payload || payload.length < 12 + 16 + 2) return null;
	let plaintext: ArrayBuffer;
	try {
		plaintext = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: payload.slice(0, 12), additionalData: associatedData(binding), tagLength: 128 },
			key,
			payload.slice(12),
		);
	} catch {
		return null;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(plaintext));
	} catch {
		return null;
	}
	if (!isRecord(parsed) || parsed.type !== binding.type) return null;
	const { type: _type, ...rest } = parsed;
	const checked = parseTarget(binding.type, rest);
	return checked.ok ? checked.target : null;
}
