// Builds the `adapter` block of the host-side SIEM config file for the syslog
// destination. Mirrors the validation in packages/core/src/siem-syslog.ts so an
// operator sees the same refusals before copying the file to the host; the
// host re-validates on every start and every send, so this is guidance, not a
// control. Nothing here is transmitted anywhere.

export type SyslogTransportChoice = "tls" | "tcp" | "udp";

export type SyslogFormValues = {
	transport: SyslogTransportChoice;
	host: string;
	port: string;
	facility: string;
	hostname: string;
	appName: string;
	allowPrivateNetwork: boolean;
	allowPlaintextTransport: boolean;
	caCertificatePem: string;
	pinnedSha256: string;
};

export type SyslogAdapterConfig = {
	provider: "syslog";
	endpoint: string;
	facility?: number;
	hostname?: string;
	appName?: string;
	allowPrivateNetwork?: boolean;
	allowPlaintextTransport?: boolean;
	tlsCaCertificatePem?: string;
	tlsPinnedSha256?: string[];
};

export type SyslogFormResult =
	| { ok: true; adapter: SyslogAdapterConfig; warnings: string[] }
	| { ok: false; errors: string[] };

const BLOCKED_HOSTS = new Set([
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data.ec2.internal",
]);
const DNS_NAME =
	/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const PIN = /^([A-Fa-f0-9]{64}|[A-Za-z0-9+/_-]{43}={0,1})$/;

type AddressClass = "public" | "private" | "blocked";

function classifyIpv4(a: number, b: number): AddressClass {
	if (a === 127 || a === 0 || (a === 169 && b === 254) || a >= 224) return "blocked";
	if (
		a === 10 ||
		(a === 172 && b >= 16 && b <= 31) ||
		(a === 192 && b === 168) ||
		(a === 100 && b >= 64 && b <= 127) ||
		(a === 192 && b === 0) ||
		(a === 198 && (b === 18 || b === 19 || b === 51)) ||
		(a === 203 && b === 0)
	)
		return "private";
	return "public";
}

function classifyHostLiteral(host: string): AddressClass | null {
	const v4 = IPV4.exec(host);
	if (v4) {
		const parts = v4.slice(1).map(Number);
		if (parts.some((part) => part > 255)) return "blocked";
		return classifyIpv4(parts[0] as number, parts[1] as number);
	}
	if (host.includes(":")) {
		const value = host.toLowerCase();
		if (value === "::1" || value === "::" || /^fe[89ab]/.test(value) || value.startsWith("ff"))
			return "blocked";
		if (value.startsWith("::ffff:")) return "blocked"; // mapped addresses: use the IPv4 literal
		return /^f[cd]/.test(value) ? "private" : "public";
	}
	return null;
}

function parsePins(raw: string): string[] {
	return raw
		.split(/[\s,]+/)
		.map((value) => value.trim())
		.filter(Boolean);
}

function checkTls(values: SyslogFormValues, errors: string[]): void {
	if (values.transport === "tls") {
		const pem = values.caCertificatePem.trim();
		if (pem && !/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/.test(pem))
			errors.push("The CA certificate must be PEM text (BEGIN CERTIFICATE ... END CERTIFICATE).");
		if (pem.length > 65_536) errors.push("The CA certificate bundle is too large.");
		const pins = parsePins(values.pinnedSha256);
		if (pins.length > 8) errors.push("Provide at most 8 public-key pins.");
		if (pins.some((pin) => !PIN.test(pin)))
			errors.push("Each pin must be a SHA-256 value in hex (64 characters) or base64.");
	} else if (values.caCertificatePem.trim() || values.pinnedSha256.trim()) {
		errors.push("CA and pin settings apply only to TLS destinations.");
	}
}

function checkHost(values: SyslogFormValues, errors: string[], warnings: string[]): void {
	const host = values.host
		.trim()
		.toLowerCase()
		.replace(/^\[|\]$/g, "");
	const literalClass = classifyHostLiteral(host);
	if (!host) errors.push("Enter the collector host name or address.");
	else if (BLOCKED_HOSTS.has(host) || literalClass === "blocked")
		errors.push(
			"Loopback, link-local, metadata and other non-routable addresses are not accepted for SIEM delivery.",
		);
	else if (literalClass === null && !DNS_NAME.test(host))
		errors.push("The host is not a valid DNS name or IP address.");
	else if (literalClass === "private" && !values.allowPrivateNetwork)
		errors.push(
			"This address is in a private range. Tick the private-network option to confirm an on-premises collector.",
		);
	if (literalClass === null && values.allowPrivateNetwork)
		warnings.push(
			"The host name is resolved on the host at every send; every address it returns must satisfy the same policy.",
		);
}

export function buildSyslogAdapter(values: SyslogFormValues): SyslogFormResult {
	const errors: string[] = [];
	const warnings: string[] = [];
	const host = values.host
		.trim()
		.toLowerCase()
		.replace(/^\[|\]$/g, "");
	checkHost(values, errors, warnings);
	const port = Number(values.port);
	if (!/^\d{1,5}$/.test(values.port.trim()) || port < 1 || port > 65_535)
		errors.push("The port must be a number from 1 to 65535.");
	const facility = values.facility.trim() === "" ? undefined : Number(values.facility);
	if (facility !== undefined && (!Number.isInteger(facility) || facility < 0 || facility > 23))
		errors.push("The facility must be a whole number from 0 to 23.");
	if (/[^\x21-\x7e]/.test(values.hostname) || values.hostname.length > 255)
		errors.push("The reporting hostname must be printable ASCII without spaces.");
	if (/[^\x21-\x7e]/.test(values.appName) || values.appName.length > 48)
		errors.push(
			"The application name must be printable ASCII without spaces (48 characters maximum).",
		);
	checkTls(values, errors);
	if (values.transport !== "tls" && !values.allowPlaintextTransport)
		errors.push(
			"Plain TCP and UDP send incident data unencrypted. Choose TLS, or tick the plaintext option to accept that risk.",
		);
	if (errors.length > 0) return { ok: false, errors };

	if (values.transport === "udp")
		warnings.push(
			"UDP has no acknowledgement. The delivery receipt records the datagram as sent, not received.",
		);
	if (values.transport === "tcp")
		warnings.push("Plain TCP offers neither encryption nor server authentication.");

	const displayHost = host.includes(":") ? `[${host}]` : host;
	const pins = parsePins(values.pinnedSha256);
	const ca = values.caCertificatePem.trim();
	const adapter: SyslogAdapterConfig = {
		provider: "syslog",
		endpoint: `${values.transport}://${displayHost}:${port}`,
		...(facility !== undefined ? { facility } : {}),
		...(values.hostname ? { hostname: values.hostname } : {}),
		...(values.appName ? { appName: values.appName } : {}),
		...(values.allowPrivateNetwork ? { allowPrivateNetwork: true } : {}),
		...(values.transport !== "tls" && values.allowPlaintextTransport
			? { allowPlaintextTransport: true }
			: {}),
		...(values.transport === "tls" && ca ? { tlsCaCertificatePem: ca } : {}),
		...(values.transport === "tls" && pins.length > 0 ? { tlsPinnedSha256: pins } : {}),
	};
	return { ok: true, adapter, warnings };
}

export const DEFAULT_SYSLOG_FORM: SyslogFormValues = {
	transport: "tls",
	host: "",
	port: "6514",
	facility: "16",
	hostname: "",
	appName: "aidr",
	allowPrivateNetwork: false,
	allowPlaintextTransport: false,
	caCertificatePem: "",
	pinnedSha256: "",
};
